#!/usr/bin/env python3
"""Middle East aviation event monitor, step 1.

Polls free news and advisory sources, logs Middle East aviation and security
events, pushes alerts via ntfy, and writes triggers for the step-2 traffic scan.
Standard library only. Run:  python monitor.py [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
UA = "me-aviation-monitor/1.0 (personal, non-commercial)"
GDELT_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
GNEWS_URL = "https://news.google.com/rss/search"
GDELT_GAP_S = 6  # GDELT asks for at most one request per 5 s


# ---------- helpers ----------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def http_get(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def norm_key(title: str) -> str:
    """Dedup key: the same headline from different sources collapses to one."""
    t = re.sub(r"\s+-\s+[^-]{2,60}$", "", title)  # strip " - Publisher" suffix
    t = re.sub(r"[^a-z0-9 ]", "", t.lower())
    t = re.sub(r"\s+", " ", t).strip()[:90]
    return hashlib.sha1(t.encode()).hexdigest()[:16]


def compile_terms(terms: list[str]) -> re.Pattern:
    alts = "|".join(re.escape(t.lower()) for t in sorted(terms, key=len, reverse=True))
    return re.compile(rf"\b(?:{alts})", re.IGNORECASE)


def gdelt_timespan(lookback: str) -> str:
    return lookback.replace("min", "m")


# ---------- classification ----------

class Classifier:
    def __init__(self, cfg: dict):
        self.regions = {name: compile_terms(terms) for name, terms in cfg["regions"].items()}
        self.high = compile_terms(cfg["keywords"]["high"])
        self.medium = compile_terms(cfg["keywords"]["medium"])

    def regions_in(self, text: str) -> list[str]:
        return [name for name, rx in self.regions.items() if rx.search(text)]

    def severity(self, text: str) -> str | None:
        if self.high.search(text):
            return "high"
        if self.medium.search(text):
            return "medium"
        return None


# ---------- sources ----------

def fetch_gdelt(cfg: dict, get=http_get) -> list[dict]:
    items, span = [], gdelt_timespan(cfg["settings"]["lookback"])
    for i, q in enumerate(cfg.get("gdelt", [])):
        if i:
            time.sleep(GDELT_GAP_S)
        params = {"query": q["query"], "mode": "artlist", "format": "json",
                  "timespan": span, "maxrecords": "75", "sort": "datedesc"}
        raw = get(f"{GDELT_URL}?{urllib.parse.urlencode(params)}")
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            raise RuntimeError(f"GDELT {q['name']}: {raw.strip()[:120]}")
        for a in data.get("articles", []) or []:
            try:
                ts = iso(datetime.strptime(a.get("seendate", ""), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc))
            except ValueError:
                ts = iso(now_utc())
            items.append({"source": f"gdelt:{q['name']}", "title": a.get("title", "").strip(),
                          "url": a.get("url", ""), "publisher": a.get("domain", ""), "time": ts})
    return items


def fetch_google_news(cfg: dict, get=http_get) -> list[dict]:
    items = []
    for q in cfg.get("google_news", []):
        params = {"q": q["query"], "hl": "en-US", "gl": "US", "ceid": "US:en"}
        root = ET.fromstring(get(f"{GNEWS_URL}?{urllib.parse.urlencode(params)}"))
        for it in root.iter("item"):
            title = (it.findtext("title") or "").strip()
            try:
                ts = iso(parsedate_to_datetime(it.findtext("pubDate") or ""))
            except (TypeError, ValueError):
                ts = iso(now_utc())
            items.append({"source": f"gnews:{q['name']}", "title": title,
                          "url": it.findtext("link") or "",
                          "publisher": it.findtext("source") or "", "time": ts})
    return items


CZIB_LINK = re.compile(r'href="([^"]*/czibs/(czib-?[0-9][0-9a-z-]*))"', re.IGNORECASE)


def fetch_easa(cfg: dict, get=http_get) -> dict[str, str]:
    """Return {bulletin slug: absolute url} for every CZIB linked from the index page."""
    url = cfg["easa"]["url"]
    page = get(url)
    found = {}
    for href, slug in CZIB_LINK.findall(page):
        found[slug.lower()] = urllib.parse.urljoin(url, html.unescape(href))
    if not found:
        raise RuntimeError("EASA: no bulletin links found (page layout may have changed)")
    return found


def page_sentences(raw_html: str) -> list[str]:
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw_html)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    text = re.sub(r"\s+", " ", text)
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if 25 <= len(s.strip()) <= 400]


# ---------- state ----------

def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def empty_state() -> dict:
    return {"seen": {}, "czibs": {}, "pages": {}, "last_alert": {},
            "last_digest": "", "failures": {}, "initialised": False}


# ---------- alerts ----------

def send_ntfy(title: str, message: str, priority: int, click: str = "", tags=None) -> None:
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        print("  (NTFY_TOPIC not set; alert printed only)")
        return
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    body = {"topic": topic, "title": title[:250], "message": message[:3800],
            "priority": priority, "tags": tags or []}
    if click:
        body["click"] = click
    headers = {"Content-Type": "application/json", "User-Agent": UA}
    if os.environ.get("NTFY_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['NTFY_TOKEN']}"
    req = urllib.request.Request(server, data=json.dumps(body).encode(), headers=headers, method="POST")
    urllib.request.urlopen(req, timeout=20).read()


# ---------- main run ----------

def run(cfg: dict, state: dict, fetchers: dict, dry_run: bool = False, clock=now_utc) -> dict:
    """One monitoring pass. Returns {'events': [...], 'triggers': [...], 'alerts': [...]}."""
    t0 = clock()
    s = cfg["settings"]
    clf = Classifier(cfg)
    warmup = not state.get("initialised")
    events, triggers, alerts, errors = [], [], [], []

    # 1. news
    news, news_ok = [], False
    for name in ("gdelt", "google_news"):
        if not cfg.get(name):
            continue
        try:
            news += fetchers[name](cfg)
            news_ok = True
            state["failures"][name] = 0
        except Exception as e:  # one dead source must not stop the run
            state["failures"][name] = state["failures"].get(name, 0) + 1
            errors.append(f"{name}: {e}")

    by_region: dict[str, list[dict]] = {}
    for it in news:
        if not it["title"]:
            continue
        key = norm_key(it["title"])
        if key in state["seen"]:
            continue
        state["seen"][key] = iso(t0)
        sev = clf.severity(it["title"])
        regions = clf.regions_in(it["title"])
        if not sev or not regions:
            continue
        ev = {**it, "severity": sev, "regions": regions, "logged": iso(t0)}
        events.append(ev)
        for r in regions:
            by_region.setdefault(r, []).append(ev)

    cooldown = timedelta(minutes=s["cooldown_minutes"])
    for region, evs in by_region.items():
        highs = [e for e in evs if e["severity"] == "high"]
        reason = None
        if highs:
            reason = "aviation"
        elif len(evs) >= s["cluster_threshold"]:
            reason = "security-cluster"
        if not reason:
            continue
        last = state["last_alert"].get(region)
        cooling = last and t0 - parse_iso(last) < cooldown
        lead = (highs or evs)[0]
        triggers.append({"time": iso(t0), "region": region, "reason": reason,
                         "count": len(evs), "headline": lead["title"], "url": lead["url"]})
        if not cooling:
            state["last_alert"][region] = iso(t0)
            lines = [f"- {e['title']}" for e in (highs or evs)[:5]]
            alerts.append({"title": f"{region.replace('_', ' ')}: {reason} ({len(evs)} new)",
                           "message": "\n".join(lines), "priority": 4 if highs else 3,
                           "click": lead["url"], "tags": ["airplane"] if highs else ["warning"]})

    # 2. EASA bulletins
    if cfg.get("easa"):
        try:
            current = fetchers["easa"](cfg)
            state["failures"]["easa"] = 0
            new = sorted(set(current) - set(state["czibs"]))
            if state["czibs"] and new:
                for slug in new:
                    ev = {"source": "easa", "title": f"EASA bulletin {slug.upper()}", "url": current[slug],
                          "publisher": "EASA", "time": iso(t0), "severity": "high",
                          "regions": ["EASA"], "logged": iso(t0)}
                    events.append(ev)
                    triggers.append({"time": iso(t0), "region": "EASA", "reason": "czib",
                                     "count": 1, "headline": ev["title"], "url": ev["url"]})
                    alerts.append({"title": f"New/revised EASA conflict-zone bulletin: {slug.upper()}",
                                   "message": "Check affected FIRs and validity.", "priority": 5,
                                   "click": current[slug], "tags": ["rotating_light"]})
            state["czibs"].update({k: iso(t0) for k in new})
        except Exception as e:
            state["failures"]["easa"] = state["failures"].get("easa", 0) + 1
            errors.append(f"easa: {e}")

    # 3. watched pages
    for page in cfg.get("watch_pages", []):
        try:
            sents = page_sentences(fetchers["page"](page["url"]))
            known = set(state["pages"].get(page["url"], []))
            fresh = [x for x in sents if hashlib.sha1(x.encode()).hexdigest()[:12] not in known]
            if known:
                for sentence in fresh:
                    regions = clf.regions_in(sentence)
                    if not regions:
                        continue
                    sev = "high"  # the page is an aviation advisory, so any new regional line matters
                    ev = {"source": f"page:{page['name']}", "title": sentence, "url": page["url"],
                          "publisher": page["name"], "time": iso(t0), "severity": sev,
                          "regions": regions, "logged": iso(t0)}
                    events.append(ev)
                    if sev == "high":
                        triggers.append({"time": iso(t0), "region": regions[0], "reason": "advisory-page",
                                         "count": 1, "headline": sentence, "url": page["url"]})
                        alerts.append({"title": f"{page['name']} updated: {', '.join(regions)}",
                                       "message": sentence, "priority": 4, "click": page["url"],
                                       "tags": ["airplane"]})
            state["pages"][page["url"]] = [hashlib.sha1(x.encode()).hexdigest()[:12] for x in sents]
            state["failures"][page["url"]] = 0
        except Exception as e:
            state["failures"][page["url"]] = state["failures"].get(page["url"], 0) + 1
            errors.append(f"{page['name']}: {e}")

    # 4. housekeeping
    keep = t0 - timedelta(days=s["seen_retention_days"])
    state["seen"] = {k: v for k, v in state["seen"].items() if parse_iso(v) >= keep}

    for src, n in state["failures"].items():
        if n == 6:  # three hours of consecutive failures; alert once
            alerts.append({"title": f"Monitor source failing: {src}",
                           "message": "Six consecutive failures. Check the Actions log.",
                           "priority": 3, "click": "", "tags": ["wrench"]})

    local = t0.astimezone(ZoneInfo(s["timezone"]))
    today = local.date().isoformat()
    if local.hour >= s["digest_hour"] and state.get("last_digest") != today:
        state["last_digest"] = today
        alerts.append({"title": "ME monitor daily check-in",
                       "message": f"Running. This pass: {len(events)} new events, {len(triggers)} triggers. "
                                  f"Sources failing: {', '.join(k for k, v in state['failures'].items() if v) or 'none'}.",
                       "priority": 2, "click": "", "tags": ["white_check_mark"]})

    if warmup:  # learn the current baseline before alerting, so the first live run doesn't flood
        triggers, alerts = [], []
        if news_ok:
            state["initialised"] = True
            alerts = [{"title": "ME monitor started",
                       "message": f"Baseline recorded: {len(state['seen'])} headlines, {len(state['czibs'])} EASA bulletins. "
                                  "Alerts start from the next run.",
                       "priority": 3, "click": "", "tags": ["white_check_mark"]}]

    for e in errors:
        print(f"  ! {e}", file=sys.stderr)
    return {"events": events, "triggers": triggers, "alerts": alerts, "errors": errors}


def default_fetchers() -> dict:
    return {"gdelt": fetch_gdelt, "google_news": fetch_google_news,
            "easa": fetch_easa, "page": http_get}


def append_jsonl(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print only; no alerts, no files written")
    ap.add_argument("--config", default=str(ROOT / "config.toml"))
    ap.add_argument("--state", default=str(ROOT / "state" / "state.json"))
    ap.add_argument("--data", default=str(ROOT / "data"))
    a = ap.parse_args()

    cfg = tomllib.loads(Path(a.config).read_text())
    state_path = Path(a.state)
    state = {**empty_state(), **load_json(state_path, {})}
    out = run(cfg, state, default_fetchers(), dry_run=a.dry_run)

    print(f"events={len(out['events'])} triggers={len(out['triggers'])} "
          f"alerts={len(out['alerts'])} errors={len(out['errors'])}")
    for al in out["alerts"]:
        print(f"ALERT [{al['priority']}] {al['title']}\n{al['message']}\n")
    if a.dry_run:
        return 0

    for al in out["alerts"]:
        try:
            send_ntfy(al["title"], al["message"], al["priority"], al["click"], al["tags"])
        except Exception as e:
            print(f"  ! ntfy: {e}", file=sys.stderr)
    data = Path(a.data)
    append_jsonl(data / "events.jsonl", out["events"])
    append_jsonl(data / "triggers.jsonl", out["triggers"])
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=1))
    # a run where every source failed should show red in GitHub
    return 1 if out["errors"] and not out["events"] and len(out["errors"]) >= 3 else 0


if __name__ == "__main__":
    sys.exit(main())
