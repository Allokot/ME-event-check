#!/usr/bin/env python3
"""Middle East aviation event monitor, step 1.

Polls free news feeds (English, Arabic, Hebrew, Persian) and EASA conflict-zone
bulletins, logs Middle East aviation and security events, pushes alerts via
ntfy, and writes triggers for the step-2 traffic scan.
Standard library only. Run:  python monitor.py [--dry-run]
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import json
import os
import re
import sys
import time
import tomllib
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (compatible; me-aviation-monitor/1.1; personal use)"
GDELT_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
GNEWS_URL = "https://news.google.com/rss/search"
ATOM = "{http://www.w3.org/2005/Atom}"


# ---------- helpers ----------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def http_get(url: str, timeout: int = 25) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


_AR_DIACRITICS = re.compile("[ً-ٰٟـ]")
_CHARMAP = str.maketrans({
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ي": "ی", "ى": "ی", "ك": "ک", "ة": "ه",
    "״": '"', "׳": "'", "“": '"', "”": '"', "’": "'", "‘": "'",
})


def normalise(s: str) -> str:
    """Fold case and spelling variants so one term covers Arabic, Persian and Hebrew forms."""
    s = unicodedata.normalize("NFC", s).lower()
    return _AR_DIACRITICS.sub("", s).translate(_CHARMAP)


def strip_publisher(title: str) -> str:
    """Google News appends ' - Publisher'; it must not count as content ('- MTV Lebanon')."""
    return re.sub(r"\s+[-|–]\s+[^-|–]{2,60}$", "", title)


def norm_key(title: str) -> str:
    """Dedup key: the same headline from different sources collapses to one."""
    t = re.sub(r"[^\w ]", "", normalise(strip_publisher(title)))
    t = re.sub(r"\s+", " ", t).strip()[:90]
    return hashlib.sha1(t.encode()).hexdigest()[:16]


STOP = set("the and for with from after amid over into says say said new latest update news "
           "من الی فی علی عن مع بعد حتی ان او".split())


def story_tokens(title: str) -> set[str]:
    words = re.split(r"[^\w]+", normalise(strip_publisher(title)))
    return {w for w in words if (len(w) >= 3 or w.isdigit()) and w not in STOP}


def same_story(a: set[str], b: set[str], threshold: float) -> bool:
    if len(a) < 3 or len(b) < 3:
        return False
    return len(a & b) / min(len(a), len(b)) >= threshold


# Arabic and Hebrew attach up to three prefix letters (و ب ل ف ک ال / ה ו ב ל מ ש כ).
# A non-Latin term must start a word or follow only such letters, so "قطر" does not hit "سقطری".
_PFX = "وبلفکا" + "הובלמשכ"
_NL_START = rf"(?:(?<![^\W\d_])|(?<=(?<![^\W\d_])[{_PFX}])|(?<=(?<![^\W\d_])[{_PFX}][{_PFX}])|(?<=(?<![^\W\d_])[{_PFX}][{_PFX}][{_PFX}]))"


def compile_terms(terms: list[str]) -> re.Pattern | None:
    parts = []
    for raw in terms:
        if raw.startswith("re:"):  # raw regular expression, applied to normalised text
            parts.append(f"(?:{raw[3:]})")
    for t in sorted({normalise(x) for x in terms if not x.startswith("re:")}, key=len, reverse=True):
        e = re.escape(t)
        parts.append(rf"\b{e}" if t.isascii() else _NL_START + e)
    return re.compile("|".join(parts)) if parts else None


def parse_time(s: str | None, fallback: datetime) -> datetime:
    if not s:
        return fallback
    s = s.strip()
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return fallback


def parse_feed(raw: bytes, t0: datetime) -> list[dict]:
    """RSS 2.0 or Atom -> [{'title','url','publisher','time'}]."""
    root = ET.fromstring(raw)
    out = []
    for it in root.iter("item"):
        src = it.find("source")
        out.append({"title": html.unescape((it.findtext("title") or "").strip()),
                    "url": (it.findtext("link") or "").strip(),
                    "publisher": (src.text or "") if src is not None else "",
                    "time": iso(parse_time(it.findtext("pubDate"), t0))})
    for e in root.iter(f"{ATOM}entry"):
        link = e.find(f"{ATOM}link")
        out.append({"title": html.unescape((e.findtext(f"{ATOM}title") or "").strip()),
                    "url": link.get("href", "") if link is not None else "",
                    "publisher": "",
                    "time": iso(parse_time(e.findtext(f"{ATOM}updated") or e.findtext(f"{ATOM}published"), t0))})
    return out


# ---------- real publish date ----------
# Google News stamps items with the time *it* picked them up, which can be weeks after
# the article appeared. Before alerting, resolve the Google link to the real article
# and read the publish date from the page itself.

def http_post(url: str, data: bytes, headers: dict, timeout: int = 25) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def resolve_google_link(url: str, get=http_get, post=http_post) -> str | None:
    m = re.search(r"news\.google\.com/(?:rss/)?articles/([^?/#]+)", url)
    if not m:
        return url
    art = m.group(1)
    try:  # older links carry the target URL inside the base64 id
        raw = base64.urlsafe_b64decode(art + "=" * (-len(art) % 4))
        found = re.search(rb"https?://[\x21-\x7e]+", raw)
        if found and not raw[4:].startswith(b"AU_yqL"):
            return found.group(0).decode()
    except (ValueError, binascii.Error):
        pass
    page = get(f"https://news.google.com/rss/articles/{art}").decode("utf-8", errors="replace")
    sg = re.search(r'data-n-a-sg="([^"]+)"', page)
    ts = re.search(r'data-n-a-ts="([^"]+)"', page)
    if not (sg and ts):
        return None
    inner = ('["garturlreq",[["X","X",["X","X"],null,null,1,1,"US:en",null,1,null,null,null,null,null,0,1],'
             f'"X","X",1,[1,1,1],1,1,null,0,0,null,0],"{art}",{ts.group(1)},"{sg.group(1)}"]')
    body = "f.req=" + urllib.parse.quote(json.dumps([[["Fbv4je", inner, None, "generic"]]]))
    resp = post("https://news.google.com/_/DotsSplashUi/data/batchexecute", body.encode(),
                {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}).decode("utf-8", errors="replace")
    data = json.loads(resp.split("\n\n")[1])[:-2]
    return json.loads(data[0][2])[1]


_DATE_PATTERNS = [
    r'<meta[^>]+(?:property|name|itemprop)=["\'](?:article:published_time|og:published_time|datePublished|'
    r'publish[-_]?date|pubdate|parsely-pub-date|sailthru\.date|dc\.date\.issued|date)["\'][^>]*content=["\']([^"\']+)',
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name|itemprop)=["\'](?:article:published_time|'
    r'og:published_time|datePublished|publish[-_]?date|pubdate)["\']',
    r'"datePublished"\s*:\s*"([^"]+)"',
    r'<time[^>]+datetime=["\']([^"\']+)',
]


def page_publish_date(page_html: str, url: str = "") -> datetime | None:
    for pat in _DATE_PATTERNS:
        for found in re.finditer(pat, page_html, re.IGNORECASE):
            dt = parse_time(found.group(1), None)
            if dt:
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    m = re.search(r"/(20\d\d)[/-](\d{1,2})[/-](\d{1,2})(?:/|-|$)", url)
    if m:
        try:
            return datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def make_date_checker(get=http_get, post=http_post):
    def check(item: dict) -> datetime | None:
        """Real publish date of a Google News item, or None if it can't be established."""
        real = resolve_google_link(item["url"], get, post)
        if not real:
            return None
        return page_publish_date(get(real).decode("utf-8", errors="replace"), real)
    return check


# ---------- classification ----------

class Classifier:
    def __init__(self, cfg: dict):
        self.regions = {name: compile_terms(terms) for name, terms in cfg["regions"].items()}
        kw = cfg["keywords"]
        self.high = compile_terms(kw["high"])
        self.medium = compile_terms(kw["medium"])
        self.exclude = compile_terms(kw.get("exclude", []))

    def regions_in(self, text: str) -> list[str]:
        t = normalise(strip_publisher(text))
        return [name for name, rx in self.regions.items() if rx and rx.search(t)]

    def severity(self, text: str) -> str | None:
        t = normalise(strip_publisher(text))
        if self.exclude and self.exclude.search(t):
            return None
        if self.high and self.high.search(t):
            return "high"
        if self.medium and self.medium.search(t):
            return "medium"
        return None


# ---------- sources ----------
# Each news source is a callable returning items; build_news_sources lists them by name.

def gdelt_source(q: dict, get=http_get):
    def fetch(t0: datetime) -> list[dict]:
        params = {"query": q["query"], "mode": "artlist", "format": "json",
                  "timespan": "2h", "maxrecords": "75", "sort": "datedesc"}
        url = f"{GDELT_URL}?{urllib.parse.urlencode(params)}"
        for attempt in range(2):
            try:
                raw = get(url).decode("utf-8", errors="replace")
                break
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt:
                    raise
                time.sleep(10)
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            raise RuntimeError(raw.strip()[:120])
        items = []
        for a in data.get("articles", []) or []:
            try:
                ts = datetime.strptime(a.get("seendate", ""), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                ts = t0
            items.append({"title": a.get("title", "").strip(), "url": a.get("url", ""),
                          "publisher": a.get("domain", ""), "time": iso(ts)})
        return items
    return fetch


def gnews_source(q: dict, get=http_get):
    def fetch(t0: datetime) -> list[dict]:
        params = {"q": q["query"], "hl": q.get("hl", "en-US"), "gl": q.get("gl", "US"),
                  "ceid": q.get("ceid", "US:en")}
        return parse_feed(get(f"{GNEWS_URL}?{urllib.parse.urlencode(params)}"), t0)
    return fetch


def rss_source(f: dict, get=http_get):
    def fetch(t0: datetime) -> list[dict]:
        items = parse_feed(get(f["url"]), t0)
        for it in items:
            it["publisher"] = it["publisher"] or f["name"]
        return items
    return fetch


def build_news_sources(cfg: dict, get=http_get) -> list[tuple[str, dict, callable]]:
    out = []
    for q in cfg.get("gdelt", []):
        out.append((f"gdelt:{q['name']}", q, gdelt_source(q, get)))
    for q in cfg.get("google_news", []):
        out.append((f"gnews:{q['name']}", q, gnews_source(q, get)))
    for f in cfg.get("rss", []):
        out.append((f"rss:{f['name']}", f, rss_source(f, get)))
    return out


CZIB_LINK = re.compile(r'href="([^"]*/czibs/(czib-?[0-9][0-9a-z-]*))"', re.IGNORECASE)


def fetch_easa(cfg: dict, get=http_get) -> dict[str, str]:
    """Return {bulletin slug: absolute url} for every CZIB linked from the index page."""
    url = cfg["easa"]["url"]
    page = get(url).decode("utf-8", errors="replace")
    found = {}
    for href, slug in CZIB_LINK.findall(page):
        found[slug.lower()] = urllib.parse.urljoin(url, html.unescape(href))
    if not found:
        raise RuntimeError("no bulletin links found (page layout may have changed)")
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
    return {"seen": {}, "czibs": {}, "pages": {}, "last_alert": {}, "sources_init": [], "stories": [],
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

def run(cfg: dict, state: dict, news_sources, easa=None, page_get=None,
        clock=now_utc, pause: float = 0, date_check=None) -> dict:
    """One monitoring pass. Returns {'events','triggers','alerts','errors','status'}."""
    t0 = clock()
    s = cfg["settings"]
    clf = Classifier(cfg)
    state.setdefault("sources_init", [])
    warmup = not state.get("initialised")
    events, triggers, alerts, errors, status = [], [], [], [], []
    max_age = timedelta(hours=s.get("max_age_hours", 6))
    story_thr = s.get("story_similarity", 0.6)
    max_checks = s.get("max_date_checks", 25)
    checks = {"done": 0, "stale": 0, "unknown": 0}
    state.setdefault("stories", [])
    news_ok = False

    # 1. news
    by_region: dict[str, list[dict]] = {}
    for i, (name, conf, fetch) in enumerate(news_sources):
        if i and pause:
            time.sleep(pause)
        try:
            items = fetch(t0)
            state["failures"][name] = 0
            news_ok = True
        except Exception as e:  # one dead source must not stop the run
            state["failures"][name] = state["failures"].get(name, 0) + 1
            errors.append(f"{name}: {str(e)[:150]}")
            status.append(f"{name}: FAILED ({str(e)[:80]})")
            continue
        first_time = name not in state["sources_init"]
        kept = repeats = 0
        for it in items:
            if not it["title"]:
                continue
            key = norm_key(it["title"])
            if key in state["seen"]:
                continue
            state["seen"][key] = iso(t0)
            sev = clf.severity(it["title"])
            regions = clf.regions_in(it["title"]) or ([conf["region"]] if conf.get("region") else [])
            if not sev or not regions:
                continue
            # Story memory: a reworded or re-published version of a story already seen
            # (even one seen only as stale or baseline) is not news.
            toks = story_tokens(it["title"])
            if any(same_story(toks, set(k["t"]), story_thr) for k in state["stories"]):
                repeats += 1
                continue
            state["stories"].append({"t": sorted(toks), "time": iso(t0)})
            if first_time or t0 - parse_iso(it["time"]) > max_age:
                continue  # baseline for a new source, or stale item
            if date_check and sev == "high" and name.startswith("gnews:") and checks["done"] < max_checks:
                checks["done"] += 1
                try:
                    real = date_check(it)
                except Exception:
                    real = None
                if real is None:
                    checks["unknown"] += 1
                    it = {**it, "date_unverified": True}
                elif t0 - real > max_age:
                    checks["stale"] += 1
                    continue  # old article Google re-dated; the story is remembered above
                else:
                    it = {**it, "time": iso(real)}
            ev = {**it, "source": name, "severity": sev, "regions": regions, "logged": iso(t0)}
            events.append(ev)
            kept += 1
            for r in regions:
                by_region.setdefault(r, []).append(ev)
        if first_time:
            state["sources_init"].append(name)
        status.append(f"{name}: {len(items)} items, {kept} relevant, {repeats} repeats"
                      + (" (baseline)" if first_time else ""))

    if date_check:
        status.append(f"date check: {checks['done']} checked, {checks['stale']} old articles dropped, "
                      f"{checks['unknown']} could not be verified")

    cooldown = timedelta(minutes=s["cooldown_minutes"])
    for region, evs in by_region.items():
        highs = [e for e in evs if e["severity"] == "high"]
        if highs:
            reason = "aviation"
        elif len(evs) >= s["cluster_threshold"]:
            reason = "security-cluster"
        else:
            continue
        last = state["last_alert"].get(region)
        cooling = last and t0 - parse_iso(last) < cooldown
        lead = (highs or evs)[0]
        triggers.append({"time": iso(t0), "region": region, "reason": reason,
                         "count": len(evs), "headline": lead["title"], "url": lead["url"]})
        if not cooling:
            state["last_alert"][region] = iso(t0)
            lines = [f"- {e['title']}" + (" [date unverified]" if e.get("date_unverified") else "")
                     for e in (highs or evs)[:5]]
            alerts.append({"title": f"{region.replace('_', ' ')}: {reason} ({len(evs)} new)",
                           "message": "\n".join(lines), "priority": 4 if highs else 3,
                           "click": lead["url"], "tags": ["airplane"] if highs else ["warning"]})

    # 2. EASA bulletins
    if cfg.get("easa") and easa:
        try:
            current = easa(cfg)
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
            status.append(f"easa: {len(current)} bulletins listed, {len(new)} new")
        except Exception as e:
            state["failures"]["easa"] = state["failures"].get("easa", 0) + 1
            errors.append(f"easa: {str(e)[:150]}")
            status.append(f"easa: FAILED ({str(e)[:80]})")

    # 3. watched pages
    for page in cfg.get("watch_pages", []):
        try:
            sents = page_sentences(page_get(page["url"]).decode("utf-8", errors="replace"))
            known = set(state["pages"].get(page["url"], []))
            if known:
                for sentence in sents:
                    if hashlib.sha1(sentence.encode()).hexdigest()[:12] in known:
                        continue
                    regions = clf.regions_in(sentence)
                    if not regions:
                        continue
                    ev = {"source": f"page:{page['name']}", "title": sentence, "url": page["url"],
                          "publisher": page["name"], "time": iso(t0), "severity": "high",
                          "regions": regions, "logged": iso(t0)}
                    events.append(ev)
                    triggers.append({"time": iso(t0), "region": regions[0], "reason": "advisory-page",
                                     "count": 1, "headline": sentence, "url": page["url"]})
                    alerts.append({"title": f"{page['name']} updated: {', '.join(regions)}",
                                   "message": sentence, "priority": 4, "click": page["url"],
                                   "tags": ["airplane"]})
            state["pages"][page["url"]] = [hashlib.sha1(x.encode()).hexdigest()[:12] for x in sents]
            state["failures"][page["url"]] = 0
            status.append(f"page:{page['name']}: {len(sents)} sentences")
        except Exception as e:
            state["failures"][page["url"]] = state["failures"].get(page["url"], 0) + 1
            errors.append(f"{page['name']}: {str(e)[:150]}")
            status.append(f"page:{page['name']}: FAILED ({str(e)[:80]})")

    # 4. housekeeping
    keep = t0 - timedelta(days=s["seen_retention_days"])
    state["seen"] = {k: v for k, v in state["seen"].items() if parse_iso(v) >= keep}
    story_keep = t0 - timedelta(days=s.get("story_window_days", 7))
    state["stories"] = [x for x in state["stories"] if parse_iso(x["time"]) >= story_keep][-4000:]

    for src, n in state["failures"].items():
        if n == 6:  # about three to six hours of consecutive failures; alert once
            alerts.append({"title": f"Monitor source failing: {src}",
                           "message": "Six consecutive failures. Check the Actions log.",
                           "priority": 2, "click": "", "tags": ["wrench"]})

    local = t0.astimezone(ZoneInfo(s["timezone"]))
    today = local.date().isoformat()
    if local.hour >= s["digest_hour"] and state.get("last_digest") != today:
        state["last_digest"] = today
        failing = [k for k, v in state["failures"].items() if v]
        alerts.append({"title": "ME monitor daily check-in",
                       "message": f"Running. This pass: {len(events)} new events, {len(triggers)} triggers. "
                                  f"Sources failing: {', '.join(failing) or 'none'}.",
                       "priority": 2, "click": "", "tags": ["white_check_mark"]})

    if warmup:  # learn the current baseline before alerting, so the first live run doesn't flood
        triggers, alerts = [], []
        if news_ok:
            state["initialised"] = True
            alerts = [{"title": "ME monitor started",
                       "message": f"Baseline recorded: {len(state['seen'])} headlines, {len(state['czibs'])} EASA bulletins. "
                                  "Alerts start from the next run.",
                       "priority": 3, "click": "", "tags": ["white_check_mark"]}]

    return {"events": events, "triggers": triggers, "alerts": alerts, "errors": errors, "status": status}


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

    cfg = tomllib.loads(Path(a.config).read_text(encoding="utf-8"))
    state_path = Path(a.state)
    state = {**empty_state(), **load_json(state_path, {})}
    out = run(cfg, state, build_news_sources(cfg), easa=fetch_easa, page_get=http_get, pause=1.5,
              date_check=make_date_checker())

    for line in out["status"]:
        print("  " + line)
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
    state_path.write_text(json.dumps(state, indent=1, ensure_ascii=False))
    # a run where every source failed should show red in GitHub
    return 1 if out["errors"] and not out["events"] and not any("FAILED" not in x for x in out["status"]) else 0


if __name__ == "__main__":
    sys.exit(main())
