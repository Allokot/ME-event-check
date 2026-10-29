"""Offline tests: python -m unittest discover -s tests"""
import json
import sys
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402

CFG = tomllib.loads((ROOT / "config.toml").read_text())
T0 = datetime(2026, 10, 29, 21, 37, tzinfo=timezone.utc)

GDELT = json.dumps({"articles": [
    {"title": "Iran closes airspace after missile launches", "url": "https://a.example/1",
     "domain": "a.example", "seendate": "20261029T212500Z"},
    {"title": "Qatar Airways suspends flights to Baghdad", "url": "https://b.example/2",
     "domain": "b.example", "seendate": "20261029T212000Z"},
    {"title": "Oil prices edge higher", "url": "https://c.example/3",
     "domain": "c.example", "seendate": "20261029T211000Z"},
]})
RSS = """<rss><channel>
<item><title>Iran closes airspace after missile launches - Reuters</title><link>https://g/1</link>
<pubDate>Thu, 29 Oct 2026 21:26:00 GMT</pubDate><source>Reuters</source></item>
<item><title>Explosions heard in Damascus as air defense activated - AP</title><link>https://g/2</link>
<pubDate>Thu, 29 Oct 2026 21:20:00 GMT</pubDate><source>AP</source></item>
</channel></rss>"""
EASA_A = '<a href="/en/domains/air-operations/czibs/czib-2026-03r5">x</a><a href="/en/domains/air-operations/czibs/czib-2026-09">y</a>'
EASA_B = EASA_A + '<a href="/en/domains/air-operations/czibs/czib-2026-03r6">z</a>'


def fetchers(gdelt=GDELT, rss=RSS, easa=EASA_A):
    return {
        "gdelt": lambda cfg: m.fetch_gdelt({**cfg, "gdelt": cfg["gdelt"][:1]}, get=lambda u: gdelt),
        "google_news": lambda cfg: m.fetch_google_news(cfg, get=lambda u: rss),
        "easa": lambda cfg: m.fetch_easa(cfg, get=lambda u: easa),
        "page": lambda url: "",
    }


def primed_state():
    st = m.empty_state()
    st["initialised"] = True
    st["last_digest"] = "2026-10-29"
    st["czibs"] = {"czib-2026-03r5": "x", "czib-2026-09": "x"}
    return st


class TestMonitor(unittest.TestCase):
    def test_first_run_is_silent_baseline(self):
        st = m.empty_state()
        out = m.run(CFG, st, fetchers(), clock=lambda: T0)
        self.assertEqual([a["title"] for a in out["alerts"]], ["ME monitor started"])
        self.assertEqual(out["triggers"], [])
        self.assertTrue(st["initialised"])
        self.assertEqual(len(st["czibs"]), 2)

    def test_failed_first_run_stays_in_warmup(self):
        st = m.empty_state()
        dead = fetchers()
        dead["gdelt"] = dead["google_news"] = lambda cfg: (_ for _ in ()).throw(OSError("down"))
        out = m.run(CFG, st, dead, clock=lambda: T0)
        self.assertEqual(out["alerts"], [])
        self.assertFalse(st["initialised"])

    def test_classification_dedup_and_alerts(self):
        st = primed_state()
        out = m.run(CFG, st, fetchers(), clock=lambda: T0)
        titles = [e["title"] for e in out["events"]]
        # Reuters copy of the Iran headline is a duplicate; oil story is irrelevant
        self.assertEqual(len(titles), 3, titles)
        sev = {e["title"][:20]: (e["severity"], e["regions"]) for e in out["events"]}
        self.assertEqual(sev["Iran closes airspace"], ("high", ["Iran"]))
        self.assertEqual(sev["Qatar Airways suspen"], ("high", ["Iraq", "Qatar"]))
        self.assertEqual(sev["Explosions heard in "][0], "medium")
        regions = {t["region"] for t in out["triggers"]}
        self.assertEqual(regions, {"Iran", "Iraq", "Qatar"})  # Syria single medium item: no trigger
        self.assertTrue(all(a["priority"] == 4 for a in out["alerts"]))

    def test_seen_items_not_repeated(self):
        st = primed_state()
        m.run(CFG, st, fetchers(), clock=lambda: T0)
        out = m.run(CFG, st, fetchers(), clock=lambda: T0 + timedelta(minutes=30))
        self.assertEqual(out["events"], [])

    def test_cooldown_suppresses_push_but_keeps_trigger(self):
        st = primed_state()
        m.run(CFG, st, fetchers(), clock=lambda: T0)
        g2 = json.dumps({"articles": [{"title": "Iran extends airspace closure until Friday",
                                       "url": "https://a/9", "domain": "a", "seendate": "20261029T220000Z"}]})
        out = m.run(CFG, st, fetchers(gdelt=g2, rss="<rss/>"), clock=lambda: T0 + timedelta(minutes=30))
        self.assertEqual(len(out["triggers"]), 1)
        self.assertEqual(out["alerts"], [])
        out = m.run(CFG, st, fetchers(gdelt=g2.replace("Friday", "Sunday"), rss="<rss/>"),
                    clock=lambda: T0 + timedelta(minutes=120))
        self.assertEqual(len(out["alerts"]), 1)

    def test_security_cluster_escalates(self):
        st = primed_state()
        arts = [{"title": f"Missile strike number {i} reported near Erbil", "url": f"https://x/{i}",
                 "domain": "x", "seendate": "20261029T212000Z"} for i in range(6)]
        out = m.run(CFG, st, fetchers(gdelt=json.dumps({"articles": arts}), rss="<rss/>"), clock=lambda: T0)
        self.assertEqual([t["reason"] for t in out["triggers"]], ["security-cluster"])
        self.assertEqual(out["alerts"][0]["priority"], 3)

    def test_new_easa_bulletin_alerts(self):
        st = primed_state()
        out = m.run(CFG, st, fetchers(gdelt='{"articles":[]}', rss="<rss/>", easa=EASA_B), clock=lambda: T0)
        self.assertEqual(len(out["alerts"]), 1)
        self.assertIn("CZIB-2026-03R6", out["alerts"][0]["title"])
        self.assertEqual(out["alerts"][0]["priority"], 5)

    def test_bad_source_does_not_stop_run(self):
        st = primed_state()
        out = m.run(CFG, st, fetchers(gdelt="Your query was too short"), clock=lambda: T0)
        self.assertEqual(len(out["errors"]), 1)
        self.assertTrue(out["events"])  # Google News still processed

    def test_daily_digest_once(self):
        st = primed_state()
        st["last_digest"] = "2026-10-28"
        morning = datetime(2026, 10, 30, 6, 7, tzinfo=timezone.utc)  # 07:07 Amsterdam
        e = fetchers(gdelt='{"articles":[]}', rss="<rss/>")
        out1 = m.run(CFG, st, e, clock=lambda: morning)
        out2 = m.run(CFG, st, e, clock=lambda: morning + timedelta(minutes=30))
        self.assertEqual([a["title"] for a in out1["alerts"]], ["ME monitor daily check-in"])
        self.assertEqual(out2["alerts"], [])

    def test_watch_page_diff(self):
        st = primed_state()
        cfg = {**CFG, "gdelt": [], "google_news": [], "easa": None,
               "watch_pages": [{"name": "Airline X", "url": "https://air/x"}]}
        page1 = "<p>Welcome to our travel updates page for all customers.</p>"
        page2 = page1 + "<p>All flights to Tel Aviv are suspended until 5 November.</p>"
        f = fetchers()
        f["page"] = lambda url: page1
        self.assertEqual(m.run(cfg, st, f, clock=lambda: T0)["alerts"], [])
        f["page"] = lambda url: page2
        out = m.run(cfg, st, f, clock=lambda: T0)
        self.assertEqual(out["events"][0]["regions"], ["Israel"])
        self.assertEqual(len(out["alerts"]), 1)


if __name__ == "__main__":
    unittest.main()
