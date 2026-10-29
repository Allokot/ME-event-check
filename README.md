# ME aviation event monitor (step 1)

Every 30 minutes GitHub Actions runs `monitor.py`, which checks free sources for Middle East aviation and security events, logs them, and pushes alerts to your phone through ntfy. It costs nothing and makes no Flightradar24 calls; it writes `data/triggers.jsonl`, which step 2 will use to decide when a traffic scan is worth paying for.

## Sources
- GDELT news API: four queries (aviation and security terms, split Levant/Gulf)
- Google News RSS: two queries
- EASA Conflict Zone Information Bulletins: any new bulletin or revision
- Optional: airline advisory pages you list in `config.toml`

## What alerts
| Event | Priority |
|---|---|
| New or revised EASA bulletin | urgent |
| Headline with an aviation term and a region (airspace, NOTAM, flights suspended…) | high |
| 6+ security headlines for one region in one run (missile, airstrike…) | normal |
| New line on a watched advisory page naming a region | high |
| Daily check-in at 07:00, source failing for 3 hours | low |

News alerts for the same region are held back for 90 minutes; the trigger is still logged. Thresholds, regions and terms are all in `config.toml`.

## Setup (about 10 minutes)
1. **ntfy**: install the ntfy app (iOS/Android), subscribe to a topic with a long random name, e.g. `me-watch-k3v9x2q7`. Anyone who knows the name can read it, so treat it like a password.
2. **GitHub**: create a new **public** repository and upload this folder's contents, including the hidden `.github` folder. Public repos get unlimited free Actions minutes; private ones have had scheduled runs silently not firing on free accounts this month.
3. **Secret**: repo Settings → Secrets and variables → Actions → New repository secret: `NTFY_TOPIC` = your topic name.
4. **First run**: Actions tab → "ME event check" → Run workflow. You should get "ME monitor started". That run records the current headlines as a baseline, so you aren't flooded with old news.
5. Run it once more manually. After that it runs on its own at :07 and :37 past each hour.

## Files
- `data/events.jsonl`: every relevant item (committed only when something new appears)
- `data/triggers.jsonl`: region-level triggers for step 2
- State (seen headlines) is kept in the Actions cache, so routine runs don't create commits.

## Notes
- GitHub can delay scheduled runs by several minutes under load; this isn't real-time.
- Headline matching is keyword-based. Expect some noise; tune `[keywords]` and `cluster_threshold` after a week.
- Test locally: `python -m unittest discover -s tests` and `python monitor.py --dry-run` (Python 3.11+, no dependencies).
