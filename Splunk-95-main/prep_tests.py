"""List each Splunk detection's attack_data samples (tests.json) and the size of each Windows XML sample (sizes.json)."""
import glob, json, os, urllib.request, concurrent.futures as cf
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
SC = os.path.join(ROOT, "security_content")

tests = {}
for f in glob.glob(os.path.join(SC, "detections", "**", "*.yml"), recursive=True):
    d = yaml.safe_load(open(f, encoding="utf-8"))
    ad = [a for t in d.get("tests") or [] for a in t.get("attack_data") or [] if a.get("data")]
    if ad:
        tests[d["id"]] = ad
json.dump(tests, open(os.path.join(ROOT, "tests.json"), "w"), indent=1)

def size(u):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(u, method="HEAD"), timeout=60) as r:
                return u, int(r.headers.get("Content-Length", -1))
        except Exception:
            pass
    return u, -1  # unavailable

urls = sorted({a["data"] for ad in tests.values() for a in ad if a.get("source", "").startswith("XmlWinEventLog")})
with cf.ThreadPoolExecutor(16) as ex:
    sizes = dict(ex.map(size, urls))
json.dump(sizes, open(os.path.join(ROOT, "sizes.json"), "w"), indent=1)
print("detections with tests", len(tests), "windows samples", len(urls), "unavailable", sum(s < 0 for s in sizes.values()))
