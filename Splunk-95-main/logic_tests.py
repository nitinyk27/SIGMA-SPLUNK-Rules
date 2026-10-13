"""Attach each Splunk detection's logic-test definition (published attack_data datasets) to data.json.

Only records the tests; it does not run them.
"""
import glob, json, os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SC = os.path.join(HERE, "security_content")
DATA = os.path.join(HERE, "data.json")

det = {}
for f in glob.glob(os.path.join(SC, "detections", "**", "*.yml"), recursive=True):
    d = yaml.safe_load(open(f, encoding="utf-8"))
    det[d.get("id")] = d

data = json.load(open(DATA, encoding="utf-8"))
n = 0
for r in data["rules"]:
    tests = []
    for t in det.get(r["id"], {}).get("tests") or []:
        ds = [{k: a.get(k, "") for k in ("data", "source", "sourcetype")} for a in t.get("attack_data") or [] if a.get("data")]
        if ds:
            tests.append({"name": t.get("name", "Test"), "type": t.get("test_type", ""), "datasets": ds})
    r["tests"] = tests
    n += bool(tests)
json.dump(data, open(DATA, "w", encoding="utf-8"), separators=(",", ":"), ensure_ascii=False)
print("rules with logic tests", n, "of", len(data["rules"]))
