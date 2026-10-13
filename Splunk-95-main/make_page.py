"""Write the page and its data file into the project folder."""
import json, os
ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = ROOT + "/"
page = open(os.path.join(ROOT, "template.html"), encoding="utf-8").read()
d = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
for r in d["rules"]:
    r.pop("stories", None); r.pop("slug", None); r.pop("rank", None)
    r["logic"].pop("clause", None)
    for m in r["matches"]:
        m.get("logic", {}).pop("raw_unused", None)
data = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
open(OUT + "data.json", "w", encoding="utf-8").write(data)
for f in ["index.html", "splunk-95-sigma-map.html"]:
    open(OUT + f, "w", encoding="utf-8").write(page)
if os.path.abspath(OUT) != ROOT and os.path.exists(OUT + "rules.json"):
    os.remove(OUT + "rules.json")  # superseded by data.json
print("page", len(page), "data", len(data))
