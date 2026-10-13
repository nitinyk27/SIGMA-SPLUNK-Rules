"""Implementation readiness for every Splunk detection, from the security_content metadata."""
import glob, json, os, re
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
SC = os.path.join(ROOT, "security_content")

ds = {}
for f in glob.glob(os.path.join(SC, "data_sources", "*.yml")):
    d = yaml.safe_load(open(f, encoding="utf-8"))
    ds[d["name"]] = {"tas": [{"name": t.get("name"), "url": t.get("url")} for t in (d.get("supported_TA") or [])],
                     "source": d.get("source", ""), "sourcetype": d.get("sourcetype", "")}
shipped_lookups = {os.path.splitext(os.path.basename(f))[0] for f in glob.glob(os.path.join(SC, "lookups", "*.yml"))}
det = {}
for f in glob.glob(os.path.join(SC, "detections", "**", "*.yml"), recursive=True):
    d = yaml.safe_load(open(f, encoding="utf-8"))
    det[d.get("id")] = d

ES_LOOKUPS = {"identity_lookup_expanded", "asset_lookup_by_str", "asset_lookup_by_cidr"}
data = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
from collections import Counter
cnt = Counter()
for r in data["rules"]:
    d = det.get(r["id"], {})
    search = r["search"]
    req, blockers, score = [], [], 100
    # data sources + add-ons
    srcs = r["data_source"] or []
    tas, unknown = [], []
    for s in srcs:
        info = ds.get(s)
        if not info:
            unknown.append(s)
            continue
        for t in info["tas"]:
            if t["name"] and t not in tas:
                tas.append(t)
    if srcs:
        req.append({"k": "Data", "v": "Any one of: " + ", ".join(srcs) if len(srcs) > 1 else srcs[0]})
    else:
        req.append({"k": "Data", "v": "No data source listed (built on other detections' results or the Risk index)"})
    # how common is the telemetry this rule needs
    low = " ".join(srcs).lower()
    if not srcs:
        tier = None
    elif all(re.search(r"^sysmon eventid (1|3|7|8|10|11|12|13|14|22|23)|windows event log security|crowdstrike processrollup2", x.lower()) for x in srcs[:1]) or             any(re.search(r"^sysmon eventid (1|11|13)|windows event log security 4688", x.lower()) for x in srcs):
        tier = "Common endpoint telemetry (Sysmon, Windows Security or EDR)"
    elif re.search(r"sysmon|windows event log|powershell|wineventlog|auditd|linux|osquery|windows", low):
        tier = "Extra OS logging (other Windows channels, PowerShell, Linux auditd/Sysmon)"; score -= 10
        blockers.append("Needs OS logging beyond the defaults: " + ", ".join(srcs[:3]))
    else:
        tier = "Product-specific logs"; score -= 20
        blockers.append("Only works if you collect logs from this product: " + ", ".join(srcs[:3]))
    if tier:
        req.insert(0, {"k": "Telemetry", "v": tier})
    if tas:
        req.append({"k": "Add-on", "v": "; ".join(t["name"] for t in tas[:4]), "links": [t["url"] for t in tas[:4] if t.get("url")]})
    elif srcs:
        score -= 15; blockers.append("No Splunk add-on is listed for this data source; field extractions may need to be built")
    # data model
    dm = r["logic"].get("datamodel") or ""
    if dm:
        root = dm.split(".")[0]
        req.append({"k": "Data model", "v": f"{dm} (CIM, accelerated for tstats)"})
        if root == "Risk":
            score -= 25; blockers.append("Runs on the Risk data model, so Enterprise Security risk-based alerting must be set up and feeding risk events")
    # macros that point at your indexes
    mac = sorted({m for m in re.findall(r"`([a-z0-9_]+)`", search)
                  if not m.startswith("security_content") and not m.endswith("_filter") and not m.startswith("drop_dm") and not m.startswith("process_")})
    if mac:
        req.append({"k": "Macros to point at your indexes", "v": ", ".join(f"`{m}`" for m in mac[:6])})
    # lookups
    lk = sorted(set(re.findall(r"(?:\|\s*lookup|inputlookup|outputlookup)\s+(?:append=\w+\s+)?([A-Za-z0-9_]+)", search)))
    if lk:
        custom = [x for x in lk if x not in shipped_lookups and x not in ES_LOOKUPS]
        es = [x for x in lk if x in ES_LOOKUPS]
        req.append({"k": "Lookups", "v": ", ".join(lk)})
        if es:
            score -= 10; blockers.append("Uses Enterprise Security identity/asset lookups (" + ", ".join(es) + "); populate them first")
        if custom:
            score -= 10; blockers.append("Needs lookups not shipped with ESCU: " + ", ".join(custom))
    # rule type and status
    typ, status = r.get("type"), r.get("status")
    if typ == "Correlation":
        score -= 20; blockers.append("Correlation rule: fires on combined risk from other detections, so those detections must run first")
    elif typ == "Hunting":
        score -= 10; blockers.append("Hunting search: meant for analyst-driven hunts, not an alert out of the box")
    elif typ == "Anomaly":
        req.append({"k": "Output", "v": "Anomaly: contributes risk/intermediate findings rather than a standalone alert"})
    if status == "experimental":
        score -= 15; blockers.append("Experimental status: Splunk has not promoted it to production, so expect tuning")
    if re.search(r"\|\s*(where|search)\s+[^|]*\b(count|dc|risk_score|unique\w*)\b\s*[<>]", search, re.I):
        req.append({"k": "Threshold", "v": "Applies a count/score threshold; tune it to your environment"})
    fp = (r.get("fp") or "").lower()
    if any(w in fp for w in ("filter as needed", "tune", "may be required", "noisy", "legitimate")):
        req.append({"k": "Tuning", "v": "Known false positives listed; plan to tune the `_filter` macro"})
    tests = [a for t in (d.get("tests") or []) for a in (t.get("attack_data") or [])]
    if not tests:
        score -= 10; blockers.append("No sample attack data published, so it cannot be validated with Splunk's test data")
    prods = d.get("product") or []
    req.append({"k": "Platform", "v": ", ".join(prods) + " · ships in the ES Content Update (ESCU) app"})
    if unknown:
        blockers.append("Data source not described in Splunk's catalog: " + ", ".join(unknown))
    score = max(5, min(100, score))
    label = "Ready" if score >= 85 else "Needs setup" if score >= 60 else "Complex"
    r["ready"] = {"score": score, "label": label, "req": req, "blockers": blockers, "has_tests": bool(tests)}
    cnt[label] += 1
json.dump(data, open(os.path.join(ROOT, "rules.json"), "w", encoding="utf-8"), indent=1)
print(cnt)
