"""Score every Splunk <-> Sigma pair for relevance, detection overlap and feasibility."""
import json, os, re, warnings
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_cim_data_model, splunk_windows_pipeline

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.abspath(__file__))
SG = os.path.join(ROOT, "sigma")

# Splunk CIM field -> Sigma field
FIELD_MAP = {
    "process_name": "Image", "process_exec": "Image", "process_path": "Image", "original_file_name": "OriginalFileName",
    "process": "CommandLine", "parent_process_name": "ParentImage", "parent_process_path": "ParentImage",
    "parent_process_exec": "ParentImage", "parent_process": "ParentCommandLine", "registry_path": "TargetObject",
    "registry_key_name": "TargetObject", "registry_value_name": "TargetObject", "registry_value_data": "Details",
    "file_path": "TargetFilename", "file_name": "TargetFilename", "query": "QueryName", "dest_hostname": "DestinationHostname",
    "dest_port": "DestinationPort", "url": "cs-uri-query", "http_method": "cs-method", "EventCode": "EventID",
    "SourceImage": "SourceImage", "TargetImage": "TargetImage", "GrantedAccess": "GrantedAccess", "user": "User",
}
# Splunk data model -> Sigma logsource categories that describe the same telemetry
DM_CAT = {
    "Endpoint.Processes": {"process_creation"}, "Endpoint.Registry": {"registry_set", "registry_add", "registry_event", "registry_delete"},
    "Endpoint.Filesystem": {"file_event", "file_delete", "file_rename", "file_access", "file_change"},
    "Network_Resolution": {"dns_query", "dns"}, "Network_Traffic": {"network_connection", "firewall"},
    "Web": {"webserver", "proxy"}, "Endpoint.Services": {"service"}, "Change": set(),
}
SYSMON_EVENT_CAT = {"1": "process_creation", "3": "network_connection", "7": "image_load", "8": "create_remote_thread",
                    "10": "process_access", "11": "file_event", "12": "registry_event", "13": "registry_set",
                    "17": "pipe_created", "22": "dns_query", "23": "file_delete"}
TACTICS = {}  # filled from rule data

def norm(v):
    v = str(v).lower().replace("\\\\", "\\").strip().strip("*").strip()
    return v.lstrip("\\/").strip()

def match(a, b):
    a, b = norm(a), norm(b)
    if len(a) < 3 or len(b) < 3:
        return a == b and a != ""
    return a in b or b in a

def title_sim(a, b):
    stop = set("detects detect detection suspicious possible potential windows execution activity using usage process via with from the".split())
    wa = {w for w in re.findall(r"[a-z0-9]{3,}", a.lower()) if w not in stop}
    wb = {w for w in re.findall(r"[a-z0-9]{3,}", b.lower()) if w not in stop}
    return len(wa & wb) / max(1, len(wa | wb))

def splunk_values(r):
    out = []
    for c in r["logic"]["conditions"]:
        if c["kind"] != "cond" or c["op"] in (">", "<", ">=", "<="):
            continue
        for v in c["values"]:
            if norm(v):
                out.append((c["field"], v, c["op"] in ("!=", "not in")))
    return out

def sigma_values(m):
    pos, neg = [], []
    for s in m["logic"]["selections"]:
        for g in s["groups"]:
            for row in g:
                for v in row["values"]:
                    if v in ("(null)", "") or not norm(v):
                        continue
                    (neg if s["filter"] else pos).append((row["field"], v))
    return pos, neg

def splunk_target_categories(r):
    cats = set()
    dm = r["logic"].get("datamodel", "")
    for k, v in DM_CAT.items():
        if dm.startswith(k):
            cats |= v
    for c in r["logic"]["conditions"]:
        if c["field"] in ("EventCode", "EventID"):
            for v in c["values"]:
                if v in SYSMON_EVENT_CAT and "sysmon" in r["search"].lower():
                    cats.add(SYSMON_EVENT_CAT[v])
    return cats

def logsource_fit(r, m):
    cat = m["logic"]["raw"]
    ls = yaml.safe_load(m["logic"]["raw"]).get("logsource", {})
    lcat, prod, svc = ls.get("category", ""), ls.get("product", ""), ls.get("service", "")
    cats = splunk_target_categories(r)
    ds = " ".join(r["data_source"]).lower() + " " + r["search"].lower()
    if lcat and lcat in cats:
        return 1.0, f"Same telemetry: Splunk {r['logic'].get('datamodel') or 'source'} ↔ Sigma {lcat}"
    if cats and lcat and lcat.startswith("registry") and any(c.startswith("registry") for c in cats):
        return 0.8, f"Similar telemetry: Splunk {'/'.join(sorted(cats))} ↔ Sigma {lcat}"
    hints = [x for x in (prod, svc) if x]
    if hints and any(h.lower().replace("_", "") in ds.replace("_", "").replace(" ", "") or
                     {"m365": "o365", "azure": "azure", "linux": "auditd"}.get(h, "@@") in ds for h in hints):
        return 0.8, f"Same product: Sigma {'/'.join(hints)} matches the Splunk data source"
    return 0.3, f"Different telemetry: Splunk uses {', '.join(r['data_source'][:2]) or 'other data'}, Sigma expects {'/'.join(x for x in (prod, lcat, svc) if x)}"

# ---------- relevance ----------
def relevance(r, m, ov):
    sp_t = {x["id"] for x in r["mitre"]}
    sp_tac = {t for x in r["mitre"] for t in x["tactics"]}
    reasons = []
    exact = sp_t & set(m["mitre"])
    parent = {t.split(".")[0] for t in sp_t} & {t.split(".")[0] for t in m["mitre"]}
    if exact:
        tech = 45; reasons.append(f"Same ATT&CK technique ({', '.join(sorted(exact))})")
    elif parent:
        tech = 32; reasons.append(f"Same parent technique ({', '.join(sorted(parent))}), different sub-technique")
    elif not m["mitre"]:
        tech = 10; reasons.append("Sigma rule has no ATT&CK technique tag")
    else:
        tech = 5; reasons.append(f"Different techniques (Splunk {', '.join(sorted(sp_t))} vs Sigma {', '.join(m['mitre'])})")
    ts = title_sim(r["name"], m["title"])
    tsc = round(20 * min(1, ts * 2))
    if ts >= 0.3:
        reasons.append("Rule names describe the same behaviour")
    fit, why = logsource_fit(r, m)
    reasons.append(why)
    best_cov = max(ov["splunk_cov"], ov["sigma_cov"]) / 100
    ind = round(15 * best_cov)
    if best_cov < .3:
        reasons.append("Little shared detection logic")
    score = min(100, tech + tsc + round(20 * fit) + ind)
    if best_cov < .3:
        score = min(score, 55)
    label = "High" if score >= 70 else "Medium" if score >= 45 else "Low"
    return {"score": score, "label": label, "reasons": reasons}

# ---------- overlap ----------
def overlap(r, m):
    S = splunk_values(r)
    G, F = sigma_values(m)
    s_hit = [v for v in S if any(match(v[1], g[1]) for g in G)]
    g_hit = [g for g in G if any(match(v[1], g[1]) for v in S)]
    covS = len(s_hit) / len(S) if S else 0
    covG = len(g_hit) / len(G) if G else 0
    only_s = [f"{f} {'≠' if neg else '='} {v}" for f, v, neg in S if (f, v, neg) not in s_hit]
    only_g = [f"{f} = {v}" for f, v in G if (f, v) not in g_hit]
    shared = sorted({v for _, v, _ in s_hit}, key=len)
    # fields that line up between the two rules
    fpairs = set()
    for f, v, _ in s_hit:
        for gf, gv in G:
            if match(v, gv):
                fpairs.add(f"{f} ↔ {gf}")
    field_ok = [p for p in fpairs if FIELD_MAP.get(p.split(" ↔ ")[0]) == p.split(" ↔ ")[1]]
    score = round(100 * (covS + covG) / 2)
    if covS >= .75 and covG >= .75:
        label, summary = "Equivalent", "Both rules look for essentially the same values."
    elif covS >= .75:
        label, summary = "Sigma ⊇ Splunk", "Everything the Splunk rule looks for is also in the Sigma rule; Sigma adds more values or conditions."
    elif covG >= .75:
        label, summary = "Splunk ⊇ Sigma", "Everything the Sigma rule looks for is also in the Splunk rule; Splunk adds more values or conditions."
    elif max(covS, covG) >= .3:
        label, summary = "Partial", "The rules share some indicators, but each checks things the other does not."
    else:
        label, summary = "Minimal", "Few indicators in common; treat these as related rather than overlapping."
    notes = []
    if F:
        notes.append(f"Sigma excludes {len(F)} value(s) (filters) that the Splunk rule does not exclude")
    neg_s = [v for v in S if v[2]]
    if neg_s:
        notes.append(f"Splunk excludes {len(neg_s)} value(s)")
    if re.search(r"\|\s*(where|search)\s+\w*(count|unique|dc)\w*\s*[<>]=?", r["search"], re.I) or re.search(r"\bwhere\s+count\s*[<>]", r["search"], re.I):
        notes.append("Splunk applies a count threshold that plain Sigma cannot express")
    if "timeframe" in m["logic"]["raw"] or "correlation" in m["logic"]["raw"]:
        notes.append("Sigma uses a time window/correlation")
    return {"score": score, "label": label, "summary": summary, "splunk_cov": round(covS * 100), "sigma_cov": round(covG * 100),
            "shared": shared[:14], "only_splunk": only_s[:12], "only_sigma": only_g[:12],
            "n_splunk": len(S), "n_sigma": len(G), "fields": sorted(fpairs)[:8], "fields_std": len(field_ok), "notes": notes}

# ---------- feasibility ----------
_conv_cache = {}
def convert(path):
    if path not in _conv_cache:
        _conv_cache[path] = _convert(path)
    return _conv_cache[path]

def _convert(path):
    col = SigmaCollection.from_yaml(open(path, encoding="utf-8").read())
    attempts = [("cim", lambda: SplunkBackend(processing_pipeline=splunk_cim_data_model()).convert(col, "data_model")),
                ("windows", lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline()).convert(col)),
                ("generic", lambda: SplunkBackend().convert(col))]
    errs = []
    for name, fn in attempts:
        try:
            q = fn()
            if q:
                return name, q[0] if isinstance(q, list) else str(q), errs
        except Exception as e:
            errs.append(f"{name}: {str(e).splitlines()[0][:160]}")
    return None, "", errs

def feasibility(r, m):
    path = os.path.join(SG, m["url"].split("/blob/master/", 1)[1])
    mode, spl, errs = convert(path)
    raw = m["logic"]["raw"]
    ls = yaml.safe_load(raw).get("logsource", {})
    dm = r["logic"].get("datamodel", "")
    reasons, score = [], 0
    if mode == "cim":
        dm_sig = re.search(r"datamodel=(\S+)", spl)
        same = dm_sig and dm and dm_sig.group(1).split(".")[0] == dm.split(".")[0]
        score = 90 if same else 80
        reasons.append(f"pySigma converts it to a tstats search on {dm_sig.group(1) if dm_sig else 'a CIM data model'}" +
                       (", the same data model the Splunk rule uses" if same else ""))
    if mode == "windows" and ls.get("product") != "windows":
        mode = "generic"
    if mode in ("windows", "generic") and errs and ls.get("category") in ("process_creation", "registry_set", "registry_event", "registry_add", "file_event", "network_connection", "dns_query"):
        reasons.append("CIM data-model conversion failed (" + errs[0].split(": ", 1)[-1][:120] + ")")
    if mode == "windows":
        score = 70
        reasons.append("pySigma converts it to raw SPL using Windows event field names; it needs Sysmon or Security logs searchable with those fields")
        if "sysmon" in r["search"].lower() or "wineventlog" in r["search"].lower():
            score = 80; reasons.append("The Splunk rule already searches raw Windows event logs, so the data is there")
    elif mode == "generic":
        score = 50
        reasons.append("pySigma converts it only without a field-mapping pipeline; field names must be mapped to your sourcetype by hand")
        prod = ls.get("product", "") + ls.get("service", "")
        if any(k in r["search"].lower() for k in ("auditd", "azure", "o365", "aws", "gws", "okta", "cisco")) and prod:
            score = 60; reasons.append(f"The Splunk rule already searches {ls.get('product')} data, so only field names need mapping")
    elif mode != "cim":
        score = 20
        reasons.append("pySigma could not convert it to SPL; porting needs manual work")
        if errs:
            reasons.append(errs[-1])
    if "|expand" in raw:
        score -= 20; reasons.append("Uses placeholder values (|expand) that must be filled in for your environment")
    if re.search(r"\|re\b|\|re:", raw):
        score -= 5; reasons.append("Uses regex matching, which is slower in Splunk")
    status, level = m.get("status", ""), m.get("level", "")
    if status in ("experimental", "test"):
        reasons.append(f"Sigma status is '{status}', so tune it before production")
    if level in ("low", "informational"):
        score -= 5; reasons.append(f"Sigma level is '{level}' (hunting value rather than alerting)")
    score = max(5, min(100, score))
    label = "High" if score >= 75 else "Medium" if score >= 50 else "Low"
    return {"score": score, "label": label, "reasons": reasons, "mode": mode or "failed", "spl": spl[:4000]}

data = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
# sigma status/level back from source files (status was stripped for the page)
for r in data["rules"]:
    for m in r["matches"]:
        d = yaml.safe_load(open(os.path.join(SG, m["url"].split("/blob/master/", 1)[1]), encoding="utf-8"))
        m["status"] = d.get("status", "")
        ov = overlap(r, m)
        m["assess"] = {"relevance": relevance(r, m, ov), "overlap": ov, "feasibility": feasibility(r, m)}
    # a pair with low relevance and almost no shared logic is not coverage
    r["matches"] = [m for m in r["matches"] if not (m["assess"]["relevance"]["label"] == "Low" and m["assess"]["overlap"]["label"] == "Minimal")]
    if not r["matches"]:
        r["coverage"] = "None"
        continue
    a = r["matches"][0]["assess"]
    rel, ol = a["relevance"]["label"], a["overlap"]["label"]
    if rel == "High" and ol in ("Equivalent", "Sigma ⊇ Splunk"):
        r["coverage"] = "Strong"
    elif rel != "Low" and ol != "Minimal" and (rel == "High" or ol != "Partial"):
        r["coverage"] = "Moderate"
    else:
        r["coverage"] = "Weak"
json.dump(data, open(os.path.join(ROOT, "rules.json"), "w", encoding="utf-8"), indent=1)

from collections import Counter
best = [r["matches"][0]["assess"] for r in data["rules"] if r["matches"]]
print("coverage", Counter(r["coverage"] for r in data["rules"]))
print("relevance", Counter(a["relevance"]["label"] for a in best))
print("overlap", Counter(a["overlap"]["label"] for a in best))
print("feasibility", Counter(a["feasibility"]["label"] for a in best), Counter(a["feasibility"]["mode"] for a in best))
for r in data["rules"][:2]:
    a = r["matches"][0]["assess"]
    print("==", r["name"], "->", r["matches"][0]["title"])
    for k in a:
        print("  ", k, a[k]["label"], a[k]["score"], a[k].get("reasons", a[k].get("summary")))
    print("   spl:", a["feasibility"]["spl"][:200])
