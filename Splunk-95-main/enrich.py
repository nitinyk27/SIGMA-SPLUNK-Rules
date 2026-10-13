"""Add readable detection logic to rules.json: Splunk conditions and Sigma detection blocks."""
import json, os, re
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
SC = os.path.join(ROOT, "security_content")
SG = os.path.join(ROOT, "sigma")

macros = {}
for f in os.listdir(os.path.join(SC, "macros")):
    try:
        m = yaml.safe_load(open(os.path.join(SC, "macros", f), encoding="utf-8"))
        macros[m["name"]] = (m.get("definition") or "").strip()
    except Exception:
        pass

SKIP_MACRO = re.compile(r"^(security_content_|drop_dm_object_name|.*_filter$)")

def splunk_filter(search):
    """Return the part of the SPL that decides what matches, with helper macros expanded."""
    s = re.sub(r"```.*?```", " ", search.strip(), flags=re.S)
    m = re.search(r"\bwhere\b(.*?)(?:\bby\b|\|)", s, re.I | re.S) if re.match(r"\|?\s*tstats", s) else None
    if m:
        clause = m.group(1)
    else:
        # plain search: the base search plus any where/search filters, stop at aggregation/formatting
        parts = [p.strip() for p in s.split("|") if p.strip()]
        keep = []
        for p in parts:
            head = p.split()[0].lower()
            if head in ("stats", "tstats", "table", "fields", "rename", "eval", "rex", "lookup", "fillnull", "dedup",
                        "sort", "join", "spath", "streamstats", "eventstats", "bin", "bucket", "iplocation", "mvexpand", "makemv",
                        "convert", "inputlookup", "append", "transaction", "timechart", "top", "rare", "head") and keep:
                if head == "stats":
                    continue
                continue
            if p.startswith("`") and SKIP_MACRO.match(p.strip("`").split("(")[0]):
                continue
            if head in ("where", "search") or not keep:
                keep.append(p)
        clause = "\n| ".join(keep)
    clause = re.sub(r"\s+", " ", clause).strip()

    def expand(mt):
        name = mt.group(1)
        if SKIP_MACRO.match(name):
            return ""
        d = macros.get(name)
        if d is None:
            return mt.group(0)
        # data-source macros (sysmon, wineventlog_security…) just pick the index/sourcetype
        if name.startswith("process_") or len(d) < 400:
            return f"{d}"
        return mt.group(0)
    expanded = re.sub(r"`([A-Za-z0-9_]+)(?:\([^`]*\))?`", expand, clause)
    return clause, re.sub(r"\s+", " ", expanded).strip()

COND = re.compile(
    r"""(?P<not>\bNOT\s+)?"?(?P<f>[A-Za-z_][\w.{}]*)"?\s*(?:(?P<op>!=|=|<=|>=|<|>)\s*(?P<v>"[^"]*"|'[^']*'|[^\s()]+)|\s+IN\s*\((?P<in>[^)]*)\))""",
    re.I)

def splunk_conditions(expr):
    rows, seen = [], {}
    for m in COND.finditer(expr):
        f = m.group("f")
        if f.lower() in ("index", "sourcetype", "source", "earliest", "latest", "eventtype", "channel", "datamodel") and not m.group("in"):
            kind = "source"
        else:
            kind = "cond"
        f = re.sub(r"^(Processes|Filesystem|Registry|Network_Traffic|All_Traffic|Web|Authentication|All_Changes|Change|DNS|Network_Resolution|All_Email|Endpoint)\.", "", f)
        if m.group("in"):
            vals = [v.strip().strip('"\'') for v in re.findall(r'"[^"]*"|\'[^\']*\'|[^,\s]+', m.group("in"))]
            op = "not in" if m.group("not") else "in"
        else:
            vals = [m.group("v").strip('"\'')]
            op = m.group("op")
            if m.group("not"):
                op = {"=": "!=", "!=": "="}.get(op, op)
        vals = [v.replace("\\\\", "\\") for v in vals if v and v != "="]
        if not vals:
            continue
        key = (f, op, kind)
        if (op in ("in", "not in") or kind == "source") and key in seen:
            for v in vals:
                if v not in rows[seen[key]]["values"]:
                    rows[seen[key]]["values"].append(v)
        else:
            seen[key] = len(rows)
            before = expr[:m.start()]
            orp = bool(re.search(r"(?:^|\s)OR\s*\(?\s*$", before, re.I))
            rows.append({"field": f, "op": op, "values": vals, "kind": kind, "or": orp})
    return rows

def sigma_logic(url):
    rel = url.split("/blob/master/", 1)[1]
    d = yaml.safe_load(open(os.path.join(SG, rel), encoding="utf-8"))
    det = d.get("detection", {}) or {}
    sels = []
    for name, body in det.items():
        if name in ("condition", "timeframe"):
            continue
        groups = []
        if isinstance(body, dict):
            groups.append(body)
        elif isinstance(body, list):
            if all(isinstance(x, dict) for x in body):
                groups.extend(body)
            else:
                groups.append({"(keywords)": body})
        else:
            groups.append({"(keywords)": [body]})
        out = []
        for g in groups:
            rows = []
            for field, vals in g.items():
                parts = str(field).split("|")
                vals = vals if isinstance(vals, list) else [vals]
                rows.append({"field": parts[0], "mods": parts[1:], "values": ["(null)" if v is None else str(v) for v in vals]})
            out.append(rows)
        sels.append({"name": name, "filter": name.lower().startswith("filter"), "groups": out})
    cond = det.get("condition", "")
    if isinstance(cond, list):
        cond = " | ".join(cond)
    raw = yaml.safe_dump({"logsource": d.get("logsource", {}), "detection": det}, sort_keys=False, allow_unicode=True, width=200)
    return {"selections": sels, "condition": str(cond), "raw": raw.strip()}

data = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
for r in data["rules"]:
    clause, expanded = splunk_filter(r["search"])
    dm = re.search(r"datamodel\s*=\s*([\w.]+)", r["search"])
    r["logic"] = {"clause": clause, "expanded": expanded, "conditions": splunk_conditions(expanded), "datamodel": dm.group(1) if dm else ""}
    for m in r["matches"]:
        m["logic"] = sigma_logic(m["url"])
json.dump(data, open(os.path.join(ROOT, "rules.json"), "w", encoding="utf-8"), indent=1)

for r in data["rules"][:3] + [x for x in data["rules"] if x["category"] != "endpoint"][:3]:
    print("==", r["name"]); print("  clause:", r["logic"]["expanded"][:300])
    for c in r["logic"]["conditions"]:
        print("   ", c)
    m = r["matches"][0]["logic"]; print("  sigma cond:", m["condition"])
    for s in m["selections"]:
        print("   ", s["name"], s["groups"])
print("no conditions:", [r["name"] for r in data["rules"] if not any(c["kind"] == "cond" for c in r["logic"]["conditions"])])
