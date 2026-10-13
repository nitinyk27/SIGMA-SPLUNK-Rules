"""Select 95 Splunk detections with the strongest Sigma overlap, map to MITRE, emit JSON."""
import json, math, os, re, sys
from collections import Counter, defaultdict
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
SC = os.path.join(ROOT, "security_content")
SG = os.path.join(ROOT, "sigma")
N_PICK = 95
PER_TECH_CAP = 3  # keep the list from collapsing onto a few techniques

# ---------- MITRE ----------
attack = json.load(open(os.path.join(ROOT, "attack.json"), encoding="utf-8"))
tech = {}
tactic_order = {}
for o in attack["objects"]:
    if o.get("revoked") or o.get("x_mitre_deprecated"):
        continue
    if o["type"] == "attack-pattern":
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ext:
            tech[ext["external_id"]] = {
                "name": o["name"],
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"],
                "url": ext["url"],
            }
for i, t in enumerate(["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                       "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
                       "collection", "command-and-control", "exfiltration", "impact"]):
    tactic_order[t] = i
for tid, t in tech.items():
    if "." in tid and tid.split(".")[0] in tech:
        t["parent"] = tech[tid.split(".")[0]]["name"]

# ---------- tokenising ----------
STOP = set("""the and for with from that this process processes parent name file path original_file_name dest user
count firsttime lasttime summariesonly tstats datamodel endpoint where true false null exe cmd.exe""".split())
STOP |= {"*", ""}

def norm_tokens(value):
    """Turn one indicator value into comparable tokens."""
    v = str(value).lower().replace("\\\\", "\\").strip().strip("'\"")
    out = set()
    core = v.strip("*").strip("\\/ ").strip()
    if 3 <= len(core) <= 80:
        out.add(core)
    for part in re.split(r"[\\/\s*=,;:\"'()|]+", v):
        part = part.strip(".-")
        if len(part) >= 4 and not part.isdigit():
            out.add(part)
    return {t for t in out if t not in STOP}

macros = {}
for f in os.listdir(os.path.join(SC, "macros")):
    try:
        m = yaml.safe_load(open(os.path.join(SC, "macros", f), encoding="utf-8"))
        macros[m["name"]] = m.get("definition", "")
    except Exception:
        pass

def spl_indicators(search):
    s = search
    # expand process_* style macros that hide the image name
    for mac in re.findall(r"`([a-z0-9_]+)(?:\([^`]*\))?`", s):
        if mac.startswith("process_") or mac.startswith("system_network") or mac in ("powershell",):
            s += " " + macros.get(mac, "")
    vals = re.findall(r'"([^"]{2,200})"', s)
    vals += re.findall(r"=\s*([A-Za-z0-9_.\-]+\.(?:exe|dll|ps1|vbs|js|bat|sys))", s)
    vals += re.findall(r"EventCode\s*=\s*(\d+)", s)
    vals += re.findall(r"[A-Za-z_][\w.]*\s*!?=\s*([^\s()\"`|,]{3,120})", s)
    toks = set()
    for v in vals:
        if v.lower().startswith(("security_content", "drop_dm")):
            continue
        toks |= norm_tokens(v)
    return toks

def sigma_values(det):
    vals = []
    def walk(x, key=None):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "condition":
                    continue
                walk(v, k)
        elif isinstance(x, list):
            for v in x:
                walk(v, key)
        elif x is not None:
            vals.append(str(x))
    walk(det)
    return vals

WORD = re.compile(r"[a-z0-9]{4,}")
TITLE_STOP = set("detects detect detection suspicious possible potential windows execution activity using usage process via with from".split())

def title_words(t):
    return {w for w in WORD.findall(t.lower()) if w not in TITLE_STOP}

# ---------- load Splunk ----------
splunk = []
for cat in ["endpoint", "cloud", "network", "web", "application"]:
    for dp, _, fs in os.walk(os.path.join(SC, "detections", cat)):
        for f in fs:
            if not f.endswith(".yml"):
                continue
            d = yaml.safe_load(open(os.path.join(dp, f), encoding="utf-8"))
            if d.get("status") == "deprecated":
                continue
            mids = d.get("tags", {}).get("mitre_attack_id") or d.get("mitre_attack_id") or []
            splunk.append({
                "id": d["id"], "name": d["name"], "type": d.get("type", ""), "status": d.get("status", ""), "category": cat,
                "description": " ".join(d.get("description", "").split()),
                "search": d.get("search", "").strip(),
                "how_to_implement": " ".join(str(d.get("how_to_implement", "")).split()),
                "fp": " ".join(str(d.get("known_false_positives", "")).split()),
                "data_source": d.get("data_source") or [],
                "stories": d.get("analytic_story") or d.get("tags", {}).get("analytic_story") or [],
                "mitre": mids,
                "slug": f[:-4],
                "_tok": spl_indicators(d.get("search", "")),
                "_tw": title_words(d["name"]),
            })

# ---------- load Sigma ----------
sigma = []
for top in ["rules", "rules-emerging-threats", "rules-threat-hunting", "rules-dfir"]:
    base = os.path.join(SG, top)
    for dp, _, fs in os.walk(base):
        for f in fs:
            if not f.endswith(".yml"):
                continue
            p = os.path.join(dp, f)
            try:
                d = yaml.safe_load(open(p, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(d, dict) or d.get("status") in ("deprecated", "unsupported"):
                continue
            tags = d.get("tags") or []
            tids = sorted({t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)})
            toks = set()
            for v in sigma_values(d.get("detection", {})):
                toks |= norm_tokens(v)
            ls = d.get("logsource", {})
            sigma.append({
                "id": d.get("id"), "title": d.get("title", ""), "level": d.get("level", ""),
                "status": d.get("status", ""), "description": " ".join(str(d.get("description", "")).split()),
                "logsource": "/".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)),
                "mitre": tids,
                "url": "https://github.com/SigmaHQ/sigma/blob/master/" + os.path.relpath(p, SG).replace("\\", "/"),
                "_tok": toks, "_tw": title_words(d.get("title", "")),
            })

# IDF over the sigma corpus so generic tokens (powershell.exe, cmd) weigh less
df = Counter(t for s in sigma for t in s["_tok"])
NS = len(sigma)
idf = lambda t: math.log((NS + 1) / (df.get(t, 0) + 1)) + 1

by_tech = defaultdict(list)
for i, s in enumerate(sigma):
    for t in s["mitre"]:
        by_tech[t].append(i)
        by_tech[t.split(".")[0]].append(i)

def score(sp, sg):
    shared = sp["_tok"] & sg["_tok"]
    if not shared:
        return 0, [], ""
    w_shared = sum(idf(t) for t in shared)
    w_sp = sum(idf(t) for t in sp["_tok"]) or 1
    w_sg = sum(idf(t) for t in sg["_tok"]) or 1
    # half cosine, half "how much of the Splunk logic does the Sigma rule also look for"
    tok = 0.5 * w_shared / math.sqrt(w_sp * w_sg) + 0.5 * w_shared / w_sp
    # a match resting only on very common tokens (rundll32.exe, powershell) is weak
    if min(df.get(t, 0) for t in shared) > 40:
        tok *= 0.55
    # both rules key on binaries, but not the same ones: likely a different behaviour
    ex_sp = {t for t in sp["_tok"] if t.endswith(".exe")}
    ex_sg = {t for t in sg["_tok"] if t.endswith(".exe")}
    if ex_sp and ex_sg and not (ex_sp & ex_sg):
        tok *= 0.5
    tw = len(sp["_tw"] & sg["_tw"]) / max(1, len(sp["_tw"] | sg["_tw"]))
    exact = set(sp["mitre"]) & set(sg["mitre"])
    parent = {m.split(".")[0] for m in sp["mitre"]} & {m.split(".")[0] for m in sg["mitre"]}
    tb = 0.25 if exact else (0.12 if parent else 0)
    s = 0.6 * tok + 0.25 * tw + tb
    kind = "exact technique" if exact else ("same parent technique" if parent else "indicator overlap only")
    return s, sorted(shared, key=lambda t: -idf(t))[:8], kind

for sp in splunk:
    cands = set()
    for m in sp["mitre"]:
        cands.update(by_tech.get(m, []))
        cands.update(by_tech.get(m.split(".")[0], []))
    # also allow strong indicator matches outside the technique
    rare = [t for t in sp["_tok"] if df.get(t, 0) and df[t] <= 15]
    for i, s in enumerate(sigma):
        if s["_tok"] & set(rare):
            cands.add(i)
    res = []
    for i in cands:
        sc, shared, kind = score(sp, sigma[i])
        # at least one shared indicator must be specific (a file name, a long string)
        if sc > 0.18 and any(len(t) >= 6 or "." in t for t in shared):
            res.append((sc, i, shared, kind))
    res.sort(reverse=True)
    sp["matches"] = [{"score": round(sc, 3), "shared": sh, "kind": k, **{kk: vv for kk, vv in sigma[i].items() if not kk.startswith("_")}}
                     for sc, i, sh, k in res[:3]]
    # rank on the best match plus a small bonus for corroborating rules
    top = [m["score"] for m in sp["matches"]]
    sp["rank"] = (top[0] + 0.15 * sum(top[1:3])) if top else 0

# ---------- pick 95 with per-technique cap ----------
# every detection: matched ones by match strength, then the rest by name
picked = sorted(splunk, key=lambda s: (-s["rank"], s["name"].lower()))

out = []
for n, s in enumerate(picked, 1):
    mitre = []
    for m in s["mitre"]:
        t = tech.get(m, {})
        mitre.append({"id": m, "name": t.get("name", "?"), "parent": t.get("parent"),
                      "tactics": t.get("tactics", []), "url": t.get("url", f"https://attack.mitre.org/techniques/{m.replace('.', '/')}/")})
    out.append({
        "n": n, **{k: v for k, v in s.items() if not k.startswith("_") and k not in ("rank",)},
        "rank": round(s["rank"], 3), "mitre": mitre,
        "coverage": "None",
        "url": f"https://research.splunk.com/{s['category']}/{s['id']}/",
    })

json.dump({"generated": "2026-09-29", "splunk_total": len(splunk), "sigma_total": NS, "rules": out},
          open(os.path.join(ROOT, "rules.json"), "w", encoding="utf-8"), indent=1)
print("splunk candidates", len(splunk), "sigma", NS, "picked", len(out))
print(Counter(t for r in out for m in r["mitre"] for t in m["tactics"]).most_common())
print(Counter(r["category"] for r in out))
for r in [x for x in out if x["matches"]][:5]:
    m = r["matches"][0]
    print(f'{r["n"]:>3} {r["rank"]:.2f} {r["name"][:60]:60} -> {m["title"][:55]} [{m["kind"]}] {m["shared"][:4]}')
