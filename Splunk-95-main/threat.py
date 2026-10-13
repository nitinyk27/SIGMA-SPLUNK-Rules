"""Add CVEs, threat-actor (ATT&CK group) links and the full ATT&CK matrix layout to data.json."""
import json, os, re
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = HERE
SC, SG = os.path.join(SRC, "security_content"), os.path.join(SRC, "sigma")
DATA = os.path.join(HERE, "data.json")

attack = json.load(open(os.path.join(SRC, "attack.json"), encoding="utf-8"))
objs = {o["id"]: o for o in attack["objects"]}
live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
ext = lambda o: next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})

# ---------- matrix: tactics in order, techniques (parents) with sub-techniques, sorted by name ----------
matrix_obj = next(o for o in attack["objects"] if o["type"] == "x-mitre-matrix" and live(o))
tactics = [objs[t] for t in matrix_obj["tactic_refs"]]
techs = {}
for o in attack["objects"]:
    if o["type"] == "attack-pattern" and live(o) and ext(o).get("external_id"):
        techs[ext(o)["external_id"]] = {"id": ext(o)["external_id"], "name": o["name"], "url": ext(o)["url"],
                                        "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"]}
mtx = []
for t in tactics:
    short = t["x_mitre_shortname"]
    parents = sorted((x for x in techs.values() if "." not in x["id"] and short in x["tactics"]), key=lambda x: x["name"].lower())
    col = []
    for p in parents:
        subs = sorted((x for x in techs.values() if x["id"].startswith(p["id"] + ".") and short in x["tactics"]), key=lambda x: x["name"].lower())
        col.append({"id": p["id"], "name": p["name"], "subs": [{"id": s["id"], "name": s["name"]} for s in subs]})
    mtx.append({"short": short, "name": t["name"], "techs": col})

# ---------- groups ----------
groups, alias_idx = [], []
uses = {}
for o in attack["objects"]:
    if o["type"] == "relationship" and o.get("relationship_type") == "uses" and live(o) \
            and o["source_ref"].startswith("intrusion-set") and o["target_ref"].startswith("attack-pattern"):
        tp = objs.get(o["target_ref"])
        if tp and live(tp) and ext(tp).get("external_id"):
            uses.setdefault(o["source_ref"], set()).add(ext(tp)["external_id"])
for o in attack["objects"]:
    if o["type"] == "intrusion-set" and live(o):
        e = ext(o)
        g = {"id": e["external_id"], "name": o["name"], "aliases": [a for a in (o.get("aliases") or []) if a != o["name"]],
             "url": e["url"], "techs": sorted(uses.get(o["id"], set())), "splunk": [], "sigma": []}
        groups.append(g)
        for a in [o["name"]] + (o.get("aliases") or []):
            if len(a) >= 4:
                alias_idx.append((re.compile(r"(?<![A-Za-z0-9])" + re.escape(a).replace(r"\ ", r"[\s\-_]*") + r"(?![A-Za-z0-9])", re.I), g))
gid = {g["id"]: g for g in groups}

# names that collide with unrelated malware families
NOT_ACTOR = re.compile(r"snake\s+keylogger", re.I)

def actors_in(text):
    text = NOT_ACTOR.sub(" ", text or "")
    return sorted({g["id"] for rx, g in alias_idx if rx.search(text)})

CVE_RX = re.compile(r"CVE[-_.](\d{4})[-_.](\d{4,7})", re.I)
def cves_in(text):
    return sorted({f"CVE-{a}-{b}" for a, b in CVE_RX.findall(text or "")})

# ---------- splunk metadata ----------
det = {}
for dp, _, fs in os.walk(os.path.join(SC, "detections")):
    for f in fs:
        if f.endswith(".yml"):
            d = yaml.safe_load(open(os.path.join(dp, f), encoding="utf-8"))
            det[d.get("id")] = d

data = json.load(open(DATA, encoding="utf-8"))
sig_cache = {}
def sigma_meta(url):
    if url not in sig_cache:
        rel = url.split("/blob/master/", 1)[1]
        d = yaml.safe_load(open(os.path.join(SG, rel), encoding="utf-8"))
        tags = d.get("tags") or []
        text = " ".join([rel, d.get("title", ""), d.get("description", "") or ""] + [str(x) for x in d.get("references") or []])
        g = {t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.g\d{4}$", t)}
        # emerging-threats folders name the actor, e.g. rules-emerging-threats/2023/TA/Lazarus/
        m = re.search(r"rules-emerging-threats/\d{4}/TA/([^/]+)/", rel)
        if m:
            g |= set(actors_in(m.group(1).replace("-", " ")))
        g |= set(actors_in(d.get("title", "")))
        sig_cache[url] = {"cves": sorted(set(cves_in(" ".join(tags) + " " + rel + " " + d.get("title", ""))) | set(cves_in(d.get("description", "") or ""))),
                          "actors": sorted(x for x in g if x in gid)}
    return sig_cache[url]

cve_map = {}
for r in data["rules"]:
    d = det.get(r["id"], {})
    stories = d.get("analytic_story") or (d.get("tags") or {}).get("analytic_story") or []
    r["stories"] = stories
    r["cves"] = sorted(set(d.get("cve") or (d.get("tags") or {}).get("cve") or []) | set(cves_in(r["name"])))
    r["actors"] = sorted(set(actors_in(" | ".join(stories))) | set(actors_in(r["name"])))
    for m in r["matches"]:
        sm = sigma_meta(m["url"])
        m["cves"], m["actors"] = sm["cves"], sm["actors"]
    for c in r["cves"]:
        cve_map.setdefault(c, {"id": c, "splunk": [], "sigma": {}})["splunk"].append(r["n"])
    for c in {c for m in r["matches"] for c in m["cves"]}:
        e = cve_map.setdefault(c, {"id": c, "splunk": [], "sigma": {}})
        for m in r["matches"]:
            if c in m["cves"]:
                e["sigma"][m["id"]] = m["title"]
    for a in r["actors"]:
        gid[a]["splunk"].append(r["n"])
    for m in r["matches"]:
        for a in m["actors"]:
            if m["id"] not in gid[a]["sigma"]:
                gid[a]["sigma"].append(m["id"])

data["matrix"] = mtx
data["groups"] = sorted(groups, key=lambda g: g["name"].lower())
data["cves"] = sorted(({"id": c["id"], "splunk": c["splunk"], "sigma": [{"id": k, "title": v} for k, v in c["sigma"].items()]} for c in cve_map.values()),
                      key=lambda c: c["id"], reverse=True)
json.dump(data, open(DATA, "w", encoding="utf-8"), separators=(",", ":"), ensure_ascii=False)

print("tactics", len(mtx), "parent cells", sum(len(t["techs"]) for t in mtx))
print("groups", len(groups), "with splunk rules", sum(1 for g in groups if g["splunk"]), "with sigma", sum(1 for g in groups if g["sigma"]))
print("cves", len(cve_map), "splunk rules with cve", sum(1 for r in data["rules"] if r["cves"]), "with actors", sum(1 for r in data["rules"] if r["actors"]))
print([ (g["name"], len(g["splunk"])) for g in sorted(groups, key=lambda g: -len(g["splunk"]))[:10]])
