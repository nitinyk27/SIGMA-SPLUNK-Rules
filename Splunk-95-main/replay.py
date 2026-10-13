"""Replay Splunk attack_data samples through each Splunk filter and its matched Sigma rules.

For every Splunk rule with Windows XML sample logs, count the events its filter matches and how many
of those the Sigma rule also matches. That answers "does the Sigma rule catch what Splunk catches".
"""
import html, json, ntpath, os, re, warnings
from collections import defaultdict
from sigma.rule import SigmaRule
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.types import SigmaString, SigmaRegularExpression, SigmaNull, SigmaNumber, SigmaExists, SigmaCompareExpression, SigmaCIDRExpression, SigmaFieldReference, SigmaBool

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.abspath(__file__))
SG = os.path.join(ROOT, "sigma")
ADIR = os.path.join(ROOT, "attack_data")
MAX_EVENTS = 60000

class Unsupported(Exception):
    pass

# ---------------- events ----------------
EV_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)
DATA_RE = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]\s*(?:/>|>(.*?)</Data>)", re.S)
SYS_RE = {k: re.compile(p, re.S) for k, p in {
    "EventID": r"<EventID[^>]*>(\d+)</EventID>", "Channel": r"<Channel>(.*?)</Channel>",
    "Computer": r"<Computer>(.*?)</Computer>", "Provider": r"<Provider Name=['\"]([^'\"]+)"}.items()}

def base(p):
    return ntpath.basename(p or "")

def cim_aliases(e):
    eid, ch = e.get("EventID", ""), e.get("Channel", "")
    sysmon = "Sysmon" in ch
    if ch == "Security" and eid == "4688":
        e.setdefault("Image", e.get("NewProcessName", ""))
        e.setdefault("ParentImage", e.get("ParentProcessName", ""))
        e.setdefault("CommandLine", e.get("CommandLine", ""))
    img = e.get("Image") or e.get("SourceImage") or ""
    if img:
        e.update(process_path=img, process_name=base(img), process_exec=base(img))
    if "CommandLine" in e:
        e["process"] = e["CommandLine"]
    if e.get("ParentImage"):
        e.update(parent_process_path=e["ParentImage"], parent_process_name=base(e["ParentImage"]), parent_process_exec=base(e["ParentImage"]))
    if "ParentCommandLine" in e:
        e["parent_process"] = e["ParentCommandLine"]
    if "OriginalFileName" in e:
        e["original_file_name"] = e["OriginalFileName"]
    if "User" in e:
        e["user"] = e["User"]
    if "TargetObject" in e:
        to = e["TargetObject"]
        e.update(registry_path=to, registry_key_name=to.rsplit("\\", 1)[0], registry_value_name=to.rsplit("\\", 1)[-1],
                 registry_value_data=e.get("Details", ""))
    if "TargetFilename" in e:
        e.update(file_path=e["TargetFilename"], file_name=base(e["TargetFilename"]))
    if "QueryName" in e:
        e["query"] = e["QueryName"]
    if sysmon and eid == "3":
        e.update(dest_ip=e.get("DestinationIp", ""), dest_port=e.get("DestinationPort", ""), src_ip=e.get("SourceIp", ""),
                 dest=e.get("DestinationHostname", "") or e.get("DestinationIp", ""))
    if "ImageLoaded" in e:
        e["loaded_file_path"] = e["ImageLoaded"]; e["loaded_file"] = base(e["ImageLoaded"])
    e.setdefault("dest", e.get("Computer", ""))
    return e

_parsed = {}
def load_events(path, source):
    key = (path, source)
    if key in _parsed:
        return _parsed[key]
    txt = open(path, encoding="utf-8", errors="replace").read()
    evs = []
    for m in EV_RE.finditer(txt):
        x = m.group(0)
        e = {}
        for k, rx in SYS_RE.items():
            mm = rx.search(x)
            if mm:
                e[k] = mm.group(1)
        for n, v in DATA_RE.findall(x):
            e[n] = html.unescape(v or "")
        e["EventCode"] = e.get("EventID", "")
        e["source"] = source
        e["sourcetype"] = "XmlWinEventLog"
        e["_raw"] = x
        evs.append(cim_aliases(e))
        if len(evs) >= MAX_EVENTS:
            break
    _parsed[key] = evs
    return evs

# ---------------- Sigma evaluation ----------------
CAT_EVENTS = {
    "process_creation": {("sysmon", "1"), ("Security", "4688")}, "network_connection": {("sysmon", "3")},
    "image_load": {("sysmon", "7")}, "create_remote_thread": {("sysmon", "8")}, "raw_access_thread": {("sysmon", "9")},
    "process_access": {("sysmon", "10")}, "file_event": {("sysmon", "11")}, "registry_add": {("sysmon", "12")},
    "registry_delete": {("sysmon", "12")}, "registry_set": {("sysmon", "13")}, "registry_rename": {("sysmon", "14")},
    "registry_event": {("sysmon", "12"), ("sysmon", "13"), ("sysmon", "14")}, "create_stream_hash": {("sysmon", "15")},
    "pipe_created": {("sysmon", "17"), ("sysmon", "18")}, "wmi_event": {("sysmon", "19"), ("sysmon", "20"), ("sysmon", "21")},
    "dns_query": {("sysmon", "22")}, "file_delete": {("sysmon", "23"), ("sysmon", "26")}, "process_tampering": {("sysmon", "25")},
    "driver_load": {("sysmon", "6")}, "ps_script": {("powershell", "4104")}, "ps_module": {("powershell", "4103")},
}
SERVICE_CH = {"security": "Security", "system": "System", "sysmon": "Microsoft-Windows-Sysmon/Operational",
              "powershell": "Microsoft-Windows-PowerShell/Operational", "application": "Application",
              "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational", "wmi": "Microsoft-Windows-WMI-Activity/Operational",
              "bits-client": "Microsoft-Windows-Bits-Client/Operational", "windefend": "Microsoft-Windows-Windows Defender/Operational",
              "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer/Operational"}

def ev_kind(e):
    ch = e.get("Channel", "")
    if "Sysmon" in ch:
        return "sysmon"
    if "PowerShell" in ch:
        return "powershell"
    return ch

def sigma_scope(ls):
    cat, svc, prod = ls.category, ls.service, ls.product
    if prod and prod != "windows":
        raise Unsupported(f"logsource {prod} is not replayable from Windows event logs")
    if cat:
        if cat not in CAT_EVENTS:
            raise Unsupported(f"logsource category {cat}")
        allowed = CAT_EVENTS[cat]
        return lambda e: (ev_kind(e), e.get("EventID")) in allowed
    if svc:
        ch = SERVICE_CH.get(svc)
        if not ch:
            raise Unsupported(f"logsource service {svc}")
        return lambda e: e.get("Channel", "").lower() == ch.lower()
    return lambda e: True

_rx_cache = {}
def sval_match(val, fv):
    if type(val).__name__ == "SigmaExpansion":
        return any(sval_match(v, fv) for v in val.values)
    if isinstance(val, SigmaString):
        key = id(val)
        rx = _rx_cache.get(key)
        if rx is None:
            if val.contains_special():
                pat = ""
                for part in val.s:
                    if isinstance(part, str):
                        pat += re.escape(part)
                    elif part.name == "WILDCARD_MULTI":
                        pat += ".*"
                    elif part.name == "WILDCARD_SINGLE":
                        pat += "."
                    else:
                        raise Unsupported("placeholder value")
                rx = re.compile(pat, re.I | re.S)
            else:
                rx = str(val).lower()
            _rx_cache[key] = rx
        if isinstance(rx, str):
            return fv.lower() == rx
        return rx.fullmatch(fv) is not None
    if isinstance(val, SigmaRegularExpression):
        key = id(val)
        if key not in _rx_cache:
            fl = 0
            for f in getattr(val, "flags", None) or []:
                fl |= {"IGNORECASE": re.I, "MULTILINE": re.M, "DOTALL": re.S}.get(getattr(f, "name", ""), 0)
            _rx_cache[key] = re.compile(str(val.regexp), fl)
        return _rx_cache[key].search(fv) is not None
    if isinstance(val, SigmaNumber):
        return fv.strip() == str(val.number)
    if isinstance(val, SigmaBool):
        return fv.lower() == str(val.boolean).lower()
    raise Unsupported(type(val).__name__)

def s_eval(node, e):
    if isinstance(node, ConditionAND):
        return all(s_eval(a, e) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(s_eval(a, e) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not s_eval(node.args[0], e)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        val, f = node.value, node.field
        fv = e.get(f)
        if isinstance(val, SigmaNull):
            return fv is None or fv == ""
        if isinstance(val, SigmaExists):
            return (fv is not None) == val.exists
        if fv is None:
            return False
        if isinstance(val, SigmaCompareExpression):
            try:
                n = float(fv); t = float(val.number.number)
            except ValueError:
                return False
            op = val.op.name
            return {"LT": n < t, "LTE": n <= t, "GT": n > t, "GTE": n >= t}[op]
        if isinstance(val, (SigmaCIDRExpression, SigmaFieldReference)):
            raise Unsupported(type(val).__name__)
        return sval_match(val, fv)
    if isinstance(node, ConditionValueExpression):  # keyword search on the raw event
        raw = e["_raw"]
        return sval_match(node.value, raw) if not isinstance(node.value, SigmaString) else \
            re.search(sval_to_search(node.value), raw, re.I | re.S) is not None
    raise Unsupported(type(node).__name__)

def sval_to_search(val):
    pat = ""
    for part in val.s:
        pat += re.escape(part) if isinstance(part, str) else (".*" if part.name == "WILDCARD_MULTI" else ".")
    return pat

_sigma_cache = {}
def sigma_matcher(url):
    if url in _sigma_cache:
        return _sigma_cache[url]
    try:
        rule = SigmaRule.from_yaml(open(os.path.join(SG, url.split("/blob/master/", 1)[1]), encoding="utf-8").read())
        if getattr(rule.detection, "timeframe", None) or "timeframe:" in open(os.path.join(SG, url.split("/blob/master/", 1)[1]), encoding="utf-8").read():
            raise Unsupported("time-window condition")
        scope = sigma_scope(rule.logsource)
        trees = [c.parse() for c in rule.detection.parsed_condition]
        res = (lambda e: scope(e) and any(s_eval(t, e) for t in trees)), None
    except Unsupported as x:
        res = None, str(x)
    except Exception as x:
        res = None, "parse error: " + str(x).splitlines()[0][:100]
    _sigma_cache[url] = res
    return res

# ---------------- Splunk filter evaluation ----------------
DM_EVENTS = {
    "Endpoint.Processes": {("sysmon", "1"), ("Security", "4688")},
    "Endpoint.Registry": {("sysmon", "12"), ("sysmon", "13"), ("sysmon", "14")},
    "Endpoint.Filesystem": {("sysmon", "11"), ("sysmon", "23"), ("sysmon", "26"), ("sysmon", "2")},
    "Network_Traffic": {("sysmon", "3")}, "Endpoint.Ports": {("sysmon", "3")},
    "Network_Resolution": {("sysmon", "22")},
}
TOK = re.compile(r'''\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<comma>,)|(?P<pipe>\|)|(?P<op>==|!=|<=|>=|=|<|>)|(?P<str>"(?:\\.|[^"\\])*")|(?P<mac>`[^`]*`)|(?P<word>[^\s()=!<>,"|`]+))''')

def tokenize(s):
    out, pos = [], 0
    s = s.strip()
    while pos < len(s):
        m = TOK.match(s, pos)
        if not m or m.end() == pos:
            raise Unsupported("tokenize")
        pos = m.end()
        k = m.lastgroup
        v = m.group(k)
        if k == "str":
            v = re.sub(r'\\(.)', r'\1', v[1:-1])
            out.append(("str", v))
        elif k == "word" and v.upper() in ("AND", "OR", "NOT", "IN"):
            out.append((v.upper(), v))
        else:
            out.append((k, v))
    return out

def wild(v):
    return re.compile("^" + ".*".join(re.escape(p) for p in v.split("*")) + "$", re.I | re.S)

FUNCS = {"like", "match", "isnull", "isnotnull", "len", "lower", "upper", "mvcount", "cidrmatch", "searchmatch", "in", "if", "case", "coalesce", "replace", "tonumber", "tostring", "substr", "mvindex", "split", "trim", "strptime", "relative_time", "now", "round"}

class SPL:
    """Tiny evaluator for the search / tstats WHERE / simple where filters used by detections."""
    def __init__(self, tokens, where=False):
        self.t, self.i, self.where = tokens, 0, where
        self.missing = set()
    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else (None, None)
    def take(self):
        tok = self.t[self.i]; self.i += 1; return tok
    def parse(self):
        node = self.p_or()
        if self.i != len(self.t):
            raise Unsupported(f"trailing tokens near {self.peek()[1]}")
        return node
    def p_or(self):
        items = [self.p_and()]
        while self.peek()[0] == "OR":
            self.take(); items.append(self.p_and())
        return ("or", items) if len(items) > 1 else items[0]
    def p_and(self):
        items = [self.p_not()]
        while True:
            k = self.peek()[0]
            if k == "AND":
                self.take(); items.append(self.p_not())
            elif k in ("lp", "NOT", "word", "str", "mac"):
                items.append(self.p_not())
            else:
                break
        return ("and", items) if len(items) > 1 else items[0]
    def p_not(self):
        if self.peek()[0] == "NOT":
            self.take(); return ("not", self.p_not())
        return self.p_atom()
    def p_atom(self):
        k, v = self.peek()
        if k == "lp":
            self.take(); n = self.p_or()
            if self.peek()[0] != "rp":
                raise Unsupported("unbalanced parens")
            self.take(); return n
        if k == "mac":
            self.take(); return ("true",)
        if k in ("word", "str"):
            self.take()
            nk = self.peek()[0]
            if k == "word" and v.lower() in FUNCS and nk == "lp":
                raise Unsupported(f"function {v}()")
            if nk == "op":
                op = self.take()[1]
                vk, vv = self.take()
                if vk not in ("word", "str"):
                    raise Unsupported("comparison value")
                return ("cmp", v.strip('"'), op, vv, vk == "str")
            if nk == "IN":
                self.take()
                if self.take()[0] != "lp":
                    raise Unsupported("IN list")
                vals = []
                while self.peek()[0] not in ("rp", None):
                    tk, tv = self.take()
                    if tk in ("word", "str"):
                        vals.append(tv)
                if self.peek()[0] != "rp":
                    raise Unsupported("IN list end")
                self.take()
                return ("in", v, vals)
            return ("term", v)
        raise Unsupported(f"unexpected {v}")

def fieldname(f):
    f = f.strip('"')
    return re.sub(r"^(Processes|Filesystem|Registry|All_Traffic|Ports|DNS|Web|Network_Traffic|Endpoint)\.", "", f)

def spl_eval(n, e, st):
    t = n[0]
    if t == "and":
        return all(spl_eval(x, e, st) for x in n[1])
    if t == "or":
        return any(spl_eval(x, e, st) for x in n[1])
    if t == "not":
        return not spl_eval(n[1], e, st)
    if t == "true":
        return True
    if t == "term":
        v = n[1]
        if v.lower() in ("index", "earliest", "latest"):
            return True
        return wild("*" + v.strip("*") + "*").match(e["_raw"]) is not None
    if t == "cmp":
        _, f, op, v, quoted = n
        fn = fieldname(f)
        if fn.lower() in ("index", "eventtype", "earliest", "latest", "tag", "host") or fn.startswith("datamodel"):
            return True
        if fn not in e:
            if fn in ("source", "sourcetype"):
                return False
            st["missing"].add(fn)
            return op == "!=" and st.get("where") is False
        fv = e[fn]
        if op in ("<", ">", "<=", ">="):
            try:
                a, b = float(fv), float(v)
            except ValueError:
                return False
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        hit = wild(v).match(fv) is not None if "*" in v else fv.lower() == v.lower()
        return hit if op in ("=", "==") else not hit
    if t == "in":
        fn = fieldname(n[1])
        if fn not in e:
            st["missing"].add(fn); return False
        fv = e[fn]
        return any((wild(v).match(fv) is not None) if "*" in v else fv.lower() == v.lower() for v in n[2])
    raise Unsupported(t)

def splunk_matcher(r):
    expr = r["logic"]["expanded"]
    dm = r["logic"].get("datamodel", "")
    scope = None
    if dm:
        key = next((k for k in DM_EVENTS if dm.startswith(k)), None)
        if not key:
            raise Unsupported(f"data model {dm}")
        allowed = DM_EVENTS[key]
        scope = lambda e: (ev_kind(e), e.get("EventID")) in allowed
    segs = [x.strip() for x in re.split(r"\|", expr) if x.strip()]
    nodes, notes = [], []
    for i, sg in enumerate(segs):
        head = sg.split()[0].lower()
        if i == 0 and head not in ("where", "search"):
            body = sg[6:] if head == "tstats" else sg
            nodes.append(SPL(tokenize(body)).parse())
        elif head == "search":
            nodes.append(SPL(tokenize(sg[6:])).parse())
        elif head == "where":
            try:
                nodes.append(("where", SPL(tokenize(sg[5:]), where=True).parse()))
            except Unsupported as x:
                notes.append(f"where-clause not replayed ({x})")
        else:
            notes.append(f"'{head}' step not replayed")
    def fn(e, st):
        if scope and not scope(e):
            return False
        for n in nodes:
            if n[0] == "where":
                st["where"] = True
                ok = spl_eval(n[1], e, st)
                st["where"] = False
                if not ok:
                    return False
            elif not spl_eval(n, e, st):
                return False
        return True
    return fn, notes

def brief(e):
    for k in ("CommandLine", "TargetObject", "TargetFilename", "QueryName", "ScriptBlockText", "ImageLoaded", "TargetImage"):
        if e.get(k):
            return f"{k}: {e[k][:220]}"
    return f"EventID {e.get('EventID')} {e.get('Image', '')[:160]}"

# ---------------- run ----------------
data = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
tests = json.load(open(os.path.join(ROOT, "tests.json")))
index = json.load(open(os.path.join(ROOT, "attack_index.json"))) if os.path.exists(os.path.join(ROOT, "attack_index.json")) else {}
sizes = json.load(open(os.path.join(ROOT, "sizes.json")))

from collections import Counter
stat = Counter()
for n, r in enumerate(data["rules"]):
    if not r["matches"]:
        r.pop("test", None)
        continue
    ad = [a for a in tests.get(r["id"], []) if a.get("source", "").startswith("XmlWinEventLog")]
    other = [a for a in tests.get(r["id"], []) if not a.get("source", "").startswith("XmlWinEventLog")]
    T = {"datasets": len(ad), "events": 0, "splunk_hits": 0, "matches": {}, "notes": []}
    if not ad:
        T["status"] = "no_windows_data"
        T["notes"].append("Splunk's sample data for this rule is not Windows event XML" if other else "Splunk publishes no sample data for this rule")
        r["test"] = T; stat[T["status"]] += 1
        continue
    files = []
    for a in ad:
        u = a["data"]
        p = os.path.join(ADIR, index.get(u, "")) if u in index else None
        if p and os.path.exists(p):
            files.append((p, a.get("source", "")))
        elif sizes.get(u, 0) > 25e6:
            T["notes"].append("A sample file over 25 MB was skipped")
        else:
            T["notes"].append("A sample file could not be downloaded (blocked by antivirus or unavailable)")
    if not files:
        T["status"] = "no_data"
        r["test"] = T; stat[T["status"]] += 1
        continue
    events = [e for p, s in files for e in load_events(p, s)]
    T["events"] = len(events)
    try:
        sp, notes = splunk_matcher(r)
        T["notes"] += notes
        st = {"missing": set(), "where": False}
        hits = [e for e in events if sp(e, st)]
        if st["missing"]:
            T["notes"].append("Fields not present in replayed events: " + ", ".join(sorted(st["missing"]))[:200])
    except Unsupported as x:
        T["status"] = "splunk_unsupported"; T["notes"].append(f"Splunk filter could not be replayed ({x})")
        r["test"] = T; stat[T["status"]] += 1
        continue
    T["splunk_hits"] = len(hits)
    for m in r["matches"]:
        fn, err = sigma_matcher(m["url"])
        if fn is None:
            T["matches"][m["id"]] = {"verdict": "not_replayable", "note": err}
            continue
        try:
            both = [e for e in hits if fn(e)]
            total = sum(1 for e in events if fn(e))
        except Unsupported as x:
            T["matches"][m["id"]] = {"verdict": "not_replayable", "note": str(x)}
            continue
        missed = [e for e in hits if e not in both][:2]
        if not hits:
            verdict = "untested"
        else:
            pct = len(both) / len(hits)
            verdict = "covers" if pct >= 0.9 else "partial" if len(both) else "misses"
        T["matches"][m["id"]] = {"verdict": verdict, "both": len(both), "sigma_total": total,
                                  "pct": round(100 * len(both) / len(hits)) if hits else None,
                                  "missed_examples": [brief(e) for e in missed]}
    T["status"] = "tested" if hits else "splunk_no_hits"
    if not hits:
        T["notes"].append("The Splunk filter matched none of the replayed events (it may rely on aggregation, lookups or fields the replay cannot derive)")
    r["test"] = T
    stat[T["status"]] += 1
    if n % 200 == 0:
        print(n, dict(stat), flush=True)

json.dump(data, open(os.path.join(ROOT, "rules.json"), "w", encoding="utf-8"), indent=1)
print("status", dict(stat))
v = Counter()
for r in data["rules"]:
    t = r.get("test")
    if t and t["status"] == "tested":
        best = max((x for x in t["matches"].values() if x.get("pct") is not None), key=lambda x: x["pct"], default=None)
        v["best " + (best["verdict"] if best else "not_replayable")] += 1
print(dict(v))
