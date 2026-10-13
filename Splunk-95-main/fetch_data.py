"""Download Splunk attack_data samples (Windows XML event logs, <= 25 MB) used by matched rules."""
import hashlib, json, os, urllib.request, concurrent.futures as cf
ROOT = os.path.dirname(os.path.abspath(__file__))
DST = os.path.join(ROOT, "attack_data")
os.makedirs(DST, exist_ok=True)
sizes = json.load(open(os.path.join(ROOT, "sizes.json")))
todo = [u for u, s in sizes.items() if 0 <= s <= 25e6]

def name(u):
    return hashlib.sha1(u.encode()).hexdigest()[:16] + ".log"

def get(u):
    p = os.path.join(DST, name(u))
    if os.path.exists(p) and os.path.getsize(p) == sizes[u]:
        return u, "cached"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(u, timeout=120) as r, open(p + ".part", "wb") as f:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
            os.replace(p + ".part", p)
            return u, "ok"
        except Exception as e:
            err = str(e)
    return u, "fail " + err

done = 0
with cf.ThreadPoolExecutor(8) as ex:
    for u, st in ex.map(get, todo):
        done += 1
        if done % 50 == 0 or st.startswith("fail"):
            print(done, len(todo), st, flush=True)
json.dump({u: name(u) for u in todo}, open(os.path.join(ROOT, "attack_index.json"), "w"))
print("finished", done)
