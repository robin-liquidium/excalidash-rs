#!/usr/bin/env python3
"""Measure memory of a running stack: idle, under 2-user collab load, after.

  python3 -I measure.py BASE_URL CONTAINER[,CONTAINER...] [load_seconds]

Onboards a fresh instance (enable auth, register admin via the setup code in the
container log, create a drawing), then samples:
  - VmRSS / VmHWM of each container's main process (host /proc)
  - cgroup memory usage as reported by `docker stats`
"""
import json, re, subprocess, sys, threading, time, urllib.request, http.cookiejar

base = sys.argv[1]
containers = sys.argv[2].split(",")
load_secs = float(sys.argv[3]) if len(sys.argv) > 3 else 60
here = __file__.rsplit("/", 1)[0]
PASSWORD = "Str0ng!Passw0rd#1"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = {"t": None}


def req(method, path, body=None):
    h = {"Origin": base}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if csrf["t"]:
        h["x-csrf-token"] = csrf["t"]
    r = opener.open(urllib.request.Request(base + path, data=data, method=method, headers=h), timeout=60)
    return json.loads(r.read() or b"null")


def refresh_csrf():
    csrf["t"] = req("GET", "/api/csrf-token")["token"]


def logs(c):
    p = subprocess.run(["docker", "logs", c], capture_output=True, text=True)
    return p.stdout + p.stderr


def pids_of(c):
    """Every process in the container (init, node, nginx master + workers)."""
    out = subprocess.check_output(["docker", "top", c, "-eo", "pid"], text=True).split()[1:]
    return [int(p) for p in out if p.isdigit()]


def proc_mem(pids):
    out = {"VmRSS": 0, "VmHWM": 0}
    for pid in pids:
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith(("VmRSS", "VmHWM")):
                        k, v = line.split(":")
                        out[k] += int(v.strip().split()[0])  # kB
        except FileNotFoundError:
            pass
    return out


def cgroup_mib(c):
    s = subprocess.check_output(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", c], text=True).strip()
    v = s.split("/")[0].strip()
    num = float(re.match(r"[\d.]+", v).group())
    unit = v[len(re.match(r"[\d.]+", v).group()):].strip()
    return round(num * {"B": 1 / 1048576, "KiB": 1 / 1024, "MiB": 1, "GiB": 1024}.get(unit, 1), 2)


def snapshot(label):
    total_rss = 0
    detail = {}
    for c in containers:
        m = proc_mem(pids_of(c))
        total_rss += m["VmRSS"]
        detail[c] = {"rss_mib": round(m["VmRSS"] / 1024, 2), "hwm_mib": round(m["VmHWM"] / 1024, 2), "cgroup_mib": cgroup_mib(c)}
    print(f"[{label}] total RSS {total_rss / 1024:.1f} MiB  {json.dumps(detail)}")
    return {"label": label, "total_rss_mib": round(total_rss / 1024, 2), "containers": detail}


# --- onboard -------------------------------------------------------------------
refresh_csrf()
status = req("GET", "/api/auth/status")
if not status.get("authEnabled"):
    req("POST", "/api/auth/onboarding-choice", {"enableAuth": True})
code = None
for _ in range(50):
    found = [m for c in containers for m in re.findall(r"\[BOOTSTRAP SETUP\][^:]*\): (\S+)", logs(c))]
    if found:
        code = found[-1]
        break
    time.sleep(0.2)
try:
    req("POST", "/api/auth/register", {"email": "load@example.test", "password": PASSWORD, "name": "Load Test", "setupCode": code})
except Exception:
    refresh_csrf()
    req("POST", "/api/auth/login", {"email": "load@example.test", "password": PASSWORD})
refresh_csrf()
drawing = req("POST", "/api/drawings", {"name": "load", "elements": [], "appState": {"viewBackgroundColor": "#ffffff"}})
token = next(c.value for c in jar if c.name == "excalidash-access-token")

results = {"base": base, "containers": containers}
time.sleep(20)
results["idle"] = snapshot("idle")

peak = {"v": 0, "snap": None}
done = threading.Event()


def sampler():
    while not done.is_set():
        s = sum(proc_mem(pids_of(c))["VmRSS"] for c in containers) / 1024
        if s > peak["v"]:
            peak["v"] = s
        time.sleep(0.5)


threading.Thread(target=sampler, daemon=True).start()
load = subprocess.run([sys.executable, "-I", f"{here}/collab_load.py", base, token, drawing["id"], str(load_secs)],
                      capture_output=True, text=True)
done.set()
results["load_stats"] = load.stdout.strip() or load.stderr.strip()[-500:]
results["during_load_peak_rss_mib"] = round(peak["v"], 2)
results["after_load"] = snapshot("after load")
time.sleep(30)
results["settled"] = snapshot("settled 30s after load")
print(f"peak RSS during load: {peak['v']:.1f} MiB; load stats: {results['load_stats']}")
print(json.dumps(results))
