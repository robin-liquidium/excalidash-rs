#!/usr/bin/env python3
"""Two simulated collaborators editing one drawing over Socket.IO (Engine.IO v4
long-polling, stdlib only) plus periodic REST saves.

  python3 -I collab_load.py BASE_URL ACCESS_TOKEN DRAWING_ID [seconds]

BASE_URL is the public origin (e.g. http://127.0.0.1:16802); the API is under /api.
"""
import json, sys, threading, time, urllib.request

base, token, drawing_id = sys.argv[1], sys.argv[2], sys.argv[3]
duration = float(sys.argv[4]) if len(sys.argv) > 4 else 60.0
stop = time.time() + duration
stats = {"sent": 0, "received": 0, "saves": 0, "errors": 0}
lock = threading.Lock()


csrf_cookie = {"v": ""}


def http(method, url, data=None, headers=None):
    cookie = f"excalidash-access-token={token}"
    if csrf_cookie["v"]:
        cookie += "; " + csrf_cookie["v"]
    h = {"Cookie": cookie, "Origin": base}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    with urllib.request.urlopen(req, timeout=30) as r:
        for k, v in r.getheaders():
            if k.lower() == "set-cookie" and v.startswith("excalidash-csrf-client="):
                csrf_cookie["v"] = v.split(";")[0]
        return r.read().decode("utf-8", "replace")


class Client:
    def __init__(self, name):
        self.name = name
        hs = http("GET", f"{base}/socket.io/?EIO=4&transport=polling")
        self.sid = json.loads(hs[1:])["sid"]
        self.url = f"{base}/socket.io/?EIO=4&transport=polling&sid={self.sid}"
        self.send("40" + json.dumps({"token": token}))

    def send(self, packet):
        http("POST", self.url, packet.encode(), {"Content-Type": "text/plain;charset=UTF-8"})
        with lock:
            stats["sent"] += 1

    def emit(self, event, payload):
        self.send("42" + json.dumps([event, payload]))

    def poll_loop(self):
        while time.time() < stop:
            try:
                body = http("GET", self.url)
                for pkt in body.split("\x1e"):
                    if pkt == "2":
                        self.send("3")
                    elif pkt.startswith("42"):
                        with lock:
                            stats["received"] += 1
            except Exception:
                with lock:
                    stats["errors"] += 1
                time.sleep(0.5)


def element(i, who):
    return {"id": f"{who}-el-{i % 50}", "type": "rectangle", "x": i, "y": i * 2, "width": 40, "height": 30,
            "version": i + 1, "versionNonce": i * 7, "isDeleted": False, "strokeColor": "#1e1e1e"}


def editor(c):
    threading.Thread(target=c.poll_loop, daemon=True).start()
    c.emit("join-room", {"drawingId": drawing_id, "user": {"id": c.name, "name": c.name, "color": "#ff0000"}})
    i = 0
    while time.time() < stop:
        i += 1
        try:
            c.emit("cursor-move", {"drawingId": drawing_id, "pointer": {"x": i % 800, "y": i % 600}, "button": "up"})
            if i % 3 == 0:
                c.emit("element-update", {"drawingId": drawing_id, "elements": [element(i, c.name)]})
        except Exception:
            with lock:
                stats["errors"] += 1
        time.sleep(0.05)


def saver():
    version = None
    while time.time() < stop:
        try:
            d = json.loads(http("GET", f"{base}/api/drawings/{drawing_id}"))
            version = d.get("version")
            csrf = json.loads(http("GET", f"{base}/api/csrf-token"))["token"]
            body = {"elements": [element(j, "saver") for j in range(200)], "appState": {"viewBackgroundColor": "#ffffff"},
                    "version": version}
            http("PUT", f"{base}/api/drawings/{drawing_id}", json.dumps(body).encode(),
                 {"Content-Type": "application/json", "x-csrf-token": csrf})
            with lock:
                stats["saves"] += 1
        except Exception:
            with lock:
                stats["errors"] += 1
        time.sleep(2)


threads = [threading.Thread(target=editor, args=(Client(n),)) for n in ("alice", "bob")]
threads.append(threading.Thread(target=saver))
for t in threads:
    t.start()
for t in threads:
    t.join()
print(json.dumps(stats))
