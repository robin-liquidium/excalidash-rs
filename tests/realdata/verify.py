#!/usr/bin/env python3
"""Helper for tests/realdata/run.sh. Mints access tokens with $JWT_SECRET (never printed).

  verify.py read     DB NODE_API RUST_API   compare every read endpoint for every active user
  verify.py write    DB RUST_API            create/update/snapshot data through Rust
  verify.py readback DB NODE_API            upstream Node reads what Rust wrote
"""
import base64, hashlib, hmac, json, os, sqlite3, sys, time, urllib.error, urllib.request, uuid

mode, db_path = sys.argv[1], sys.argv[2]
STATE = "/tmp/exrs-realdata-state.json"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(user_id, email):
    now = int(time.time())
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"userId": user_id, "email": email, "authProvider": "local", "type": "access",
                              "iat": now, "exp": now + 900, "jti": str(uuid.uuid4())}).encode())
    sig = hmac.new(os.environ["JWT_SECRET"].encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(sig)}"


def call(api, path, token, method="GET", body=None, csrf=None, cookie_extra=""):
    h = {"Cookie": f"excalidash-access-token={token}{cookie_extra}", "X-Forwarded-Proto": "https",
         "Origin": "https://excali.robin.build"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if csrf:
        h["x-csrf-token"] = csrf
    req = urllib.request.Request(api + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(), dict(r.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def csrf_for(api, token):
    st, body, headers = call(api, "/csrf-token", token)
    cookie = headers.get("Set-Cookie", headers.get("set-cookie", "")).split(";")[0]
    return json.loads(body)["token"], f"; {cookie}" if cookie else ""


def users():
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    return c.execute('SELECT id, email FROM "User" WHERE "isActive" = 1').fetchall()


def norm(v):
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items() if k not in ("token",)}
    if isinstance(v, list):
        return [norm(x) for x in v]
    return v


def collect(api, uid, email):
    t = mint(uid, email)
    out = {}
    def get(path, as_json=True):
        st, body, h = call(api, path, t)
        if as_json:
            try:
                out[path] = (st, norm(json.loads(body)))
            except Exception:
                out[path] = (st, body[:200].decode("latin1"))
        else:
            out[path] = (st, hashlib.sha256(body).hexdigest(), len(body))
        return st, body
    for p in ("/auth/me", "/auth/status", "/auth/preferences", "/auth/api-keys", "/collections", "/library",
              "/drawings", "/drawings/shared", "/drawings?includeData=true"):
        get(p)
    st, body = call(api, "/drawings?includeData=true", t)[:2]
    drawings = (json.loads(body).get("drawings") if isinstance(json.loads(body), dict) else json.loads(body)) or []
    for d in drawings:
        did = d["id"]
        st, b = get(f"/drawings/{did}")
        get(f"/drawings/{did}/preview", as_json=False)
        get(f"/drawings/{did}/sharing")
        st, hb = get(f"/drawings/{did}/history")
        try:
            hist = json.loads(hb)
            snaps = hist.get("snapshots", hist) if isinstance(hist, dict) else hist
            for s in snaps or []:
                get(f"/drawings/{did}/history/{s['id']}")
        except Exception:
            pass
        try:
            files = json.loads(b).get("files") or {}
            if isinstance(files, str):
                files = json.loads(files)
            for fid, f in files.items():
                ref = f.get("dataURL", "")
                if ref.startswith("/api/files/"):
                    get(ref[len("/api"):], as_json=False)
        except Exception:
            pass
    return out, len(drawings)


if mode == "read":
    node_api, rust_api = sys.argv[3], sys.argv[4]
    total, bad = 0, 0
    for uid, email in users():
        a, n = collect(node_api, uid, email)
        b, _ = collect(rust_api, uid, email)
        for path in sorted(a.keys() | b.keys()):
            total += 1
            if a.get(path) != b.get(path):
                bad += 1
                print(f"DIFF user={uid[:8]} {path}\n  node={str(a.get(path))[:400]}\n  rust={str(b.get(path))[:400]}")
        print(f"user {uid[:8]}…: {n} drawings, {len(a)} endpoints compared")
    print(f"real-data read parity: {total - bad}/{total} identical")
    sys.exit(1 if bad else 0)

if mode == "write":
    api = sys.argv[3]
    uid, email = users()[0]
    t = mint(uid, email)
    csrf, ck = csrf_for(api, t)
    st, body, _ = call(api, "/drawings", t, "POST", {"name": "rust-realdata-check", "elements": [], "appState": {"viewBackgroundColor": "#ffffff"}}, csrf, ck)
    assert st in (200, 201), (st, body[:300])
    d = json.loads(body)
    upd = {"name": "rust-realdata-check v2", "version": d.get("version", 1),
           "elements": [{"id": "r1", "type": "rectangle", "x": 1, "y": 2, "width": 3, "height": 4, "version": 1}],
           "appState": {"viewBackgroundColor": "#ffffff"}}
    st, body, _ = call(api, f"/drawings/{d['id']}", t, "PUT", upd, csrf, ck)
    assert st == 200, (st, body[:300])
    st, body, _ = call(api, "/auth/preferences", t, "PUT", {"theme": "dark"}, csrf, ck)
    print(f"rust write ok: drawing {d['id']} (status prefs {st})")
    json.dump({"drawing": d["id"], "user": uid, "email": email}, open(STATE, "w"))
    sys.exit(0)

if mode == "readback":
    api = sys.argv[3]
    s = json.load(open(STATE))
    t = mint(s["user"], s["email"])
    st, body, _ = call(api, f"/drawings/{s['drawing']}", t)
    d = json.loads(body)
    ok = st == 200 and d.get("name") == "rust-realdata-check v2" and len(d.get("elements") or []) == 1
    st2, hb, _ = call(api, f"/drawings/{s['drawing']}/history", t)
    st3, lb, _ = call(api, "/drawings", t)
    print(f"upstream Node reads Rust-written data: drawing={st} ok={ok} history={st2} list={st3}")
    os.remove(STATE)
    sys.exit(0 if ok and st2 == 200 and st3 == 200 else 1)
