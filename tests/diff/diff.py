#!/usr/bin/env python3
"""Differential tester: replay one API scenario against upstream Node (via its
nginx frontend) and the Rust image, then diff status codes, headers and JSON.

Usage: tests/diff/run.sh   (starts fresh stacks, runs this, tears down)
       python3 -I tests/diff/diff.py [--json report.json]

Each target keeps its own cookie jar, CSRF token and captured ids, so ids that
legitimately differ (uuids, tokens, timestamps) are normalised to placeholders.
"""
import base64, http.cookiejar, io, json, re, subprocess, sys, time, urllib.error, urllib.request, zipfile

TARGETS = {
    "node": {"base": "http://127.0.0.1:16801", "container": "exrs-diff-node-backend-1"},
    "rust": {"base": "http://127.0.0.1:16802", "container": "exrs-diff-rust-1"},
}
PASSWORD = "Str0ng!Passw0rd#1"
PNG_1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

# Headers whose values legitimately differ per run/implementation.
VOLATILE_HEADERS = {
    "date", "x-request-id", "etag", "content-length", "ratelimit-remaining", "ratelimit-reset",
    "keep-alive", "connection", "transfer-encoding", "last-modified", "expires",
    "retry-after", "content-disposition",
}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
JWT_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]+$")
HEX_RE = re.compile(r"^[0-9a-f]{32,128}$")
API_KEY_RE = re.compile(r"^exd_[\w-]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,}(\.[A-Za-z0-9_-]{20,})?$")


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None


class Target:
    def __init__(self, name, base, container):
        self.name, self.base, self.container = name, base, container
        self.vars = {}
        self.clients = {}

    def client(self, who):
        if who not in self.clients:
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
            self.clients[who] = {"opener": opener, "csrf": None, "bearer": None, "jar": jar}
        return self.clients[who]

    def request(self, who, method, path, body=None, raw=None, ctype=None, headers=None, origin=True, csrf=True):
        c = self.client(who)
        data, h = None, {}
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if raw is not None:
            data = raw
            h["Content-Type"] = ctype or "application/octet-stream"
        if origin:
            h["Origin"] = self.base
        if csrf and c["csrf"]:
            h["x-csrf-token"] = c["csrf"]
        if c["bearer"]:
            h["Authorization"] = "Bearer " + c["bearer"]
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with c["opener"].open(req, timeout=60) as r:
                return Resp(r.status, list(r.getheaders()), r.read())
        except urllib.error.HTTPError as e:
            return Resp(e.code, list(e.headers.items()), e.read())

    def csrf(self, who):
        r = self.request(who, "GET", "/api/csrf-token")
        self.client(who)["csrf"] = (r.json() or {}).get("token")
        return r

    def logs(self):
        return subprocess.run(["docker", "logs", self.container], capture_output=True, text=True).stdout + \
            subprocess.run(["docker", "logs", self.container], capture_output=True, text=True).stderr


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def normalize(value, t):
    """Replace run-specific values with stable placeholders."""
    rev = {}
    for k, v in t.vars.items():
        if isinstance(v, str) and len(v) >= 6:
            rev[v] = k
    def walk(v):
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            if v in rev:
                return f"<var:{rev[v]}>"
            for name, var in sorted(rev.items(), key=lambda kv: -len(kv[0])):
                if name in v:
                    v = v.replace(name, f"<var:{var}>")
            if UUID_RE.match(v):
                return "<uuid>"
            if ISO_RE.match(v):
                return "<date>"
            if JWT_RE.match(v):
                return "<jwt>"
            if API_KEY_RE.match(v):
                return "<apikey>"
            if HEX_RE.match(v):
                return "<hex>"
            if TOKEN_RE.match(v) and not v.isalpha():
                return "<token>"
            return v
        if isinstance(v, int) and not isinstance(v, bool) and v > 1_500_000_000_000:
            return "<ms>"
        return v
    return walk(value)


def cookie_shape(v):
    parts = [p.strip() for p in v.split(";")]
    name = parts[0].split("=", 1)[0]
    empty = parts[0].endswith("=")
    attrs = sorted(p.split("=", 1)[0].lower() + ("" if p.split("=", 1)[0].lower() in ("expires",) else ("=" + p.split("=", 1)[1] if "=" in p else "")) for p in parts[1:])
    return f"{name}{'(empty)' if empty else ''};" + ";".join(attrs)


IGNORED_HEADERS = set()  # Rust does not impersonate nginx's Server header (documented deviation)


def header_map(resp, base):
    m = {}
    for k, v in resp.headers:
        k = k.lower()
        if k in IGNORED_HEADERS:
            continue
        if resp.status == 204 and k == "content-length":
            continue  # RFC 9110 forbids Content-Length on 204; hyper omits it (documented deviation)
        if k == "access-control-allow-origin" and v == base:
            v = "<own-origin>"
        if k == "location":
            v = v.replace(base, "<own-origin>")
        if k in VOLATILE_HEADERS:
            m.setdefault(k, "<present>")
            continue
        if k == "set-cookie":
            v = cookie_shape(v)
        m.setdefault(k, [])
        if isinstance(m[k], list):
            m[k].append(v)
    return {k: (sorted(v) if isinstance(v, list) else v) for k, v in m.items()}


def diff_json(a, b, path="$", out=None, order_notes=None):
    out = [] if out is None else out
    if type(a) != type(b):
        out.append(f"{path}: type {type(a).__name__} != {type(b).__name__} ({short(a)} vs {short(b)})")
        return out
    if isinstance(a, dict):
        if list(a.keys()) != list(b.keys()) and set(a.keys()) == set(b.keys()) and order_notes is not None:
            order_notes.append(path)
        for k in a.keys() - b.keys():
            out.append(f"{path}.{k}: missing in rust ({short(a[k])})")
        for k in b.keys() - a.keys():
            out.append(f"{path}.{k}: extra in rust ({short(b[k])})")
        for k in a.keys() & b.keys():
            diff_json(a[k], b[k], f"{path}.{k}", out, order_notes)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(f"{path}: list len {len(a)} != {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diff_json(x, y, f"{path}[{i}]", out, order_notes)
    elif a != b:
        out.append(f"{path}: {short(a)} != {short(b)}")
    return out


def short(v):
    s = json.dumps(v) if not isinstance(v, str) else v
    return s if len(s) < 120 else s[:117] + "..."


class Runner:
    def __init__(self):
        self.t = {n: Target(n, c["base"], c["container"]) for n, c in TARGETS.items()}
        self.results = []

    def step(self, name, method, path, body=None, who="admin", save=None, raw=None, ctype=None,
             headers=None, origin=True, csrf=True, compare_body=True, ignore_paths=()):
        rs = {}
        for n, t in self.t.items():
            p = path(t.vars) if callable(path) else path
            b = body(t.vars) if callable(body) else body
            rw = raw(t.vars) if callable(raw) else raw
            rs[n] = t.request(who, method, p, body=b, raw=rw, ctype=ctype, headers=headers, origin=origin, csrf=csrf)
            if save:
                try:
                    save(t.vars, rs[n].json(), rs[n])
                except Exception as e:  # capture failures show up as diffs anyway
                    t.vars.setdefault("_save_errors", []).append(f"{name}: {e}")
        a, b = rs["node"], rs["rust"]
        problems, order = [], []
        if a.status != b.status:
            problems.append(f"status {a.status} != {b.status}")
        ha, hb = header_map(a, self.t['node'].base), header_map(b, self.t['rust'].base)
        for k in sorted(ha.keys() | hb.keys()):
            if k not in hb:
                problems.append(f"header missing in rust: {k}: {ha[k]}")
            elif k not in ha:
                problems.append(f"header extra in rust: {k}: {hb[k]}")
            elif ha[k] != hb[k]:
                problems.append(f"header {k}: {ha[k]} != {hb[k]}")
        if compare_body:
            ja, jb = a.json(), b.json()
            if ja is not None or jb is not None:
                na, nb = normalize(ja, self.t["node"]), normalize(jb, self.t["rust"])
                for ip in ignore_paths:
                    na, nb = drop_path(na, ip), drop_path(nb, ip)
                problems += diff_json(na, nb, order_notes=order)
            elif a.body != b.body and not (a.header("content-type") or "").startswith(("application/zip", "image/", "application/octet")):
                problems.append(f"body differs ({len(a.body)} vs {len(b.body)} bytes)")
        self.results.append({"step": name, "method": method, "status": [a.status, b.status], "problems": problems, "key_order": order})
        mark = "OK " if not problems else "DIFF"
        print(f"[{mark}] {name}: {method} {path if isinstance(path, str) else '(dynamic)'} -> {a.status}/{b.status}")
        for p in problems:
            print(f"        {p}")
        return rs

    def both(self, fn):
        for t in self.t.values():
            fn(t)


def drop_path(v, dotted):
    if v is None:
        return v
    parts = dotted.split(".")
    def rec(node, i):
        if isinstance(node, list):
            return [rec(x, i) for x in node]
        if not isinstance(node, dict):
            return node
        if i == len(parts) - 1:
            return {k: x for k, x in node.items() if k != parts[i]}
        return {k: (rec(x, i + 1) if k == parts[i] else x) for k, x in node.items()}
    return rec(v, 0)


def setup_code(t):
    deadline = time.time() + 10
    while time.time() < deadline:
        codes = re.findall(r"\[BOOTSTRAP SETUP\][^:]*\): (\S+)", t.logs())
        if codes:
            return codes[-1]
        time.sleep(0.3)
    raise RuntimeError(f"no setup code for {t.name}")


def scene(text="hello"):
    return {
        "elements": [{"id": "rect-1", "type": "rectangle", "x": 10, "y": 20, "width": 100, "height": 50, "angle": 0,
                      "strokeColor": "#1e1e1e", "backgroundColor": "transparent", "fillStyle": "solid", "strokeWidth": 2,
                      "strokeStyle": "solid", "roughness": 1, "opacity": 100, "groupIds": [], "frameId": None,
                      "roundness": {"type": 3}, "seed": 1, "version": 3, "versionNonce": 7, "isDeleted": False,
                      "boundElements": None, "updated": 1700000000000, "link": None, "locked": False},
                     {"id": "text-1", "type": "text", "x": 0, "y": 0, "width": 50, "height": 20, "text": text,
                      "fontSize": 20, "fontFamily": 5, "textAlign": "left", "verticalAlign": "top", "version": 1}],
        "appState": {"viewBackgroundColor": "#ffffff", "gridSize": None, "zoom": {"value": 1},
                     "activeTool": {"type": "selection", "locked": False}, "theme": "light"},
    }


def scenario(R):
    s = R.step
    s("health", "GET", "/api/health")
    s("status fresh", "GET", "/api/auth/status")
    s("gate before onboarding", "GET", "/api/drawings")
    s("csrf token", "GET", "/api/csrf-token", save=lambda v, j, r: None)
    R.both(lambda t: t.csrf("admin"))
    s("onboarding missing body", "POST", "/api/auth/onboarding-choice", body={})
    s("onboarding enable", "POST", "/api/auth/onboarding-choice", body={"enableAuth": True})
    s("status after onboarding", "GET", "/api/auth/status")
    R.both(lambda t: t.vars.__setitem__("code", setup_code(t)))
    s("register weak password", "POST", "/api/auth/register", body=lambda v: {"email": "admin@example.test", "password": "weak", "name": "Admin", "setupCode": v["code"]})
    s("register bad code", "POST", "/api/auth/register", body={"email": "admin@example.test", "password": PASSWORD, "name": "Admin", "setupCode": "WRONG-CODE"})
    R.both(lambda t: t.vars.__setitem__("code", setup_code(t)))
    s("register admin", "POST", "/api/auth/register", body=lambda v: {"email": "admin@example.test", "password": PASSWORD, "name": "Admin User", "setupCode": v["code"]},
      save=lambda v, j, r: v.__setitem__("admin_id", j["user"]["id"]))
    R.both(lambda t: t.csrf("admin"))
    time.sleep(5.5)  # upstream caches the onboarding gate for 5s; a real client reloads
    s("me", "GET", "/api/auth/me")
    s("status authed", "GET", "/api/auth/status")
    s("logout", "POST", "/api/auth/logout", body={})
    s("me after logout", "GET", "/api/auth/me")
    s("login wrong password", "POST", "/api/auth/login", body={"email": "admin@example.test", "password": "nope"})
    s("login", "POST", "/api/auth/login", body={"email": "admin@example.test", "password": PASSWORD})
    R.both(lambda t: t.csrf("admin"))
    s("refresh", "POST", "/api/auth/refresh", body={})
    R.both(lambda t: t.csrf("admin"))

    # admin
    s("admin create user", "POST", "/api/auth/users", body={"email": "bob@example.test", "password": PASSWORD, "name": "Bob", "role": "USER"},
      save=lambda v, j, r: v.__setitem__("bob_id", j["user"]["id"]))
    s("admin create invalid", "POST", "/api/auth/users", body={"email": "nope", "name": ""})
    s("admin list users", "GET", "/api/auth/users")
    s("rate limit get", "GET", "/api/auth/rate-limit/login")
    s("rate limit put", "PUT", "/api/auth/rate-limit/login", body={"enabled": True, "windowMs": 60000, "max": 50})
    s("registration toggle", "POST", "/api/auth/registration/toggle", body={"enabled": False})
    s("impersonation targets", "GET", "/api/auth/impersonation-targets")
    s("update user", "PATCH", lambda v: f"/api/auth/users/{v['bob_id']}", body={"name": "Bobby"})

    # account
    s("preferences get", "GET", "/api/auth/preferences")
    s("preferences put", "PUT", "/api/auth/preferences", body={"theme": "dark", "gridStep": 10})
    s("preferences put invalid", "PUT", "/api/auth/preferences", body={"theme": "neon"})
    s("profile put", "PUT", "/api/auth/profile", body={"name": "Admin Renamed"})
    s("password reset capability", "GET", "/api/auth/password-reset-capability")
    s("api key create", "POST", "/api/auth/api-keys", body={"name": "ci key"},
      save=lambda v, j, r: (v.__setitem__("api_key", j.get("token") or j.get("apiKey", {}).get("token") or j.get("key")),))
    s("api key list", "GET", "/api/auth/api-keys")

    # collections + drawings
    s("collections list empty", "GET", "/api/collections")
    s("collection create", "POST", "/api/collections", body={"name": "Work"}, save=lambda v, j, r: v.__setitem__("col_id", j["id"]))
    s("collection create invalid", "POST", "/api/collections", body={"name": ""})
    s("collection rename", "PUT", lambda v: f"/api/collections/{v['col_id']}", body={"name": "Work 2"})
    body = scene()
    body.update({"name": "First drawing", "files": {"img-1": {"id": "img-1", "mimeType": "image/png", "dataURL": f"data:image/png;base64,{PNG_1x1}", "created": 1700000000000}},
                 "preview": "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"1\" height=\"1\"/><script>alert(1)</script></svg>"})
    s("drawing create", "POST", "/api/drawings", body=lambda v: dict(body, collectionId=v["col_id"]), save=lambda v, j, r: v.__setitem__("d1", j["id"]))
    s("drawing create invalid", "POST", "/api/drawings", body={"elements": [{"x": "not-a-number"}], "appState": {}})
    s("drawing create bad image", "POST", "/api/drawings", body={"name": "x", "elements": [], "appState": {}, "files": {"f": {"dataURL": "data:text/html;base64,AAAA"}}})
    s("drawing get", "GET", lambda v: f"/api/drawings/{v['d1']}")
    s("drawing get unknown", "GET", "/api/drawings/does-not-exist")
    s("drawings list", "GET", "/api/drawings")
    s("drawings list full", "GET", "/api/drawings?includeData=true&sortField=name&sortDirection=asc")
    s("drawings search", "GET", "/api/drawings?search=First")
    s("drawings by collection", "GET", lambda v: f"/api/drawings?collectionId={v['col_id']}")
    s("drawing preview", "GET", lambda v: f"/api/drawings/{v['d1']}/preview")
    s("file get", "GET", lambda v: f"/api/files/{v['d1']}/img-1")
    s("files config", "GET", "/api/files/config")
    upd = scene("hello again")
    s("drawing update", "PUT", lambda v: f"/api/drawings/{v['d1']}", body=dict(upd, name="First drawing v2", version=1))
    s("drawing update conflict", "PUT", lambda v: f"/api/drawings/{v['d1']}", body=dict(upd, version=1))
    s("drawing history", "GET", lambda v: f"/api/drawings/{v['d1']}/history", save=lambda v, j, r: v.__setitem__("snap", (j.get("snapshots") or j)[0]["id"] if (j.get("snapshots") if isinstance(j, dict) else j) else None))
    s("drawing snapshot", "GET", lambda v: f"/api/drawings/{v['d1']}/history/{v.get('snap')}")
    s("drawing restore", "POST", lambda v: f"/api/drawings/{v['d1']}/history/{v.get('snap')}/restore", body={})
    s("drawing duplicate", "POST", lambda v: f"/api/drawings/{v['d1']}/duplicate", body={}, save=lambda v, j, r: v.__setitem__("d2", j["id"]))
    s("storage diff", "GET", lambda v: f"/api/drawings/{v['d1']}/files/diff")
    s("storage trim", "POST", lambda v: f"/api/drawings/{v['d1']}/trim", body={})
    s("orphans delete", "DELETE", lambda v: f"/api/drawings/{v['d1']}/files/orphans")
    s("upload file raw", "PUT", lambda v: f"/api/drawings/{v['d1']}/files/img-2", raw=base64.b64decode(PNG_1x1), ctype="image/png")

    # sharing
    s("sharing get", "GET", lambda v: f"/api/drawings/{v['d1']}/sharing")
    s("permission add", "POST", lambda v: f"/api/drawings/{v['d1']}/permissions", body=lambda v: {"granteeUserId": v["bob_id"], "permission": "view"},
      save=lambda v, j, r: v.__setitem__("perm_id", (j.get("permission") or j).get("id")))
    s("link share create", "POST", lambda v: f"/api/drawings/{v['d1']}/link-shares", body={"permission": "view"},
      save=lambda v, j, r: (v.__setitem__("share_id", (j.get("share") or j).get("id")), v.__setitem__("share_token", (j.get("share") or j).get("token") or j.get("token"))))
    s("share resolve", "GET", lambda v: f"/api/drawings/{v['d1']}/share-resolve", who="anon")
    s("collection shares", "GET", lambda v: f"/api/collections/{v['col_id']}/shares")
    s("collection share add", "POST", lambda v: f"/api/collections/{v['col_id']}/shares", body={"identifier": "bob@example.test", "role": "edit"})

    # second user
    R.both(lambda t: t.csrf("bob"))
    s("bob login", "POST", "/api/auth/login", who="bob", body={"email": "bob@example.test", "password": PASSWORD})
    R.both(lambda t: t.csrf("bob"))
    s("bob shared drawings", "GET", "/api/drawings/shared", who="bob")
    s("bob read shared", "GET", lambda v: f"/api/drawings/{v['d1']}", who="bob")
    s("bob update viewer-only", "PUT", lambda v: f"/api/drawings/{v['d1']}", who="bob", body=dict(scene("bob"), version=99))
    s("bob delete forbidden", "DELETE", lambda v: f"/api/drawings/{v['d1']}", who="bob")
    s("bob hide shared", "PATCH", lambda v: f"/api/drawings/{v['d1']}/shared-visibility", who="bob", body={"hidden": True})
    s("bob preferences", "GET", "/api/auth/preferences", who="bob")
    s("bob admin forbidden", "GET", "/api/auth/users", who="bob")
    s("anon drawing read", "GET", lambda v: f"/api/drawings/{v['d1']}", who="anon")
    s("anon drawings list", "GET", "/api/drawings", who="anon")

    s("permission delete", "DELETE", lambda v: f"/api/drawings/{v['d1']}/permissions/{v.get('perm_id')}")
    s("link share delete", "DELETE", lambda v: f"/api/drawings/{v['d1']}/link-shares/{v.get('share_id')}")

    # library
    s("library get", "GET", "/api/library")
    s("library put", "PUT", "/api/library", body={"items": [{"id": "lib-1", "status": "published", "elements": []}]})
    s("library get after", "GET", "/api/library")

    # api key auth (non-browser bearer, no origin/csrf)
    def apikey_client(t):
        c = t.client("apikey")
        c["bearer"] = t.vars.get("api_key")
    R.both(apikey_client)
    s("api key list drawings", "GET", "/api/drawings", who="apikey", origin=False, csrf=False)
    s("api key create drawing", "POST", "/api/drawings", who="apikey", origin=False, csrf=False, body=dict(scene(), name="via api"))
    s("api key forbidden route", "GET", "/api/auth/users", who="apikey", origin=False, csrf=False)

    # export / import
    rs = s("export", "GET", "/api/export/excalidash", compare_body=False)
    for n, t in R.t.items():
        t.vars["_export"] = rs[n].body
    try:
        a = zipfile.ZipFile(io.BytesIO(rs["node"].body)).namelist()
        b = zipfile.ZipFile(io.BytesIO(rs["rust"].body)).namelist()
        same = sorted(map(norm_entry, a)) == sorted(map(norm_entry, b))
        print(f"        export entries node={len(a)} rust={len(b)} same-names={same}")
        if not same:
            R.results[-1]["problems"].append("export entry names differ")
        if not same:
            print(f"        node: {sorted(map(norm_entry, a))}\n        rust: {sorted(map(norm_entry, b))}")
        za, zb = zipfile.ZipFile(io.BytesIO(rs["node"].body)), zipfile.ZipFile(io.BytesIO(rs["rust"].body))
        for n in a:
            if n.endswith(".json") and "manifest" in n:
                ma, mb = json.loads(za.read(n)), json.loads(zb.read(n))
                d = diff_json(normalize(json.loads(norm_entry(json.dumps(ma))), R.t["node"]), normalize(json.loads(norm_entry(json.dumps(mb))), R.t["rust"]))
                print(f"        manifest diffs: {d[:10]}")
    except Exception as e:
        print(f"        export not a zip: {e}")

    # destructive tail
    s("collection delete", "DELETE", lambda v: f"/api/collections/{v['col_id']}")
    s("drawing delete", "DELETE", lambda v: f"/api/drawings/{v['d2']}")
    s("api key revoke", "DELETE", "/api/auth/api-keys/does-not-exist")
    s("change password wrong", "POST", "/api/auth/change-password", body={"currentPassword": "nope", "newPassword": PASSWORD + "x"})
    s("system update", "GET", "/api/system/update")
    s("unknown route", "GET", "/api/nope")
    s("unknown auth route", "GET", "/api/auth/nope")
    s("options disallowed origin", "OPTIONS", lambda v: f"/api/drawings/{v['d1']}", headers={"Origin": "https://evil.example"}, origin=False)
    s("options unknown route", "OPTIONS", "/api/nope", headers={"Origin": "https://evil.example"}, origin=False)
    s("case-insensitive list", "GET", "/api/Drawings")
    s("case-insensitive read", "GET", lambda v: f"/api/DRAWINGS/{v['d1']}/HISTORY")
    s("case-insensitive auth", "GET", "/api/Auth/Status")
    s("socket.io handshake", "GET", "/socket.io/?EIO=4&transport=polling", compare_body=False)
    s("socket.io preflight", "OPTIONS", "/socket.io/?EIO=4&transport=polling", compare_body=False,
      headers={"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    s("spa index", "GET", "/", compare_body=False)
    s("spa deep link", "GET", "/drawing/abc", compare_body=False)
    s("spa index.html", "GET", "/index.html", compare_body=False)
    s("favicon", "GET", "/favicon.svg", compare_body=False)
    s("missing asset is nginx 404", "GET", "/assets/does-not-exist.js")
    s("directory redirect", "GET", "/assets", compare_body=False)
    s("directory listing forbidden", "GET", "/assets/")
    s("post to static", "POST", "/favicon.svg", compare_body=False)
    rs = s("static asset", "GET", "/", compare_body=False)
    asset = {n: re.search(rb'/assets/[^"]+\.js', r.body).group().decode() for n, r in rs.items()}
    s("static js asset gzip", "GET", lambda v: asset["node"], headers={"Accept-Encoding": "gzip"}, compare_body=False)
    s("static js asset identity", "GET", lambda v: asset["node"], compare_body=False)
    s("static asset 304", "GET", lambda v: asset["node"], headers={"If-Modified-Since": "Sat, 03 Oct 2026 20:23:00 GMT"}, compare_body=False)


def norm_entry(name):
    name = re.sub(r"__[0-9a-f]{8}(?=\.)", "__<id8>", name)
    return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", name)


def main():
    R = Runner()
    try:
        scenario(R)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"scenario aborted: {e}")
    total = len(R.results)
    bad = [r for r in R.results if r["problems"]]
    order = [r for r in R.results if r["key_order"]]
    print(f"\n{total - len(bad)}/{total} steps identical; {len(bad)} with differences; {len(order)} with key-order-only notes")
    if "--json" in sys.argv:
        with open(sys.argv[sys.argv.index("--json") + 1], "w") as f:
            json.dump(R.results, f, indent=1)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
