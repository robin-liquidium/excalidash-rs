#!/usr/bin/env python3
"""Regenerate src/http/express_routes.rs from an upstream ExcaliDash checkout.

Usage: python3 -I tools/gen_express_routes.py upstream-ref/excalidash > src/http/express_routes.rs

Collects every `app.<method>("path"` / `router.<method>("path"` in backend/src (tests
excluded); `router` routes live under the `/auth` mount (index.ts: app.use("/auth", authRouter)).
"""
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
src = root / "backend" / "src"
pat = re.compile(r'\b(app|router)\.(get|post|put|patch|delete)\(\s*"([^"]+)"')
routes = []
for f in sorted(src.rglob("*.ts")):
    rel = f.relative_to(src).as_posix()
    if "__tests__" in rel or rel.endswith(".test.ts"):
        continue
    for recv, method, path in pat.findall(f.read_text()):
        if not path.startswith("/"):
            continue  # app.get("trust proxy") etc.
        full = ("/auth" + path) if recv == "router" else path
        routes.append((full, method.upper(), rel))
seen = set()
unique = []
for r in sorted(routes, key=lambda r: (r[0], r[1])):
    if (r[0], r[1]) not in seen:
        seen.add((r[0], r[1]))
        unique.append(r)
try:
    tag = subprocess.run(["git", "-C", str(root), "describe", "--tags"], capture_output=True, text=True).stdout.strip()
except OSError:
    tag = ""
print(f"//! Upstream Express route table (generated from ExcaliDash {tag.lstrip('v') or '?'} `backend/src`).")
print("//! Used for Express's case-insensitive path matching and its automatic OPTIONS reply.")
print("//! Regenerate when porting a new upstream release: tools/gen_express_routes.py (see UPGRADING.md).")
print("pub static ROUTES: &[(&str, &str)] = &[")
for path, method, rel in unique:
    print(f'    ("{method}", "{path}"), // {rel}')
print("];")
