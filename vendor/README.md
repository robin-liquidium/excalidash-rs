# Vendored crates

## hyper 1.12.0

Upstream source with two patches (search for `excalidash-rs patch`):

1. `src/ext/mod.rs`: `HeaderCaseMap` is public and has `new()`/`push()`, so the server can
   attach a response extension with the exact header-name spellings upstream ExcaliDash
   (Express + nginx) sends. hyper's HTTP/1 encoder already honours this extension.
2. `src/proto/h1/role.rs`: an explicit `Content-Length: 0` header on a 204 response is
   written instead of dropped (Express/cors send it on preflight replies).

When bumping hyper, re-apply both patches to the new version (they are ~25 lines).
