# syntax=docker/dockerfile:1
# ExcaliDash (Rust backend + bundled upstream frontend) in a single scratch image.

ARG FRONTEND_IMAGE=zimengxiong/excalidash-frontend:0.6.5

# --- build: static musl binary -------------------------------------------------
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# Dependency layer (cached until Cargo.toml/Cargo.lock change).
COPY Cargo.toml Cargo.lock build.rs VERSION ./
COPY prisma ./prisma
COPY vendor ./vendor
RUN mkdir src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked && rm -rf src target/release/.fingerprint/excalidash*
COPY src ./src
RUN cargo build --release --locked && cp target/release/excalidash-rs /excalidash-rs

# --- frontend: unmodified upstream build, compressible assets stored as .gz -----
FROM ${FRONTEND_IMAGE} AS frontend-src
FROM alpine:3 AS frontend
COPY --from=frontend-src /usr/share/nginx/html /public
# Keep the original mtimes so Last-Modified/ETag match nginx's (gzip resets them).
RUN find /public -type f \( -name '*.js' -o -name '*.css' \) -exec sh -c 'gzip -9 -n -k "$1" && touch -r "$1" "$1.gz" && rm "$1"' _ {} \; \
    && mkdir -p /skel/app/prisma /skel/app/backups /skel/app/uploads

# --- runtime ------------------------------------------------------------------------
FROM scratch
COPY --from=frontend --chown=1001:1001 /skel/app /app
COPY --from=frontend /public /app/public
COPY --from=build /excalidash-rs /app/excalidash-rs
COPY VERSION /app/VERSION
WORKDIR /app
USER 1001:1001
ENV EXCALIDASH_ENTRYPOINT=1 \
    PORT=8080 \
    DATABASE_URL=file:/app/prisma/dev.db
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD ["/app/excalidash-rs", "healthcheck"]
ENTRYPOINT ["/app/excalidash-rs"]
