//! PostgreSQL backend for [`crate::sql`] (`postgres` cargo feature).
//!
//! Statements arrive in the SQLite dialect used throughout the code base and are
//! translated here: `?N` → `$N`, and integer 0/1 literals compared with or inserted
//! into BOOLEAN columns become FALSE/TRUE. Parameters are encoded for the type the
//! server inferred (ms → TIMESTAMP(3), 0/1 → BOOLEAN, i64 → INTEGER, …), and result
//! values are normalised to the SQLite value model (timestamps as ms, booleans 0/1).
use super::{Error, Result, ValueRef};
use bytes::BytesMut;
use postgres::types::{IsNull, Kind, Type};
use std::{collections::HashMap, sync::Arc};

/// Columns declared BOOLEAN in the Prisma PostgreSQL schema.
const BOOL_COLUMNS: &[&str] = &[
    "aiChatgptEnabled",
    "authEnabled",
    "authLoginRateLimitEnabled",
    "authOnboardingCompleted",
    "hidden",
    "isActive",
    "mustResetPassword",
    "needsReconnect",
    "oidcJitProvisioningEnabled",
    "registrationEnabled",
    "revoked",
    "used",
];

/// Columns declared TIMESTAMP(3) (`expiresAt` is BIGINT on "ChatGptConnection").
const TIMESTAMP_COLUMNS: &[&str] = &[
    "bootstrapSetupCodeExpiresAt",
    "bootstrapSetupCodeIssuedAt",
    "createdAt",
    "expiresAt",
    "lastLoginAt",
    "lastUsedAt",
    "lockedUntil",
    "revokedAt",
    "updatedAt",
];

pub fn is_postgres_url(url: &str) -> bool {
    url.starts_with("postgresql://") || url.starts_with("postgres://")
}

// ---------------------------------------------------------------------------
// Connection URL (Prisma's PostgreSQL connection string)

pub struct PgTarget {
    config: postgres::Config,
    tls: tokio_postgres_rustls::MakeRustlsConnect,
    schema: String,
    pub pool_size: u32,
}

/// Parse a Prisma PostgreSQL URL. Prisma-only arguments are interpreted here
/// (`schema` → search_path, `connection_limit` → pool size, `sslmode`/`sslaccept`/
/// `sslcert` → TLS) and not passed to the server.
pub fn parse_url(raw: &str) -> Result<PgTarget> {
    let url = url::Url::parse(raw).map_err(|e| Error::Other(format!("invalid DATABASE_URL: {e}")))?;
    let dec = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned();
    let mut cfg = postgres::Config::new();
    let mut schema = "public".to_string();
    let mut pool_size = 4u32;
    let mut sslmode = "prefer".to_string();
    let mut sslaccept = "accept_invalid_certs".to_string();
    let mut sslcert: Option<String> = None;
    if let Some(host) = url.host_str() {
        cfg.host(host.trim_start_matches('[').trim_end_matches(']'));
    }
    cfg.port(url.port().unwrap_or(5432));
    if !url.username().is_empty() {
        cfg.user(&dec(url.username()));
    }
    if let Some(p) = url.password() {
        cfg.password(dec(p));
    }
    let db = url.path().trim_start_matches('/');
    if !db.is_empty() {
        cfg.dbname(&dec(db));
    }
    cfg.connect_timeout(std::time::Duration::from_secs(5));
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "schema" => schema = v.into_owned(),
            "connection_limit" => pool_size = v.parse().unwrap_or(pool_size).max(1),
            "connect_timeout" => {
                if let Ok(s) = v.parse::<u64>() {
                    if s > 0 {
                        cfg.connect_timeout(std::time::Duration::from_secs(s));
                    }
                }
            }
            "sslmode" => sslmode = v.into_owned(),
            "sslaccept" => sslaccept = v.into_owned(),
            "sslcert" => sslcert = Some(v.into_owned()),
            "host" => {
                cfg.host(v.as_ref());
            }
            "application_name" => {
                cfg.application_name(v.as_ref());
            }
            "options" => {
                cfg.options(v.as_ref());
            }
            // pool_timeout, socket_timeout, pgbouncer, statement_cache_size, sslidentity,
            // sslpassword: Prisma engine knobs without an equivalent here.
            _ => {}
        }
    }
    cfg.ssl_mode(match sslmode.as_str() {
        "disable" => postgres::config::SslMode::Disable,
        "require" => postgres::config::SslMode::Require,
        _ => postgres::config::SslMode::Prefer,
    });
    let tls = tls_connector(sslaccept == "strict", sslcert.as_deref())?;
    Ok(PgTarget { config: cfg, tls, schema, pool_size })
}

#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Prisma's default `sslaccept=accept_invalid_certs` skips verification; `strict`
/// verifies against `sslcert` (PEM CA) or the bundled web PKI roots.
fn tls_connector(strict: bool, ca_file: Option<&str>) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Other(e.to_string()))?;
    let config = if strict {
        let mut roots = rustls::RootCertStore::empty();
        match ca_file {
            Some(path) => {
                let pem = std::fs::read(path).map_err(|e| Error::Other(format!("sslcert {path}: {e}")))?;
                for cert in rustls_pemfile_certs(&pem) {
                    roots.add(cert).map_err(|e| Error::Other(format!("sslcert {path}: {e}")))?;
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth()
    };
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(config))
}

fn rustls_pemfile_certs(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem).filter_map(|c| c.ok()).collect()
}

// ---------------------------------------------------------------------------
// Sessions and pool

pub struct PgSession {
    client: postgres::Client,
    stmts: HashMap<String, postgres::Statement>,
}

impl PgTarget {
    pub fn connect(&self) -> std::result::Result<PgSession, postgres::Error> {
        let mut client = self.config.connect(self.tls.clone())?;
        client.batch_execute(&format!("SET search_path TO {}", quote_ident(&self.schema)))?;
        Ok(PgSession { client, stmts: HashMap::new() })
    }
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub struct PgManager(pub PgTarget);

impl r2d2::ManageConnection for PgManager {
    type Connection = PgSession;
    type Error = postgres::Error;
    fn connect(&self) -> std::result::Result<PgSession, postgres::Error> {
        self.0.connect()
    }
    fn is_valid(&self, s: &mut PgSession) -> std::result::Result<(), postgres::Error> {
        s.client.simple_query("").map(|_| ())
    }
    fn has_broken(&self, s: &mut PgSession) -> bool {
        s.client.is_closed()
    }
}

pub enum PgConn {
    Pooled(r2d2::PooledConnection<PgManager>),
    Owned(PgSession),
}

impl std::ops::Deref for PgConn {
    type Target = PgSession;
    fn deref(&self) -> &PgSession {
        match self {
            PgConn::Pooled(c) => c,
            PgConn::Owned(c) => c,
        }
    }
}
impl std::ops::DerefMut for PgConn {
    fn deref_mut(&mut self) -> &mut PgSession {
        match self {
            PgConn::Pooled(c) => c,
            PgConn::Owned(c) => c,
        }
    }
}

impl PgConn {
    pub fn connect(url: &str) -> Result<PgConn> {
        Ok(PgConn::Owned(parse_url(url)?.connect()?))
    }
}

impl PgSession {
    fn statement(&mut self, sql: &str) -> Result<postgres::Statement> {
        if let Some(s) = self.stmts.get(sql) {
            return Ok(s.clone());
        }
        let translated = translate(sql);
        let st = self.client.prepare(&translated)?;
        if self.stmts.len() > 512 {
            self.stmts.clear();
        }
        self.stmts.insert(sql.to_string(), st.clone());
        Ok(st)
    }

    pub fn execute(&mut self, sql: &str, values: &[ValueRef<'_>]) -> Result<usize> {
        let st = self.statement(sql)?;
        let params: Vec<Param<'_>> = values.iter().map(|v| Param(*v)).collect();
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = params.iter().map(|p| p as _).collect();
        Ok(self.client.execute(&st, &refs)? as usize)
    }

    pub fn query(&mut self, sql: &str, values: &[ValueRef<'_>]) -> Result<Vec<postgres::Row>> {
        let st = self.statement(sql)?;
        let params: Vec<Param<'_>> = values.iter().map(|v| Param(*v)).collect();
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = params.iter().map(|p| p as _).collect();
        Ok(self.client.query(&st, &refs)?)
    }

    /// Several parameterless statements in the SQLite dialect.
    pub fn execute_batch(&mut self, sql: &str) -> Result<()> {
        Ok(self.client.batch_execute(&translate(sql))?)
    }

    pub fn batch_execute_raw(&mut self, sql: &str) -> Result<()> {
        Ok(self.client.batch_execute(sql)?)
    }
}

// ---------------------------------------------------------------------------
// Parameters

#[derive(Debug)]
struct Param<'a>(ValueRef<'a>);

fn ms_to_naive(ms: i64) -> Option<chrono::NaiveDateTime> {
    chrono::DateTime::from_timestamp_millis(ms).map(|d| d.naive_utc())
}

fn text_to_ms(t: &str) -> Option<i64> {
    crate::util::parse_date_ms(t)
}

type BoxErr = Box<dyn std::error::Error + Sync + Send>;

impl postgres::types::ToSql for Param<'_> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> std::result::Result<IsNull, BoxErr> {
        let bad = || -> BoxErr { format!("cannot bind {:?} as {ty}", self.0).into() };
        if matches!(ty.kind(), Kind::Enum(_)) {
            return match self.0 {
                ValueRef::Null => Ok(IsNull::Yes),
                ValueRef::Text(t) => {
                    out.extend_from_slice(t);
                    Ok(IsNull::No)
                }
                _ => Err(bad()),
            };
        }
        match (self.0, ty) {
            (ValueRef::Null, _) => Ok(IsNull::Yes),
            (ValueRef::Integer(i), &Type::BOOL) => (i != 0).to_sql(ty, out),
            (ValueRef::Integer(i), &Type::INT2) => i16::try_from(i)?.to_sql(ty, out),
            (ValueRef::Integer(i), &Type::INT4) => i32::try_from(i)?.to_sql(ty, out),
            (ValueRef::Integer(i), &Type::INT8) => i.to_sql(ty, out),
            (ValueRef::Integer(i), &Type::FLOAT4) => (i as f32).to_sql(ty, out),
            (ValueRef::Integer(i), &Type::FLOAT8) => (i as f64).to_sql(ty, out),
            (ValueRef::Integer(ms), &Type::TIMESTAMP) => ms_to_naive(ms).ok_or_else(bad)?.to_sql(ty, out),
            (ValueRef::Integer(ms), &Type::TIMESTAMPTZ) => {
                chrono::DateTime::from_timestamp_millis(ms).ok_or_else(bad)?.to_sql(ty, out)
            }
            (ValueRef::Integer(i), &Type::TEXT | &Type::VARCHAR | &Type::BPCHAR | &Type::NAME | &Type::UNKNOWN) => {
                i.to_string().as_str().to_sql(ty, out)
            }
            (ValueRef::Real(f), &Type::FLOAT8) => f.to_sql(ty, out),
            (ValueRef::Real(f), &Type::FLOAT4) => (f as f32).to_sql(ty, out),
            (ValueRef::Real(f), &Type::INT4) if f.fract() == 0.0 => (f as i32).to_sql(ty, out),
            (ValueRef::Real(f), &Type::INT8) if f.fract() == 0.0 => (f as i64).to_sql(ty, out),
            (ValueRef::Real(f), &Type::TIMESTAMP) => ms_to_naive(f as i64).ok_or_else(bad)?.to_sql(ty, out),
            (ValueRef::Real(f), &Type::TEXT | &Type::VARCHAR | &Type::UNKNOWN) => {
                crate::util::js_num_str(f).as_str().to_sql(ty, out)
            }
            (ValueRef::Text(t), &Type::TEXT | &Type::VARCHAR | &Type::BPCHAR | &Type::NAME | &Type::UNKNOWN) => {
                std::str::from_utf8(t)?.to_sql(ty, out)
            }
            (ValueRef::Text(t), &Type::JSON) => {
                out.extend_from_slice(t);
                Ok(IsNull::No)
            }
            (ValueRef::Text(t), &Type::JSONB) => {
                out.extend_from_slice(&[1]);
                out.extend_from_slice(t);
                Ok(IsNull::No)
            }
            (ValueRef::Text(t), &Type::TIMESTAMP) => {
                ms_to_naive(text_to_ms(std::str::from_utf8(t)?).ok_or_else(bad)?).ok_or_else(bad)?.to_sql(ty, out)
            }
            (ValueRef::Text(t), &Type::BOOL) => matches!(t, b"1" | b"true").to_sql(ty, out),
            (ValueRef::Text(t), &Type::INT4) => std::str::from_utf8(t)?.parse::<i32>()?.to_sql(ty, out),
            (ValueRef::Text(t), &Type::INT8) => std::str::from_utf8(t)?.parse::<i64>()?.to_sql(ty, out),
            (ValueRef::Text(b) | ValueRef::Blob(b), &Type::BYTEA) => b.to_sql(ty, out),
            (ValueRef::Blob(b), &Type::TEXT | &Type::VARCHAR | &Type::UNKNOWN) => std::str::from_utf8(b)?.to_sql(ty, out),
            _ => Err(bad()),
        }
    }
    fn accepts(_: &Type) -> bool {
        true
    }
    postgres::types::to_sql_checked!();
}

// ---------------------------------------------------------------------------
// Results

/// Raw column bytes (binary format), decoded below.
struct Raw<'a>(Option<&'a [u8]>);

impl<'a> postgres::types::FromSql<'a> for Raw<'a> {
    fn from_sql(_: &Type, raw: &'a [u8]) -> std::result::Result<Self, BoxErr> {
        Ok(Raw(Some(raw)))
    }
    fn from_sql_null(_: &Type) -> std::result::Result<Self, BoxErr> {
        Ok(Raw(None))
    }
    fn accepts(_: &Type) -> bool {
        true
    }
}

fn be_i64(b: &[u8]) -> i64 {
    let mut a = [0u8; 8];
    a[8 - b.len()..].copy_from_slice(b);
    let v = i64::from_be_bytes(a);
    // sign-extend narrower integers
    let shift = 64 - 8 * b.len() as u32;
    if shift == 0 { v } else { (v << shift) >> shift }
}

/// Postgres epoch (2000-01-01) in unix ms.
const PG_EPOCH_MS: i64 = 946_684_800_000;

/// Decode column `i` into the SQLite value model.
pub fn value_ref<'r>(row: &'r postgres::Row, i: usize) -> Result<ValueRef<'r>> {
    let col = row.columns().get(i).ok_or_else(|| Error::InvalidColumnIndex(i.to_string()))?;
    let ty = col.type_().clone();
    let Raw(raw) = row.try_get::<_, Raw<'r>>(i)?;
    let Some(b) = raw else { return Ok(ValueRef::Null) };
    Ok(match ty {
        Type::BOOL => ValueRef::Integer((b.first() == Some(&1)) as i64),
        Type::INT2 | Type::INT4 | Type::INT8 | Type::OID => ValueRef::Integer(be_i64(b)),
        Type::FLOAT4 => ValueRef::Real(f32::from_be_bytes(b.try_into().map_err(|_| Error::Other("float4".into()))?) as f64),
        Type::FLOAT8 => ValueRef::Real(f64::from_be_bytes(b.try_into().map_err(|_| Error::Other("float8".into()))?)),
        // microseconds since 2000-01-01 → unix ms
        Type::TIMESTAMP | Type::TIMESTAMPTZ => ValueRef::Integer(PG_EPOCH_MS + be_i64(b).div_euclid(1000)),
        Type::BYTEA => ValueRef::Blob(b),
        Type::JSONB => ValueRef::Text(b.get(1..).unwrap_or_default()),
        Type::NUMERIC => numeric(b)?,
        _ => ValueRef::Text(b),
    })
}

/// Binary NUMERIC → Integer when integral, else Real.
fn numeric(b: &[u8]) -> Result<ValueRef<'static>> {
    let rd = |i: usize| -> i64 { i16::from_be_bytes([b[i], b[i + 1]]) as i64 };
    if b.len() < 8 {
        return Err(Error::Other("numeric".into()));
    }
    let (ndigits, weight, sign, dscale) = (rd(0) as usize, rd(2), rd(4) as u16, rd(6));
    if sign == 0xC000 {
        return Ok(ValueRef::Real(f64::NAN));
    }
    let mut v = 0f64;
    for d in 0..ndigits {
        v += rd(8 + 2 * d) as f64 * 10000f64.powi((weight - d as i64) as i32);
    }
    if sign == 0x4000 {
        v = -v;
    }
    Ok(if dscale == 0 && v.abs() < 9.0e15 { ValueRef::Integer(v as i64) } else { ValueRef::Real(v) })
}

// ---------------------------------------------------------------------------
// SQL translation (SQLite dialect → PostgreSQL)

#[derive(Debug, PartialEq)]
enum Tok<'s> {
    Ident(&'s str), // "quoted" identifier, without quotes
    Str(&'s str),   // 'string' incl. quotes
    Param(Option<u32>),
    Num(&'s str),
    Word(&'s str),
    Punct(&'s str),
    Space(&'s str),
}

fn tokenize(sql: &str) -> Vec<Tok<'_>> {
    let b = sql.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        match c {
            b'"' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'"' {
                        if b.get(i + 1) == Some(&b'"') {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                out.push(Tok::Ident(&sql[start + 1..i.min(b.len())]));
                i += 1;
            }
            b'\'' => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i = (i + 1).min(b.len());
                out.push(Tok::Str(&sql[start..i]));
            }
            b'?' => {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Tok::Param(sql[start + 1..i].parse().ok()));
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                out.push(Tok::Space(&sql[start..i]));
            }
            _ if c.is_ascii_whitespace() => {
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                out.push(Tok::Space(&sql[start..i]));
            }
            _ if c.is_ascii_digit() => {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                    i += 1;
                }
                out.push(Tok::Num(&sql[start..i]));
            }
            _ if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 => {
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$' || b[i] >= 0x80) {
                    i += 1;
                }
                out.push(Tok::Word(&sql[start..i]));
            }
            _ => {
                i += 1;
                if matches!((c, b.get(i)), (b'!' | b'<' | b'>', Some(b'=')) | (b'<', Some(b'>')) | (b'|', Some(b'|'))) {
                    i += 1;
                }
                out.push(Tok::Punct(&sql[start..i]));
            }
        }
    }
    out
}

fn is_bool_col(name: &str) -> bool {
    BOOL_COLUMNS.contains(&name)
}

/// Literal integer written to / compared with a typed column: 0/1 for BOOLEAN,
/// unix ms for TIMESTAMP(3) (SQLite stores both as plain integers).
fn typed_lit(col: &str, n: &str, int_expires: bool) -> Option<String> {
    if is_bool_col(col) {
        return match n {
            "0" => Some("FALSE".into()),
            "1" => Some("TRUE".into()),
            _ => None,
        };
    }
    if TIMESTAMP_COLUMNS.contains(&col) && !(int_expires && col == "expiresAt") && n.bytes().all(|b| b.is_ascii_digit()) {
        return Some(format!("(TIMESTAMP 'epoch' + {n} * INTERVAL '1 millisecond')"));
    }
    None
}

pub fn translate(sql: &str) -> String {
    let toks = tokenize(sql);
    let mut repl: HashMap<usize, String> = HashMap::new();
    let int_expires = toks.iter().any(|t| *t == Tok::Ident("ChatGptConnection"));
    let next_sig = |from: usize| (from..toks.len()).find(|&j| !matches!(toks[j], Tok::Space(_)));

    // `"boolCol" (=|!=|<>) 0|1`  and  `0|1 = "boolCol"`
    for (i, t) in toks.iter().enumerate() {
        if let Tok::Ident(name) = t {
            if let Some(op) = next_sig(i + 1) {
                if matches!(toks[op], Tok::Punct("=" | "!=" | "<>" | "<" | ">" | "<=" | ">=")) {
                    if let Some(v) = next_sig(op + 1) {
                        if let Tok::Num(n) = toks[v] {
                            if let Some(l) = typed_lit(name, n, int_expires) {
                                repl.insert(v, l);
                            }
                        }
                    }
                }
            }
        }
    }

    // INSERT INTO "T" ("a","b",…) VALUES (…),(…)
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i], Tok::Word(w) if w.eq_ignore_ascii_case("INSERT")) {
            if let Some((cols, mut j)) = insert_columns(&toks, i) {
                if matches!(next_sig(j).map(|k| &toks[k]), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("VALUES")) {
                    j = next_sig(j).unwrap() + 1;
                    // one or more tuples
                    loop {
                        let Some(open) = next_sig(j) else { break };
                        if toks[open] != Tok::Punct("(") {
                            break;
                        }
                        let (items, end) = split_tuple(&toks, open);
                        for (pos, (a, b)) in items.iter().enumerate() {
                            let sig: Vec<usize> = (*a..*b).filter(|&k| !matches!(toks[k], Tok::Space(_))).collect();
                            if let ([k], Some(col)) = (sig.as_slice(), cols.get(pos)) {
                                if let Tok::Num(n) = toks[*k] {
                                    if let Some(l) = typed_lit(col, n, int_expires) {
                                        repl.insert(*k, l);
                                    }
                                }
                            }
                        }
                        j = end + 1;
                        match next_sig(j) {
                            Some(k) if toks[k] == Tok::Punct(",") => j = k + 1,
                            _ => break,
                        }
                    }
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }

    // INSERT OR IGNORE → INSERT … ON CONFLICT DO NOTHING
    let mut or_ignore = false;
    for i in 0..toks.len() {
        if matches!(toks[i], Tok::Word(w) if w.eq_ignore_ascii_case("INSERT")) {
            if let Some(o) = next_sig(i + 1) {
                if matches!(toks[o], Tok::Word(w) if w.eq_ignore_ascii_case("OR")) {
                    if let Some(g) = next_sig(o + 1) {
                        if matches!(toks[g], Tok::Word(w) if w.eq_ignore_ascii_case("IGNORE")) {
                            for k in i + 1..=g {
                                repl.insert(k, String::new());
                            }
                            or_ignore = true;
                        }
                    }
                }
            }
        }
    }

    let mut out = String::with_capacity(sql.len() + 16);
    let mut bare = 0u32;
    for (i, t) in toks.iter().enumerate() {
        if let Some(r) = repl.get(&i) {
            out.push_str(r);
            continue;
        }
        match t {
            Tok::Ident(s) => {
                out.push('"');
                out.push_str(s);
                out.push('"');
            }
            Tok::Param(Some(n)) => {
                bare = bare.max(*n);
                out.push('$');
                out.push_str(&n.to_string());
            }
            Tok::Param(None) => {
                bare += 1;
                out.push('$');
                out.push_str(&bare.to_string());
            }
            Tok::Str(s) | Tok::Num(s) | Tok::Word(s) | Tok::Punct(s) | Tok::Space(s) => out.push_str(s),
        }
    }
    if or_ignore {
        let trimmed = out.trim_end().trim_end_matches(';').len();
        out.truncate(trimmed);
        out.push_str(" ON CONFLICT DO NOTHING");
    }
    out
}

/// After `INSERT [OR …] INTO "T" (cols)`: the column names and the index after `)`.
fn insert_columns<'s>(toks: &[Tok<'s>], insert: usize) -> Option<(Vec<&'s str>, usize)> {
    let mut j = insert + 1;
    let mut depth_guard = 0;
    while j < toks.len() && toks[j] != Tok::Punct("(") {
        if matches!(toks[j], Tok::Word(w) if w.eq_ignore_ascii_case("VALUES") || w.eq_ignore_ascii_case("SELECT")) {
            return None;
        }
        j += 1;
        depth_guard += 1;
        if depth_guard > 12 {
            return None;
        }
    }
    let (items, end) = split_tuple(toks, j);
    let cols = items
        .iter()
        .map(|(a, b)| {
            (*a..*b).find_map(|k| match toks[k] {
                Tok::Ident(s) | Tok::Word(s) => Some(s),
                _ => None,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some((cols, end + 1))
}

/// Split a parenthesised list starting at `open` into top-level item ranges.
fn split_tuple(toks: &[Tok<'_>], open: usize) -> (Vec<(usize, usize)>, usize) {
    let mut depth = 0;
    let mut items = vec![];
    let mut start = open + 1;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match t {
            Tok::Punct("(") => depth += 1,
            Tok::Punct(")") => {
                depth -= 1;
                if depth == 0 {
                    items.push((start, k));
                    return (items, k);
                }
            }
            Tok::Punct(",") if depth == 1 => {
                items.push((start, k));
                start = k + 1;
            }
            _ => {}
        }
    }
    (items, toks.len().saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::translate;

    #[test]
    fn placeholders_and_booleans() {
        assert_eq!(
            translate(r#"SELECT 1 FROM "User" WHERE "isActive" = 1 AND "id" = ?1 AND x = '?2' AND "role" = ?2"#),
            r#"SELECT 1 FROM "User" WHERE "isActive" = TRUE AND "id" = $1 AND x = '?2' AND "role" = $2"#
        );
        assert_eq!(translate(r#"UPDATE "D" SET "hidden"=0, "n" = 1 WHERE a = ? AND b = ?"#), r#"UPDATE "D" SET "hidden"=FALSE, "n" = 1 WHERE a = $1 AND b = $2"#);
        assert_eq!(
            translate(r#"INSERT INTO "SystemConfig" ("id","authEnabled","x","registrationEnabled") VALUES (?1, 0, 1, 1) ON CONFLICT("id") DO NOTHING"#),
            r#"INSERT INTO "SystemConfig" ("id","authEnabled","x","registrationEnabled") VALUES ($1, FALSE, 1, TRUE) ON CONFLICT("id") DO NOTHING"#
        );
        assert_eq!(translate(r#"INSERT OR IGNORE INTO "U" ("id","isActive") VALUES ('a',0);"#), r#"INSERT INTO "U" ("id","isActive") VALUES ('a',FALSE) ON CONFLICT DO NOTHING"#);
        assert_eq!(translate(r#"SELECT "a""b" FROM t -- ?3 'x"#), r#"SELECT "a""b" FROM t -- ?3 'x"#);
    }
}
