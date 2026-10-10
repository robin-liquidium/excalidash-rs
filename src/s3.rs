//! s3.ts — S3-compatible object storage for drawing images (AWS S3, R2, MinIO, OSS, ...).
//!
//! Requests are SigV4-presigned with `rusty-s3` and sent with the shared
//! `reqwest` client (`st.http()`). Every signed header is sent verbatim.
use rusty_s3::{actions::ListObjectsV2, Bucket, Credentials, S3Action, UrlStyle};
use std::{sync::OnceLock, time::Duration};

use crate::config::{config, S3Config};

/// Validity of the internal presigned request URLs (server → S3).
const SIGN_TTL: Duration = Duration::from_secs(300);
const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";

#[derive(Debug, Clone)]
pub struct S3Error(pub String);

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for S3Error {}

impl From<S3Error> for crate::http::error::ApiError {
    fn from(e: S3Error) -> Self {
        crate::http::error::ApiError::internal(e.0)
    }
}

fn not_configured() -> S3Error {
    S3Error("S3 is not configured".into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Object {
    pub key: String,
    pub size: u64,
}

/// Initialised S3 client (`initS3`).
pub struct S3Client {
    bucket: Bucket,
    credentials: Option<Credentials>,
    bucket_name: String,
    region: String,
    public_url: Option<String>,
    key_prefix: String,
}

/// RFC-1123 label rules the AWS endpoint ruleset uses for virtual hosting
/// (`isVirtualHostableS3Bucket(bucket, false)`).
fn is_virtual_hostable(bucket: &str) -> bool {
    let len = bucket.len();
    (3..=63).contains(&len)
        && bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && bucket.as_bytes()[0].is_ascii_alphanumeric()
        && bucket.as_bytes()[len - 1].is_ascii_alphanumeric()
}

impl S3Client {
    /// Build a client from the parsed `S3_*` config (bucket must be set).
    pub fn new(cfg: &S3Config) -> Result<S3Client, S3Error> {
        let bucket_name = cfg.bucket.clone().ok_or_else(not_configured)?;
        let (endpoint, path_style) = match &cfg.endpoint {
            Some(raw) => {
                let mut url = url::Url::parse(raw).map_err(|e| S3Error(format!("Invalid S3_ENDPOINT: {e}")))?;
                if !url.path().ends_with('/') {
                    let p = format!("{}/", url.path());
                    url.set_path(&p);
                }
                let host_is_ip = matches!(url.host(), Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)));
                (url, cfg.force_path_style || host_is_ip || !is_virtual_hostable(&bucket_name))
            }
            None => (
                url::Url::parse(&format!("https://s3.{}.amazonaws.com/", cfg.region))
                    .map_err(|e| S3Error(format!("Invalid S3_REGION: {e}")))?,
                !is_virtual_hostable(&bucket_name),
            ),
        };
        let style = if path_style { UrlStyle::Path } else { UrlStyle::VirtualHost };
        let bucket = Bucket::new(endpoint, style, bucket_name.clone(), cfg.region.clone())
            .map_err(|e| S3Error(format!("Invalid S3 configuration: {e:?}")))?;
        let credentials = match (&cfg.access_key_id, &cfg.secret_access_key) {
            (Some(k), Some(s)) => Some(Credentials::new(k.clone(), s.clone())),
            _ => None,
        };
        Ok(S3Client {
            bucket,
            credentials,
            bucket_name,
            region: cfg.region.clone(),
            public_url: cfg.public_url.clone(),
            key_prefix: cfg.key_prefix.clone(),
        })
    }

    pub fn bucket_name(&self) -> &str {
        &self.bucket_name
    }
    pub fn public_url_base(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    /// `drawingS3Prefix(userId, drawingId)`
    pub fn drawing_prefix(&self, user_id: &str, drawing_id: &str) -> String {
        format!("{}/{user_id}/{drawing_id}/", self.key_prefix)
    }

    /// `buildS3Key(userId, drawingId, fileId, ext, generation?)`
    pub fn build_key(&self, user_id: &str, drawing_id: &str, file_id: &str, ext: &str, generation: Option<&str>) -> String {
        let generation = generation.filter(|g| !g.is_empty()).map(|g| format!("{g}/")).unwrap_or_default();
        format!("{}{generation}{file_id}.{ext}", self.drawing_prefix(user_id, drawing_id))
    }

    /// `getPublicUrl(key)`
    pub fn public_url(&self, key: &str) -> String {
        match &self.public_url {
            Some(base) => format!("{}/{key}", base.strip_suffix('/').unwrap_or(base)),
            None => format!("https://{}.s3.{}.amazonaws.com/{key}", self.bucket_name, self.region),
        }
    }

    /// `generatePresignedDownloadUrl(key, expiresIn, overrides)`
    pub fn presigned_download_url(
        &self,
        key: &str,
        expires_in_secs: u64,
        content_type: Option<&str>,
        content_disposition: Option<&str>,
    ) -> String {
        let mut action = self.bucket.get_object(self.credentials.as_ref(), key);
        let q = action.query_mut();
        q.insert("response-cache-control", IMMUTABLE_CACHE);
        if let Some(ct) = content_type {
            q.insert("response-content-type", ct.to_string());
        }
        if let Some(cd) = content_disposition {
            q.insert("response-content-disposition", cd.to_string());
        }
        action.sign(Duration::from_secs(expires_in_secs)).to_string()
    }

    async fn send(
        &self,
        http: &reqwest::Client,
        method: reqwest::Method,
        url: url::Url,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<(reqwest::StatusCode, bytes::Bytes), S3Error> {
        let mut rb = http.request(method, url.as_str());
        for (k, v) in headers {
            rb = rb.header(*k, v);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        if let Some(t) = timeout {
            rb = rb.timeout(t);
        }
        let res = rb.send().await.map_err(|e| S3Error(describe_reqwest_error(&e)))?;
        let status = res.status();
        let bytes = res.bytes().await.map_err(|e| S3Error(describe_reqwest_error(&e)))?;
        if !status.is_success() {
            return Err(S3Error(service_error_message(status, &bytes)));
        }
        Ok((status, bytes))
    }

    /// `uploadBuffer(key, body, mimeType)`
    pub async fn upload_buffer(&self, http: &reqwest::Client, key: &str, body: Vec<u8>, mime_type: &str) -> Result<(), S3Error> {
        let headers = [("content-type", mime_type.to_string()), ("cache-control", IMMUTABLE_CACHE.to_string())];
        let mut action = self.bucket.put_object(self.credentials.as_ref(), key);
        for (k, v) in &headers {
            action.headers_mut().insert(*k, v.clone());
        }
        let url = action.sign(SIGN_TTL);
        self.send(http, reqwest::Method::PUT, url, &headers, Some(body), None).await?;
        Ok(())
    }

    /// `downloadBuffer(key)`
    pub async fn download_buffer(&self, http: &reqwest::Client, key: &str) -> Result<Vec<u8>, S3Error> {
        let url = self.bucket.get_object(self.credentials.as_ref(), key).sign(SIGN_TTL);
        let (_, bytes) = self.send(http, reqwest::Method::GET, url, &[], None, None).await?;
        Ok(bytes.to_vec())
    }

    /// `listS3Objects(prefix)` — follows continuation tokens.
    pub async fn list_objects(&self, http: &reqwest::Client, prefix: &str) -> Result<Vec<S3Object>, S3Error> {
        let mut results = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = ListObjectsV2::new(&self.bucket, self.credentials.as_ref());
            action.with_prefix(prefix.to_string());
            if let Some(t) = &token {
                action.with_continuation_token(t.clone());
            }
            let url = action.sign(SIGN_TTL);
            let (_, bytes) = self.send(http, reqwest::Method::GET, url, &[], None, None).await?;
            let text = String::from_utf8_lossy(&bytes);
            let parsed = ListObjectsV2::parse_response(&text).map_err(|e| S3Error(format!("Invalid ListObjectsV2 response: {e}")))?;
            for obj in parsed.contents {
                if !obj.key.is_empty() {
                    results.push(S3Object { key: obj.key, size: obj.size });
                }
            }
            match parsed.next_continuation_token.filter(|t| !t.is_empty()) {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        Ok(results)
    }

    /// `copyS3Object(sourceKey, destKey, mimeType?)` — server-side copy.
    pub async fn copy_object(&self, http: &reqwest::Client, source_key: &str, dest_key: &str, mime_type: Option<&str>) -> Result<(), S3Error> {
        let mut headers = vec![
            ("x-amz-copy-source", format!("{}/{source_key}", self.bucket_name)),
            ("cache-control", IMMUTABLE_CACHE.to_string()),
            ("x-amz-metadata-directive", if mime_type.is_some() { "REPLACE" } else { "COPY" }.to_string()),
        ];
        if let Some(m) = mime_type {
            headers.push(("content-type", m.to_string()));
        }
        let mut action = self.bucket.put_object(self.credentials.as_ref(), dest_key);
        for (k, v) in &headers {
            action.headers_mut().insert(*k, v.clone());
        }
        let url = action.sign(SIGN_TTL);
        let (status, bytes) = self.send(http, reqwest::Method::PUT, url, &headers, None, None).await?;
        // CopyObject can report failure inside a 200 response.
        if String::from_utf8_lossy(&bytes).contains("<Error>") {
            return Err(S3Error(service_error_message(status, &bytes)));
        }
        Ok(())
    }

    /// `deleteS3Object(key)`
    pub async fn delete_object(&self, http: &reqwest::Client, key: &str) -> Result<(), S3Error> {
        let url = self.bucket.delete_object(self.credentials.as_ref(), key).sign(SIGN_TTL);
        self.send(http, reqwest::Method::DELETE, url, &[], None, None).await?;
        Ok(())
    }

    /// `checkBucketReachable(timeoutMs)` — HeadBucket with a hard timeout; never fails.
    pub async fn check_bucket_reachable(&self, http: &reqwest::Client, timeout_ms: u64) -> Result<(), String> {
        let url = self.bucket.head_bucket(self.credentials.as_ref()).sign(SIGN_TTL);
        let fut = self.send(http, reqwest::Method::HEAD, url, &[], None, None);
        match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
            Err(_) => Err(format!("timed out after {timeout_ms}ms")),
            Ok(Err(e)) => Err(e.0),
            Ok(Ok(_)) => Ok(()),
        }
    }
}

fn describe_reqwest_error(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

fn xml_tag<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{tag}>"))? + start;
    Some(&body[start..end])
}

/// Error text like the AWS SDK: the service `Message`, else the `Code`,
/// else a status-derived name (HEAD responses have no body).
fn service_error_message(status: reqwest::StatusCode, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if let Some(m) = xml_tag(&text, "Message").filter(|m| !m.is_empty()) {
        return m.to_string();
    }
    if let Some(c) = xml_tag(&text, "Code").filter(|c| !c.is_empty()) {
        return c.to_string();
    }
    match status.as_u16() {
        301 => "PermanentRedirect".into(),
        403 => "Forbidden".into(),
        404 => "NotFound".into(),
        _ => "UnknownError".into(),
    }
}

// ---------------------------------------------------------------------------
// Module-level API (mirrors the s3.ts exports, using the configured client).

static CLIENT: OnceLock<Option<S3Client>> = OnceLock::new();

/// The configured client, or `None` when S3_BUCKET is unset (`initS3` not called).
pub fn client() -> Option<&'static S3Client> {
    CLIENT
        .get_or_init(|| {
            let cfg = &config().s3;
            cfg.bucket.as_ref()?;
            match S3Client::new(cfg) {
                Ok(c) => Some(c),
                Err(e) => {
                    eprintln!("[s3] {e}");
                    None
                }
            }
        })
        .as_ref()
}

/// isS3Enabled()
pub fn is_s3_enabled() -> bool {
    client().is_some()
}

fn require() -> Result<&'static S3Client, S3Error> {
    client().ok_or_else(not_configured)
}

/// `drawingS3Prefix(userId, drawingId)` (uses S3_KEY_PREFIX even when S3 is off).
pub fn drawing_s3_prefix(user_id: &str, drawing_id: &str) -> String {
    format!("{}/{user_id}/{drawing_id}/", config().s3.key_prefix)
}

/// `buildS3Key(userId, drawingId, fileId, ext, generation?)`
pub fn build_s3_key(user_id: &str, drawing_id: &str, file_id: &str, ext: &str, generation: Option<&str>) -> String {
    let generation = generation.filter(|g| !g.is_empty()).map(|g| format!("{g}/")).unwrap_or_default();
    format!("{}{generation}{file_id}.{ext}", drawing_s3_prefix(user_id, drawing_id))
}

/// `getS3Config()?.publicUrl`
pub fn public_url_base() -> Option<&'static str> {
    client().and_then(|c| c.public_url_base())
}

/// `getPublicUrl(key)`
pub fn get_public_url(key: &str) -> Result<String, S3Error> {
    Ok(require()?.public_url(key))
}

pub fn generate_presigned_download_url(
    key: &str,
    expires_in_secs: u64,
    content_type: Option<&str>,
    content_disposition: Option<&str>,
) -> Result<String, S3Error> {
    Ok(require()?.presigned_download_url(key, expires_in_secs, content_type, content_disposition))
}

pub async fn upload_buffer(http: &reqwest::Client, key: &str, body: Vec<u8>, mime_type: &str) -> Result<(), S3Error> {
    require()?.upload_buffer(http, key, body, mime_type).await
}

pub async fn download_buffer(http: &reqwest::Client, key: &str) -> Result<Vec<u8>, S3Error> {
    require()?.download_buffer(http, key).await
}

pub async fn list_s3_objects(http: &reqwest::Client, prefix: &str) -> Result<Vec<S3Object>, S3Error> {
    require()?.list_objects(http, prefix).await
}

pub async fn copy_s3_object(http: &reqwest::Client, source_key: &str, dest_key: &str, mime_type: Option<&str>) -> Result<(), S3Error> {
    require()?.copy_object(http, source_key, dest_key, mime_type).await
}

pub async fn delete_s3_object(http: &reqwest::Client, key: &str) -> Result<(), S3Error> {
    require()?.delete_object(http, key).await
}

/// `checkBucketReachable(timeoutMs)`
pub async fn check_bucket_reachable(http: &reqwest::Client, timeout_ms: u64) -> Result<(), String> {
    match client() {
        Some(c) => c.check_bucket_reachable(http, timeout_ms).await,
        None => Err("S3 is not configured".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(endpoint: Option<&str>, path_style: bool, public: Option<&str>) -> S3Config {
        S3Config {
            bucket: Some("my-bucket".into()),
            region: "eu-west-1".into(),
            endpoint: endpoint.map(str::to_string),
            public_url: public.map(str::to_string),
            force_path_style: path_style,
            key_prefix: "excalidash".into(),
            access_key_id: Some("AKIDEXAMPLE".into()),
            secret_access_key: Some("secret".into()),
        }
    }

    /// s3-generation-keys.integration.ts (key layout part).
    #[test]
    fn generation_keys_extend_legacy_layout() {
        let c = S3Client::new(&cfg(None, false, None)).unwrap();
        let prefix = c.drawing_prefix("owner", "drawing");
        assert_eq!(prefix, "excalidash/owner/drawing/");
        assert_eq!(c.build_key("owner", "drawing", "image-id", "png", None), format!("{prefix}image-id.png"));
        assert_eq!(
            c.build_key("owner", "drawing", "image-id", "png", Some("generation")),
            format!("{prefix}generation/image-id.png")
        );
    }

    #[test]
    fn url_styles_follow_sdk_rules() {
        let aws = S3Client::new(&cfg(None, false, None)).unwrap();
        assert!(aws.presigned_download_url("k/a.png", 60, None, None).starts_with("https://my-bucket.s3.eu-west-1.amazonaws.com/k/a.png?"));
        let minio = S3Client::new(&cfg(Some("http://127.0.0.1:9000"), false, None)).unwrap();
        assert!(minio.presigned_download_url("k.png", 60, None, None).starts_with("http://127.0.0.1:9000/my-bucket/k.png?"));
        let vhost = S3Client::new(&cfg(Some("https://oss.example.com"), false, None)).unwrap();
        assert!(vhost.presigned_download_url("k.png", 60, None, None).starts_with("https://my-bucket.oss.example.com/k.png?"));
        let forced = S3Client::new(&cfg(Some("https://minio.example.com/base"), true, None)).unwrap();
        let url = forced.presigned_download_url("k.png", 60, Some("image/png"), Some("attachment"));
        assert!(url.starts_with("https://minio.example.com/base/my-bucket/k.png?"), "{url}");
        assert!(url.contains("response-content-type=image%2Fpng"));
        assert!(url.contains("response-content-disposition=attachment"));
        assert!(url.contains("X-Amz-Expires=60"));
    }

    #[test]
    fn public_url_trims_one_trailing_slash() {
        let c = S3Client::new(&cfg(None, false, Some("https://cdn.example.com/"))).unwrap();
        assert_eq!(c.public_url("a/b.png"), "https://cdn.example.com/a/b.png");
        let c = S3Client::new(&cfg(None, false, None)).unwrap();
        assert_eq!(c.public_url("a/b.png"), "https://my-bucket.s3.eu-west-1.amazonaws.com/a/b.png");
    }

    #[test]
    fn error_messages() {
        let body = b"<?xml version=\"1.0\"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>";
        assert_eq!(service_error_message(reqwest::StatusCode::NOT_FOUND, body), "The specified bucket does not exist");
        assert_eq!(service_error_message(reqwest::StatusCode::NOT_FOUND, b""), "NotFound");
    }
}
