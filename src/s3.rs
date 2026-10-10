//! STUB — s3.ts (S3-compatible object storage for drawing images).
use crate::config::config;

/// isS3Enabled()
pub fn is_s3_enabled() -> bool {
    config().s3.bucket.is_some()
}

/// downloadBuffer(key) — placeholder until the S3 module lands (export uses it).
pub async fn download_buffer(_key: &str) -> Result<Vec<u8>, String> {
    Err("S3 is not configured".into())
}

/// checkBucketReachable(timeoutMs) — placeholder until the S3 module lands (storage doctor uses it).
pub async fn check_bucket_reachable(_timeout_ms: u64) -> Result<(), String> {
    Err("S3 is not configured".into())
}
