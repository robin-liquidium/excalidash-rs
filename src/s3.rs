//! STUB — s3.ts (S3-compatible object storage for drawing images).
use crate::config::config;

/// isS3Enabled()
pub fn is_s3_enabled() -> bool {
    config().s3.bucket.is_some()
}
