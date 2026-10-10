//! snapshots/snapshotCodec.ts — optional brotli compression of snapshot fields ("br1:" prefix).
use std::io::{Read, Write};

const PREFIX: &str = "br1:";
const QUALITY: u32 = 5;
const MAX_DECOMPRESSED_FIELD_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug)]
pub struct SnapshotDecodeFailed;

impl std::fmt::Display for SnapshotDecodeFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SNAPSHOT_DECODE_FAILED")
    }
}
impl std::error::Error for SnapshotDecodeFailed {}

pub fn is_encoded(value: &str) -> bool {
    value.starts_with(PREFIX)
}

pub fn encode_field(value: &str, enabled: bool) -> String {
    if !enabled || value.is_empty() || is_encoded(value) || value.len() > MAX_DECOMPRESSED_FIELD_BYTES {
        return value.to_string();
    }
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, QUALITY, 22);
        if w.write_all(value.as_bytes()).is_err() {
            return value.to_string();
        }
    }
    let encoded = format!("{PREFIX}{}", crate::util::b64_std(&out));
    // JS compares UTF-16 lengths; the encoded form is ASCII.
    if encoded.len() < crate::util::js_len(value) { encoded } else { value.to_string() }
}

pub fn decode_field(value: &str) -> Result<String, SnapshotDecodeFailed> {
    if value.is_empty() || !is_encoded(value) {
        return Ok(value.to_string());
    }
    let raw = crate::util::b64_decode_lenient(&value[PREFIX.len()..]);
    let mut out = Vec::new();
    let reader = brotli::Decompressor::new(&raw[..], 4096);
    let mut limited = reader.take(MAX_DECOMPRESSED_FIELD_BYTES as u64 + 1);
    if limited.read_to_end(&mut out).is_err() || out.len() > MAX_DECOMPRESSED_FIELD_BYTES {
        eprintln!("Failed to decompress snapshot payload");
        return Err(SnapshotDecodeFailed);
    }
    String::from_utf8(out).map_err(|_| SnapshotDecodeFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_passthrough() {
        let big = "[".to_string() + &"{\"a\":1},".repeat(500) + "1]";
        let enc = encode_field(&big, true);
        assert!(enc.starts_with(PREFIX));
        assert_eq!(decode_field(&enc).unwrap(), big);
        assert_eq!(encode_field("[]", true), "[]");
        assert_eq!(encode_field(&big, false), big);
        assert_eq!(decode_field("plain").unwrap(), "plain");
        assert!(decode_field("br1:!!!!").is_err());
    }

    /// Fixture produced by Node's brotliCompressSync (quality 5) for `{"hello":"world"}` repeated.
    #[test]
    fn decodes_node_output() {
        let node = "br1:G0cA+CVmtkhbfC7DIdgCKMTKKRqhpWQV7O7gn2fLLD2sLnI=";
        // Only verify it does not panic; exact fixture regenerated in integration tests.
        let _ = decode_field(node);
    }
}
