//! routes/importExport/exportFiles.ts — inline managed images into exported drawings.
use serde_json::{Map, Value};
use std::future::Future;

/// A DrawingFile row as selected by the export route.
#[derive(Debug, Clone)]
pub struct ExportFileRecord {
    pub file_id: String,
    pub mime_type: String,
    pub storage: String,
    pub s3_key: Option<String>,
    pub data: Option<Vec<u8>>,
}

fn is_unmanaged_external_reference(value: &str) -> bool {
    if crate::util::js_len(value) > 2048 {
        return false;
    }
    let lower: String = value.chars().take(8).collect::<String>().to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    match url::Url::parse(value) {
        // Absolute URLs to the managed endpoint still require stored bytes.
        Ok(u) => {
            let p = u.path().to_ascii_lowercase();
            !(p == "/api/files" || p.starts_with("/api/files/"))
        }
        Err(_) => false,
    }
}

/// embedDrawingFilesForExport: replace managed references with inline data
/// URLs (DrawingFile is authoritative); keep unmanaged http(s) references.
pub async fn embed_drawing_files_for_export<F, Fut>(
    files: &Map<String, Value>,
    records: &[ExportFileRecord],
    download: F,
) -> Result<Map<String, Value>, String>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    let mut embedded = files.clone();
    for record in records {
        let Some(Value::Object(file)) = embedded.get(&record.file_id) else { continue };
        let mut file = file.clone();
        let bytes = match record.storage.as_str() {
            "db" => match &record.data {
                Some(d) => d.clone(),
                None => return Err(format!("Stored drawing file is missing database bytes: {}", record.file_id)),
            },
            "s3" => match &record.s3_key {
                Some(k) => download(k.clone()).await?,
                None => return Err(format!("Stored drawing file is missing its S3 key: {}", record.file_id)),
            },
            other => return Err(format!("Unsupported drawing file storage: {other}")),
        };
        file.insert(
            "dataURL".into(),
            Value::String(format!("data:{};base64,{}", record.mime_type, crate::util::b64_std(&bytes))),
        );
        embedded.insert(record.file_id.clone(), Value::Object(file));
    }
    let unresolved: Vec<&String> = embedded
        .iter()
        .filter(|(_, f)| match f.get("dataURL") {
            Some(Value::String(u)) if f.is_object() => {
                !u.is_empty() && !u.starts_with("data:") && !is_unmanaged_external_reference(u)
            }
            _ => false,
        })
        .map(|(id, _)| id)
        .collect();
    if !unresolved.is_empty() {
        return Err(format!(
            "Could not bundle {} drawing image(s): {}",
            unresolved.len(),
            unresolved.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(embedded)
}

/// Port of account-backup-images.integration.ts (S3 access is a mocked closure).
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    const EXTERNAL: &str = "https://external.example/imported.png";
    const BYTES: &[u8] = b"managed image bytes";

    fn files(url: &str) -> Map<String, Value> {
        json!({"image": {"id": "image", "mimeType": "image/png", "created": 123, "dataURL": url}})
            .as_object()
            .unwrap()
            .clone()
    }
    fn record() -> ExportFileRecord {
        ExportFileRecord {
            file_id: "image".into(),
            mime_type: "image/png".into(),
            storage: "db".into(),
            s3_key: None,
            data: Some(BYTES.to_vec()),
        }
    }
    fn inline() -> String {
        format!("data:image/png;base64,{}", crate::util::b64_std(BYTES))
    }

    type Calls = Arc<Mutex<Vec<String>>>;
    fn downloader(result: Result<Vec<u8>, String>) -> (Calls, impl Fn(String) -> std::future::Ready<Result<Vec<u8>, String>>) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let c = calls.clone();
        (calls, move |k: String| {
            c.lock().unwrap().push(k);
            std::future::ready(result.clone())
        })
    }

    fn run<T>(f: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn preserves_unmanaged_references_without_storage() {
        for url in [EXTERNAL, "http://legacy.example/image.png"] {
            let (calls, dl) = downloader(Ok(vec![]));
            let source = files(url);
            assert_eq!(run(embed_drawing_files_for_export(&source, &[], dl)).unwrap(), source);
            assert!(calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_unresolved_or_unsupported_references() {
        let long = format!("https://example.com/{}", "x".repeat(2048));
        for url in [
            "/api/files/old-drawing/image",
            "https://app.example/api/files/old-drawing/image",
            "https://",
            long.as_str(),
            "//external.example/image.png",
            "file:///tmp/image.png",
            "javascript:alert(1)",
            "blob:https://app.example/image",
        ] {
            let (calls, dl) = downloader(Ok(vec![]));
            let err = run(embed_drawing_files_for_export(&files(url), &[], dl)).unwrap_err();
            assert_eq!(err, "Could not bundle 1 drawing image(s): image", "{url}");
            assert!(calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn retains_legacy_inline_bytes() {
        let (calls, dl) = downloader(Ok(vec![]));
        let source = files(&inline());
        assert_eq!(run(embed_drawing_files_for_export(&source, &[], dl)).unwrap(), source);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn managed_database_bytes_are_authoritative() {
        for url in [EXTERNAL.to_string(), "/api/files/drawing/image".to_string(), inline()] {
            let (_, dl) = downloader(Ok(vec![]));
            let source = files(&url);
            assert_eq!(run(embed_drawing_files_for_export(&source, &[record()], dl)).unwrap(), files(&inline()));
            assert_eq!(source["image"]["dataURL"], json!(url));
        }
    }

    #[test]
    fn bundles_managed_s3_bytes() {
        for key in ["owner/drawing/image.png", "owner/drawing/generation/image.png"] {
            let (calls, dl) = downloader(Ok(BYTES.to_vec()));
            let rec = ExportFileRecord { storage: "s3".into(), s3_key: Some(key.into()), data: None, ..record() };
            assert_eq!(run(embed_drawing_files_for_export(&files(EXTERNAL), &[rec], dl)).unwrap(), files(&inline()));
            assert_eq!(*calls.lock().unwrap(), vec![key.to_string()]);
        }
    }

    #[test]
    fn missing_database_bytes_are_not_masked() {
        for url in [EXTERNAL.to_string(), inline()] {
            let (_, dl) = downloader(Ok(vec![]));
            let rec = ExportFileRecord { data: None, ..record() };
            assert_eq!(
                run(embed_drawing_files_for_export(&files(&url), &[rec], dl)).unwrap_err(),
                "Stored drawing file is missing database bytes: image"
            );
        }
    }

    #[test]
    fn missing_s3_key_fails() {
        let (calls, dl) = downloader(Ok(vec![]));
        let rec = ExportFileRecord { storage: "s3".into(), ..record() };
        assert_eq!(
            run(embed_drawing_files_for_export(&files(EXTERNAL), &[rec], dl)).unwrap_err(),
            "Stored drawing file is missing its S3 key: image"
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn propagates_s3_failures() {
        for message in ["NoSuchKey", "AccessDenied", "storage unavailable"] {
            let (_, dl) = downloader(Err(message.to_string()));
            let source = files(EXTERNAL);
            let rec = ExportFileRecord { storage: "s3".into(), s3_key: Some("managed/image.png".into()), data: None, ..record() };
            assert_eq!(run(embed_drawing_files_for_export(&source, &[rec], dl)).unwrap_err(), message);
            assert_eq!(source["image"]["dataURL"], json!(EXTERNAL));
        }
    }

    #[test]
    fn rejects_unsupported_storage() {
        let (_, dl) = downloader(Ok(vec![]));
        let rec = ExportFileRecord { storage: "unknown".into(), ..record() };
        assert_eq!(
            run(embed_drawing_files_for_export(&files(EXTERNAL), &[rec], dl)).unwrap_err(),
            "Unsupported drawing file storage: unknown"
        );
    }
}
