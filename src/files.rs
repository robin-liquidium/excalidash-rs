//! STUB — fileProcessing.ts + drawingFileStore.ts (image blob interning/storage).
use serde_json::{Map, Value};

use crate::http::error::ApiError;
use crate::state::AppState;

/// internDrawingFiles(files, userId, drawingId): store inline dataURLs, rewrite to refs.
pub async fn intern_drawing_files(
    _st: &AppState,
    files: Map<String, Value>,
    _user_id: &str,
    _drawing_id: &str,
) -> Result<Map<String, Value>, ApiError> {
    Ok(files)
}

/// rewritePreviewForInternedFiles(preview, originalFiles, processedFiles)
pub fn rewrite_preview_for_interned_files(preview: &Value, original: &Map<String, Value>, processed: &Map<String, Value>) -> Value {
    let Value::String(p) = preview else { return preview.clone() };
    if p.is_empty() {
        return preview.clone();
    }
    let mut out = p.clone();
    for (id, proc_file) in processed {
        let (Some(o), Some(n)) = (
            original.get(id).and_then(|f| f.get("dataURL")).and_then(|v| v.as_str()),
            proc_file.get("dataURL").and_then(|v| v.as_str()),
        ) else { continue };
        if o == n {
            continue;
        }
        out = out.split(o).collect::<Vec<_>>().join(n);
    }
    Value::String(out)
}
