//! Port of drawing-files-merge.integration.ts, saved-scene-broadcast.integration.ts and the
//! scene-update parts of file-retention.integration.ts.
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

const AAAA: &str = "data:image/png;base64,AAAA";

fn merge_world(env: &[(&str, &str)]) -> (TestServer, TestClient, String) {
    let s = auth_server_with(env);
    let (c, id) = user(&s, "owner@test.local", "Owner");
    (s, c, id)
}

fn drawing_with_files(s: &TestServer, owner: &str, files: Value, version: i64) -> String {
    let f = files.to_string();
    insert_drawing(s, owner, NewDrawing { name: "Merge Test", files: Some(&f), version: Some(version), ..Default::default() })
}

// ---------------------------------------------------------------------------
// drawing-files-merge.integration.ts

#[test]
fn unions_incoming_files_with_existing_files_instead_of_whole_replacing() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({"file-a": file_entry("file-a", AAAA)}), 1);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-b": file_entry("file-b", AAAA)}}));
    assert_eq!(r.status, 200, "{}", r.text());
    let files = drawing_files(&s, &d);
    let mut keys: Vec<&String> = files.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["file-a", "file-b"]);
}

#[test]
fn overwrites_an_existing_file_entry_with_new_content_and_interns_it() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({"file-a": file_entry("file-a", "data:image/png;base64,OLD=")}), 1);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-a": file_entry("file-a", "data:image/png;base64,NEW=")}}));
    assert_eq!(r.status, 200);
    assert_eq!(drawing_files(&s, &d)["file-a"]["dataURL"], json!(format!("/api/files/{d}/file-a")));
    let (storage, data): (String, Vec<u8>) = s
        .db()
        .query_row(r#"SELECT "storage","data" FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = 'file-a'"#, [&d], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(storage, "db");
    assert_eq!(data, excalidash_rs::util::b64_decode_lenient("NEW="));
}

#[test]
fn does_not_let_a_blank_incoming_entry_erase_existing_content() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({"file-a": file_entry("file-a", "data:image/png;base64,GOOD=")}), 1);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-a": {"id": "file-a", "mimeType": "image/png", "dataURL": ""}}}));
    assert_eq!(r.status, 200);
    assert_eq!(drawing_files(&s, &d)["file-a"]["dataURL"], "data:image/png;base64,GOOD=");
}

#[test]
fn preserves_stored_image_metadata_for_non_string_incoming_data_urls() {
    let (s, c, owner) = merge_world(&[]);
    let stored = file_entry("file-a", "data:image/png;base64,GOOD=");
    for incoming in [json!({"id": "file-a", "mimeType": "image/png"}), json!({"id": "file-a", "dataURL": null, "mimeType": "image/png"}), json!({"id": "file-a", "dataURL": 42, "mimeType": "image/png"}), json!({"id": "file-a", "dataURL": {}, "mimeType": "image/png"})] {
        let d = drawing_with_files(&s, &owner, json!({"file-a": stored}), 1);
        let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-a": incoming}}));
        assert_eq!(r.status, 200, "{incoming}: {}", r.text());
        assert_eq!(drawing_files(&s, &d)["file-a"], stored, "{incoming}");
    }
}

#[test]
fn snapshots_the_authoritative_state_and_bumps_version() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({"file-a": file_entry("file-a", AAAA)}), 3);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-b": file_entry("file-b", AAAA)}, "version": 3}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["version"], 4);
    let (version, files): (i64, String) = s
        .db()
        .query_row(r#"SELECT "version","files" FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, [&d], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, &d), 1);
    assert_eq!(version, 3);
    let snap: Value = serde_json::from_str(&excalidash_rs::snapshots::decode_field(&files).unwrap()).unwrap();
    assert_eq!(snap.as_object().unwrap().keys().collect::<Vec<_>>(), ["file-a"]);
}

#[test]
fn reads_compressed_history_and_preserves_it_across_a_restore() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let historical = json!({"viewBackgroundColor": "#abcdef", "selectedElementIds": {}, "customData": "x".repeat(2000)});
    let enc = |v: &str| excalidash_rs::snapshots::encode_field(v, true);
    let app_state = enc(&historical.to_string());
    assert!(app_state.starts_with("br1:"));
    let snap = insert_snapshot(&s, &d, 1, &enc("[]"), &app_state, &enc("{}"));
    let read = c.get(&format!("/drawings/{d}/history/{snap}"));
    assert_eq!(read.status, 200);
    assert_eq!(read.json()["appState"], historical);
    let restore = c.post(&format!("/drawings/{d}/history/{snap}/restore"), json!({"version": 1}));
    assert_eq!(restore.status, 200, "{}", restore.text());
    assert_eq!(restore.json()["appState"], historical);
    assert_eq!(drawing_row(&s, &d).unwrap().2, historical.to_string());
}

#[test]
fn rejects_corrupt_compressed_history_without_creating_a_backup() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let snap = insert_snapshot(&s, &d, 1, "br1:not-brotli", "{}", "{}");
    let r = c.post(&format!("/drawings/{d}/history/{snap}/restore"), json!({"version": 1}));
    assert_eq!(r.status, 500);
    assert_eq!(r.json(), json!({"error": "Internal server error", "message": "An error occurred while processing your request"}));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, &d), 1);
    assert_eq!(drawing_row(&s, &d).unwrap().5, 1);
}

/// FILE_UPLOAD_MAX_MB such that maxDataUrlSize is exactly 128 bytes (2^7 / 2^20).
const MAX_128_BYTES: (&str, &str) = ("FILE_UPLOAD_MAX_MB", "0.0001220703125");

#[test]
fn rejects_oversized_image_saves_without_replacing_existing_image_data() {
    let (s, c, owner) = merge_world(&[MAX_128_BYTES]);
    let original = file_entry("file-a", AAAA);
    let d = drawing_with_files(&s, &owner, json!({"file-a": original}), 1);
    let big = format!("data:image/png;base64,{}", excalidash_rs::util::b64_std(&[0u8; 129]));
    let r = c.put(&format!("/drawings/{d}"), json!({"version": 1, "files": {"file-a": file_entry("file-a", &big)}}));
    assert_eq!(r.status, 413);
    assert_eq!(
        r.json(),
        json!({"error": "Request error", "message": "Image file \"file-a\" exceeds the maximum allowed size of 128 bytes."})
    );
    assert_eq!(drawing_files(&s, &d), json!({"file-a": original}));
    assert_eq!(drawing_row(&s, &d).unwrap().5, 1);
}

#[test]
fn accepts_the_exact_decoded_byte_image_limit() {
    let (s, c, owner) = merge_world(&[MAX_128_BYTES]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let url = format!("data:image/png;base64,{}", excalidash_rs::util::b64_std(&[0u8; 128]));
    let r = c.put(&format!("/drawings/{d}"), json!({"files": {"image": file_entry("image", &url)}}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(drawing_files(&s, &d).get("image").is_some());
}

#[test]
fn exact_limit_image_is_interned_into_a_db_row() {
    let (s, c, owner) = merge_world(&[MAX_128_BYTES]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let url = format!("data:image/png;base64,{}", excalidash_rs::util::b64_std(&[0u8; 128]));
    assert_eq!(c.put(&format!("/drawings/{d}"), json!({"files": {"image": file_entry("image", &url)}})).status, 200);
    assert_eq!(drawing_files(&s, &d)["image"]["dataURL"], json!(format!("/api/files/{d}/image")));
    let (size, data): (i64, Vec<u8>) = s
        .db()
        .query_row(r#"SELECT "sizeBytes","data" FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = 'image'"#, [&d], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!((size, data), (128, vec![0u8; 128]));
}

#[test]
fn returns_409_on_a_stale_version_and_does_not_merge() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({"file-a": file_entry("file-a", AAAA)}), 5);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"file-b": file_entry("file-b", AAAA)}, "version": 2}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["code"], "VERSION_CONFLICT");
    assert_eq!(r.json()["currentVersion"], 5);
    assert_eq!(drawing_files(&s, &d).as_object().unwrap().keys().collect::<Vec<_>>(), ["file-a"]);
}

// ---------------------------------------------------------------------------
// file-retention.integration.ts (scene-update parts, database-bytes mode)

#[test]
fn preserves_ordinary_external_image_references_without_requiring_stored_rows() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let external = json!({"dataURL": "https://external.example/image.png", "mimeType": "image/png"});
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"external": external}}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["files"]["external"], external);
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId" = ?1"#, &d), 0);
}

#[test]
fn rejects_a_managed_reference_whose_bytes_were_reclaimed_before_a_versionless_save() {
    let (s, c, owner) = merge_world(&[]);
    let d = drawing_with_files(&s, &owner, json!({}), 1);
    let image = json!({"dataURL": format!("/api/files/{d}/image"), "mimeType": "image/png"});
    // No DrawingFile row: the managed reference must not be committed.
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"image": image}}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["code"], "VERSION_CONFLICT");
    assert_eq!(r.json()["currentVersion"], 1);
    let row = drawing_row(&s, &d).unwrap();
    assert_eq!((row.3.as_str(), row.5), ("{}", 1));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, &d), 0);
    // Once the bytes exist the same save commits.
    insert_db_file(&s, &d, "image", &[1, 2, 3]);
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [], "files": {"image": image}}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["files"]["image"], image);
}

// ---------------------------------------------------------------------------
// saved-scene-broadcast.integration.ts — observed through a minimal Engine.IO v4
// polling client joined to the drawing room.

struct Polling {
    c: TestClient,
    sid: String,
}

impl Polling {
    fn url(&self) -> String {
        format!("/socket.io/?EIO=4&transport=polling&sid={}", self.sid)
    }
    fn connect(c: TestClient) -> Polling {
        let r = c.get("/socket.io/?EIO=4&transport=polling");
        assert_eq!(r.status, 200, "handshake: {}", r.text());
        let text = r.text();
        assert!(text.starts_with('0'), "{text}");
        let open: Value = serde_json::from_str(&text[1..]).unwrap();
        let p = Polling { c, sid: open["sid"].as_str().unwrap().to_string() };
        p.send("40");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let packets = p.poll();
            if packets.iter().any(|x| x == "2") {
                p.send("3");
            }
            if packets.iter().any(|x| x.starts_with("40")) {
                return p;
            }
            assert!(packets.iter().all(|x| x == "2"), "{packets:?}");
            assert!(std::time::Instant::now() < deadline, "no namespace connect");
        }
    }
    fn send(&self, packet: &str) {
        let r = self.c.send_raw("POST", &self.url(), Some(("text/plain;charset=UTF-8".into(), packet.as_bytes().to_vec())));
        assert_eq!(r.status, 200, "{}", r.text());
    }
    fn poll(&self) -> Vec<String> {
        let r = self.c.get(&self.url());
        assert_eq!(r.status, 200, "{}", r.text());
        r.text().split('\u{1e}').map(str::to_string).collect()
    }
    /// Socket.IO EVENT packets (`42[...]`) decoded as [name, payload].
    fn events_until(&self, name: &str) -> Vec<Value> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
        let mut seen = vec![];
        while std::time::Instant::now() < deadline {
            for p in self.poll() {
                if p == "2" {
                    self.send("3");
                    continue;
                }
                if let Some(rest) = p.strip_prefix("42") {
                    let v: Value = serde_json::from_str(rest).unwrap();
                    let done = v[0] == json!(name);
                    seen.push(v);
                    if done {
                        return seen;
                    }
                }
            }
        }
        panic!("no {name} event; saw {seen:?}");
    }
}

fn broadcast_world() -> (TestServer, TestClient, Polling, String) {
    let s = auth_server();
    let (c, owner) = user(&s, "saved-scene@test.local", "Owner");
    let d = insert_drawing(
        &s,
        &owner,
        NewDrawing {
            name: "Saved scene",
            elements: Some(r#"[{"id":"earlier","version":1}]"#),
            files: Some(r#"{"earlierImage":{"dataURL":"https://example.test/earlier.png"}}"#),
            version: Some(3),
            ..Default::default()
        },
    );
    // The peer is a second (cookie-authenticated) socket of the owner joined to the room.
    let peer = Polling::connect(c.clone_client());
    peer.send(&format!(r#"42["join-room",{{"drawingId":"{d}","user":{{"name":"Peer"}}}}]"#));
    peer.events_until("presence-update");
    (s, c, peer, d)
}

#[test]
fn delivers_the_committed_scene_and_merged_files_to_peers() {
    let (_s, c, peer, d) = broadcast_world();
    let r = c.put(
        &format!("/drawings/{d}"),
        json!({"elements": [{"id": "earlier", "version": 1}, {"id": "new", "version": 1}], "files": {"newImage": {"dataURL": "https://example.test/new.png"}}, "version": 3}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let body = r.json();
    assert!(body["files"].get("earlierImage").is_some());
    assert!(body["files"].get("newImage").is_some());
    let events = peer.events_until("element-update");
    let updates: Vec<&Value> = events.iter().filter(|e| e[0] == "element-update").collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(
        updates[0][1],
        json!({"drawingId": d, "persisted": true, "elements": body["elements"], "files": body["files"], "elementOrder": ["earlier", "new"]})
    );
}

#[test]
fn does_not_broadcast_rejected_or_preview_only_updates() {
    let (_s, c, peer, d) = broadcast_world();
    let r = c.put(&format!("/drawings/{d}"), json!({"elements": [{"id": "stale"}], "version": 2}));
    assert_eq!(r.status, 409);
    let r = c.put(&format!("/drawings/{d}"), json!({"preview": "<svg></svg>"}));
    assert_eq!(r.status, 200);
    // A marker event proves the queue was drained in order: nothing came before it.
    peer.send(&format!(r#"42["user-activity",{{"drawingId":"{d}","isActive":false}}]"#));
    let events = peer.events_until("presence-update");
    assert!(events.iter().all(|e| e[0] != "element-update"), "{events:?}");
}
