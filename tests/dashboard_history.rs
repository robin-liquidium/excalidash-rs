//! Port of history-restore-validation.integration.ts plus history route branches.
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

fn snapshot_rows(s: &TestServer, drawing: &str) -> Vec<(String, i64, String, String, String, i64)> {
    let c = s.db();
    let mut st = c
        .prepare(r#"SELECT "id","version","elements","appState","files","createdAt" FROM "DrawingSnapshot" WHERE "drawingId" = ?1 ORDER BY "id""#)
        .unwrap();
    st.query_map([drawing], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn rejects_invalid_snapshots_without_changing_live_data_or_history() {
    let s = auth_server();
    let (c, uid) = user(&s, "history-validation@test.local", "History owner");
    let padded = excalidash_rs::snapshots::encode_field(&format!("{{\"padding\":\"{}\"}}", "x".repeat(2000)), true);
    assert!(padded.starts_with("br1:"));
    let cases: Vec<(&str, String)> = vec![
        ("elements", "not-json".into()),
        ("elements", "{}".into()),
        ("elements", "null".into()),
        ("appState", "not-json".into()),
        ("appState", "[]".into()),
        ("appState", "null".into()),
        ("files", "not-json".into()),
        ("files", "[]".into()),
        ("files", "null".into()),
        ("elements", padded),
    ];
    for (field, raw) in cases {
        let d = insert_drawing(
            &s,
            &uid,
            NewDrawing {
                name: "Keep this scene",
                elements: Some(r#"[{"id":"keep","type":"rectangle","version":2}]"#),
                app_state: Some(r##"{"viewBackgroundColor":"#abcdef"}"##),
                files: Some(r#"{"image":{"dataURL":"data:image/png;base64,AAAA"}}"#),
                version: Some(7),
                ..Default::default()
            },
        );
        let before = drawing_row(&s, &d);
        let (mut e, mut a, mut f) = ("[]".to_string(), "{}".to_string(), "{}".to_string());
        match field {
            "elements" => e = raw.clone(),
            "appState" => a = raw.clone(),
            _ => f = raw.clone(),
        }
        let snap = insert_snapshot(&s, &d, 1, &e, &a, &f);
        let snaps_before = snapshot_rows(&s, &d);
        let r = c.post(&format!("/drawings/{d}/history/{snap}/restore"), json!({}));
        assert_eq!(r.status, 400, "{field}={raw}: {}", r.text());
        assert_eq!(
            r.json(),
            json!({"error": "Invalid drawing history snapshot", "message": "The snapshot cannot be restored without losing drawing data."})
        );
        assert_eq!(drawing_row(&s, &d), before, "{field}");
        assert_eq!(snapshot_rows(&s, &d), snaps_before, "{field}");
    }
}

#[test]
fn history_list_read_restore_and_errors() {
    let s = auth_server();
    let (c, uid) = user(&s, "historian@test.local", "Historian");
    let (v, vid) = user(&s, "history-viewer@test.local", "Viewer");
    let d = insert_drawing(&s, &uid, NewDrawing { name: "H", elements: Some(r#"[{"id":"v1"}]"#), collection_id: None, ..Default::default() });

    // Two scene saves → two snapshots (v1, v2).
    assert_eq!(c.put(&format!("/drawings/{d}"), json!({"elements": [{"id": "v2"}]})).json()["version"], 2);
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(c.put(&format!("/drawings/{d}"), json!({"elements": [{"id": "v3"}]})).json()["version"], 3);

    let list = c.get(&format!("/drawings/{d}/history")).json();
    assert_eq!(list["totalCount"], 2);
    let versions: Vec<i64> = list["snapshots"].as_array().unwrap().iter().map(|s| s["version"].as_i64().unwrap()).collect();
    assert_eq!(versions, vec![2, 1]);
    let keys: Vec<&String> = list["snapshots"][0].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "version", "createdAt"]);
    let page = c.get(&format!("/drawings/{d}/history?limit=1&offset=1")).json();
    assert_eq!(page["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(page["snapshots"][0]["version"], 1);
    for bad in ["limit=0", "limit=1.5", "offset=-1", "limit=abc", "limit=1&limit=2", "limit="] {
        assert_eq!(c.get(&format!("/drawings/{d}/history?{bad}")).json(), json!({"error": "Invalid history pagination"}), "{bad}");
    }
    assert_eq!(c.get(&format!("/drawings/{d}/history?limit=999")).status, 200);

    // Read one snapshot.
    let oldest = list["snapshots"][1]["id"].as_str().unwrap().to_string();
    let snap = c.get(&format!("/drawings/{d}/history/{oldest}")).json();
    let keys: Vec<&String> = snap.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "drawingId", "version", "elements", "appState", "files", "createdAt"]);
    assert_eq!(snap["elements"], json!([{"id": "v1"}]));
    assert_eq!(c.get(&format!("/drawings/{d}/history/nope")).json(), json!({"error": "Snapshot not found"}));

    // Access: strangers get 404; viewers can read but not restore.
    let (stranger, _) = user(&s, "stranger@test.local", "Stranger");
    assert_eq!(stranger.get(&format!("/drawings/{d}/history")).json(), json!({"error": "Drawing not found"}));
    insert_permission(&s, &d, &vid, "view", &uid);
    assert_eq!(v.get(&format!("/drawings/{d}/history")).status, 200);
    assert_eq!(v.post(&format!("/drawings/{d}/history/{oldest}/restore"), json!({})).json(), json!({"error": "Drawing not found"}));

    // Restore snapshots the current state first, clears the preview and bumps the version.
    s.db().execute(r#"UPDATE "Drawing" SET "preview" = '<svg/>' WHERE "id" = ?1"#, [&d]).unwrap();
    let r = c.post(&format!("/drawings/{d}/history/{oldest}/restore"), json!({}));
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    assert_eq!(b["elements"], json!([{"id": "v1"}]));
    assert_eq!(b["version"], 4);
    assert_eq!(b["preview"], Value::Null);
    assert_eq!(b["accessLevel"], "owner");
    assert_eq!(c.get(&format!("/drawings/{d}/history")).json()["totalCount"], 3);
    assert_eq!(c.post(&format!("/drawings/{d}/history/nope/restore"), json!({})).json(), json!({"error": "Snapshot not found"}));
}
