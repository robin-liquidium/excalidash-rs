//! server/socket.ts + server/socketAccess.ts — real-time collaboration over Socket.IO.
use serde::Serialize;
use serde_json::{json, Value};
use socketioxide::{
    extract::{AckSender, SocketRef, TryData},
    handler::ConnectHandler,
    SocketIo,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use crate::auth::cookies::ACCESS_TOKEN_COOKIE_NAME;
use crate::authz::{get_drawing_access, Access};
use crate::http::ctx::parse_cookie_header;
use crate::models::BOOTSTRAP_USER_ID;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceUser {
    pub id: String,
    pub name: String,
    pub initials: String,
    pub color: String,
    pub socket_id: String,
    pub is_active: bool,
}

#[derive(Default)]
struct SocketStateInner {
    principal: Option<String>,
    access: HashMap<String, (Access, Instant)>,
    joined_rooms: HashSet<String>,
}

#[derive(Clone, Default)]
struct SocketState(Arc<Mutex<SocketStateInner>>);

fn room_users() -> &'static Mutex<HashMap<String, Vec<PresenceUser>>> {
    static M: OnceLock<Mutex<HashMap<String, Vec<PresenceUser>>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

static APP: OnceLock<AppState> = OnceLock::new();

fn app() -> &'static AppState {
    APP.get().expect("socket app state")
}

const ACCESS_CACHE_TTL: Duration = Duration::from_millis(1500);

fn state_of(s: &SocketRef) -> SocketState {
    match s.extensions.get::<SocketState>() {
        Some(st) => st,
        None => {
            let st = SocketState::default();
            s.extensions.insert(st.clone());
            st
        }
    }
}

fn to_presence_name(v: Option<&Value>) -> String {
    match v.and_then(|v| v.as_str()) {
        Some(s) => {
            let t = crate::util::js_slice(s.trim(), 120);
            if t.is_empty() { "User".into() } else { t }
        }
        None => "User".into(),
    }
}

fn to_presence_initials(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "U".into();
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() >= 2 {
        let first = parts[0].chars().next().map(String::from).unwrap_or_default();
        let last = parts[parts.len() - 1].chars().next().map(String::from).unwrap_or_default();
        return format!("{first}{last}").to_uppercase();
    }
    crate::util::js_slice(trimmed, 2).to_uppercase()
}

fn to_presence_color(v: Option<&Value>) -> String {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^#[0-9a-fA-F]{3,8}$").unwrap());
    match v.and_then(|v| v.as_str()) {
        Some(s) if re.is_match(s.trim()) => s.trim().to_string(),
        _ => "#4f46e5".into(),
    }
}

async fn socket_auth_user_id(st: &AppState, token: Option<String>) -> Option<String> {
    match crate::auth::middleware::get_auth_enabled(&st.db).await {
        Ok(false) => return Some(BOOTSTRAP_USER_ID.to_string()),
        Ok(true) => {}
        Err(_) => return None,
    }
    let token = token?;
    let claims = crate::auth::jwt::decode_any(&token, &st.cfg.jwt_secret)?;
    let uid = claims.get("userId")?.as_str()?.to_string();
    claims.get("email")?.as_str()?;
    if claims.get("type")?.as_str()? != "access" {
        return None;
    }
    let found = st
        .db
        .call(move |c| {
            use rusqlite::OptionalExtension;
            Ok(c
                .query_row(r#"SELECT "id","isActive" FROM "User" WHERE "id" = ?1"#, [&uid], |r| {
                    Ok((r.get::<_, String>(0)?, crate::db::boolean(r, 1)?))
                })
                .optional()?)
        })
        .await
        .ok()??;
    found.1.then_some(found.0)
}

#[derive(Debug)]
struct ConnectError(&'static str);
impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

async fn auth_middleware(s: SocketRef, TryData(auth): TryData<Value>) -> Result<(), ConnectError> {
    let st = app();
    let token_from_auth = auth.ok().and_then(|a| a.get("token").and_then(|t| t.as_str()).map(str::to_string));
    let token_from_cookie = {
        let h = s.req_parts().headers.get("cookie").and_then(|v| v.to_str().ok());
        parse_cookie_header(h).remove(ACCESS_TOKEN_COOKIE_NAME).filter(|v| !v.trim().is_empty())
    };
    let token = token_from_auth.filter(|t| !t.is_empty()).or(token_from_cookie);
    let auth_enabled = match crate::auth::middleware::get_auth_enabled(&st.db).await {
        Ok(v) => v,
        Err(_) => return Err(ConnectError("Authentication failed")),
    };
    let user_id = socket_auth_user_id(st, token).await;
    let state = state_of(&s);
    state.0.lock().unwrap().principal = user_id.clone();
    if user_id.is_some() || auth_enabled {
        // Anonymous sockets are allowed when auth is on; access is enforced on join-room.
        return Ok(());
    }
    Err(ConnectError("Authentication required"))
}

async fn fresh_access(principal: Option<String>, drawing_id: String) -> Access {
    app()
        .db
        .call(move |c| Ok(get_drawing_access(c, principal.as_deref(), &drawing_id, None)?))
        .await
        .unwrap_or(Access::None)
}

async fn cached_or_fresh_access(state: &SocketState, drawing_id: &str) -> Option<Access> {
    let principal = {
        let g = state.0.lock().unwrap();
        if let Some((a, at)) = g.access.get(drawing_id) {
            if at.elapsed() < ACCESS_CACHE_TTL {
                return Some(*a);
            }
        }
        g.principal.clone()
    };
    let access = fresh_access(principal, drawing_id.to_string()).await;
    let mut g = state.0.lock().unwrap();
    if !access.can_view() {
        g.access.remove(drawing_id);
        return None;
    }
    g.access.insert(drawing_id.to_string(), (access, Instant::now()));
    Some(access)
}

fn remove_socket_from_rooms(room_ids: &[String], socket_id: &str) -> Vec<(String, Vec<PresenceUser>)> {
    let mut map = room_users().lock().unwrap();
    let mut changed = vec![];
    for room in room_ids {
        let Some(users) = map.get_mut(room) else { continue };
        let Some(idx) = users.iter().position(|u| u.socket_id == socket_id) else { continue };
        users.remove(idx);
        let snapshot = users.clone();
        if users.is_empty() {
            map.remove(room);
        }
        changed.push((room.clone(), snapshot));
    }
    changed
}

/// Broadcast emits return a future that must be driven, or nothing is sent.
fn emit_presence(io: &SocketIo, room: &str, users: &[PresenceUser]) {
    let (io, room, users) = (io.clone(), room.to_string(), users.to_vec());
    tokio::spawn(async move {
        let _ = io.to(room).emit("presence-update", &users).await;
    });
}

fn drop_drawing_access(s: &SocketRef, io: &SocketIo, state: &SocketState, drawing_id: &str) {
    let room = format!("drawing_{drawing_id}");
    for (r, users) in remove_socket_from_rooms(&[room.clone()], &s.id.to_string()) {
        emit_presence(io, &r, &users);
    }
    state.0.lock().unwrap().joined_rooms.remove(&room);
    s.leave(room);
}

fn has_access_entry(state: &SocketState, drawing_id: &str) -> bool {
    state.0.lock().unwrap().access.contains_key(drawing_id)
}

async fn on_connect(s: SocketRef, io: SocketIo) {
    let state = state_of(&s);

    {
        let (state, io) = (state.clone(), io.clone());
        s.on("join-room", async move |s: SocketRef, TryData(data): TryData<Value>, ack: AckSender| {
            let data = data.unwrap_or(Value::Null);
            let Some(drawing_id) = data.get("drawingId").and_then(|v| v.as_str()).map(str::to_string) else {
                // Upstream would query with an undefined id → no access.
                let _ = s.emit("error", &json!({"message": "You do not have access to this drawing"}));
                return;
            };
            let user = data.get("user").cloned().unwrap_or(Value::Null);
            if cached_or_fresh_access(&state, &drawing_id).await.is_none() {
                let _ = s.emit("error", &json!({"message": "You do not have access to this drawing"}));
                return;
            }
            let room = format!("drawing_{drawing_id}");
            s.join(room.clone());
            state.0.lock().unwrap().joined_rooms.insert(room.clone());
            let sid = s.id.to_string();
            let principal = state.0.lock().unwrap().principal.clone();
            let mut trusted_name = to_presence_name(user.get("name"));
            let trusted_id = match principal {
                None => crate::util::js_slice(&format!("anon:{sid}"), 200),
                Some(uid) if uid != BOOTSTRAP_USER_ID => {
                    let account = app()
                        .db
                        .call(move |c| {
                            use rusqlite::OptionalExtension;
                            Ok(c
                                .query_row(r#"SELECT "id","name" FROM "User" WHERE "id" = ?1"#, [&uid], |r| {
                                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                                })
                                .optional()?)
                        })
                        .await;
                    match account {
                        Ok(Some((id, name))) => {
                            trusted_name = to_presence_name(Some(&Value::String(name)));
                            id
                        }
                        Ok(None) => crate::util::js_slice(&format!("anon:{sid}"), 200),
                        Err(e) => {
                            eprintln!("Error in join-room handler: {e}");
                            let _ = s.emit("error", &json!({"message": "Failed to join room"}));
                            return;
                        }
                    }
                }
                Some(_) => crate::util::js_slice(&format!("anon:{sid}"), 200),
            };
            let new_user = PresenceUser {
                id: trusted_id,
                initials: to_presence_initials(&trusted_name),
                name: trusted_name,
                color: to_presence_color(user.get("color")),
                socket_id: sid.clone(),
                is_active: true,
            };
            let users = {
                let mut map = room_users().lock().unwrap();
                let list = map.entry(room.clone()).or_default();
                list.retain(|u| u.socket_id != sid);
                list.push(new_user.clone());
                list.clone()
            };
            let _ = io.to(room.clone()).emit("presence-update", &users).await;
            let _ = ack.send(&json!({
                "user": {
                    "id": new_user.id,
                    "name": new_user.name,
                    "initials": new_user.initials,
                    "color": new_user.color,
                }
            }));
        });
    }

    {
        let (state, io) = (state.clone(), io.clone());
        s.on("cursor-move", async move |s: SocketRef, TryData(data): TryData<Value>| {
            let Ok(Value::Object(mut data)) = data else {
                return;
            };
            let Some(drawing_id) = data.get("drawingId").and_then(|v| v.as_str()).map(str::to_string) else { return };
            if !has_access_entry(&state, &drawing_id) {
                return;
            }
            if cached_or_fresh_access(&state, &drawing_id).await.is_none() {
                drop_drawing_access(&s, &io, &state, &drawing_id);
                return;
            }
            let room = format!("drawing_{drawing_id}");
            let sid = s.id.to_string();
            let me = room_users().lock().unwrap().get(&room).and_then(|u| u.iter().find(|u| u.socket_id == sid).cloned());
            let Some(me) = me else { return };
            data.insert("drawingId".into(), Value::String(drawing_id));
            data.insert("userId".into(), Value::String(me.id));
            data.insert("username".into(), Value::String(me.name));
            data.insert("color".into(), Value::String(me.color));
            let _ = s.to(room).volatile().emit("cursor-move", &Value::Object(data)).await;
        });
    }

    {
        let (state, io) = (state.clone(), io.clone());
        s.on("element-update", async move |s: SocketRef, TryData(data): TryData<Value>| {
            let Ok(data) = data else { return };
            let Some(drawing_id) = data.get("drawingId").and_then(|v| v.as_str()).map(str::to_string) else { return };
            if !has_access_entry(&state, &drawing_id) {
                return;
            }
            // Mutations bypass the access cache.
            let principal = state.0.lock().unwrap().principal.clone();
            let did = drawing_id.clone();
            let fresh = app().db.call(move |c| Ok(get_drawing_access(c, principal.as_deref(), &did, None)?)).await;
            let access = match fresh {
                Ok(a) => a,
                Err(e) => {
                    state.0.lock().unwrap().access.remove(&drawing_id);
                    eprintln!("Failed to revalidate socket edit access: {e}");
                    return;
                }
            };
            if !access.can_view() {
                state.0.lock().unwrap().access.remove(&drawing_id);
                drop_drawing_access(&s, &io, &state, &drawing_id);
                return;
            }
            state.0.lock().unwrap().access.insert(drawing_id.clone(), (access, Instant::now()));
            if !access.can_edit() {
                let _ = s.emit("error", &json!({"message": "Read-only access: cannot edit this drawing"}));
                return;
            }
            let _ = s.to(format!("drawing_{drawing_id}")).emit("element-update", &data).await;
        });
    }

    {
        let (state, io) = (state.clone(), io.clone());
        s.on("user-activity", async move |s: SocketRef, TryData(data): TryData<Value>| {
            let data = data.unwrap_or(Value::Null);
            let Some(drawing_id) = data.get("drawingId").and_then(|v| v.as_str()).map(str::to_string) else { return };
            if !has_access_entry(&state, &drawing_id) {
                return;
            }
            if cached_or_fresh_access(&state, &drawing_id).await.is_none() {
                drop_drawing_access(&s, &io, &state, &drawing_id);
                return;
            }
            let is_active = data.get("isActive").cloned().unwrap_or(Value::Null);
            let room = format!("drawing_{drawing_id}");
            let sid = s.id.to_string();
            let users = {
                let mut map = room_users().lock().unwrap();
                match map.get_mut(&room) {
                    Some(users) => match users.iter_mut().find(|u| u.socket_id == sid) {
                        Some(u) => {
                            // JS assigns whatever was sent; coerce to bool for the typed struct.
                            u.is_active = is_active.as_bool().unwrap_or(!is_active.is_null() && is_active != Value::from(0));
                            Some(users.clone())
                        }
                        None => None,
                    },
                    None => None,
                }
            };
            if let Some(users) = users {
                emit_presence(&io, &room, &users);
            }
        });
    }

    {
        let (state, io) = (state.clone(), io.clone());
        s.on_disconnect(async move |s: SocketRef| {
            let rooms: Vec<String> = state.0.lock().unwrap().joined_rooms.iter().cloned().collect();
            for (room, users) in remove_socket_from_rooms(&rooms, &s.id.to_string()) {
                emit_presence(&io, &room, &users);
            }
            let mut g = state.0.lock().unwrap();
            g.joined_rooms.clear();
            g.access.clear();
        });
    }
}

/// Register handlers on the default namespace.
pub fn register(io: &SocketIo, st: AppState) {
    let _ = APP.set(st);
    io.ns("/", on_connect.with(auth_middleware));
}

/// socketHandlers.revalidateDrawingAccess(drawingId): kick sockets that lost access.
pub async fn revalidate_drawing_access(st: &AppState, drawing_id: &str) {
    let Some(io) = st.io() else { return };
    let room = format!("drawing_{drawing_id}");
    let sockets = io.to(room.clone()).sockets();
    for s in sockets {
        let state = state_of(&s);
        let principal = {
            let mut g = state.0.lock().unwrap();
            g.access.remove(drawing_id);
            g.principal.clone()
        };
        let did = drawing_id.to_string();
        let access = match st.db.call(move |c| Ok(get_drawing_access(c, principal.as_deref(), &did, None)?)).await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to revalidate drawing socket access: {e}");
                Access::None
            }
        };
        if !access.can_view() {
            for (r, users) in remove_socket_from_rooms(&[room.clone()], &s.id.to_string()) {
                emit_presence(io, &r, &users);
            }
            state.0.lock().unwrap().joined_rooms.remove(&room);
            let _ = s.emit("error", &json!({"message": "Your access to this drawing was revoked"}));
            let _ = s.disconnect();
        } else {
            state.0.lock().unwrap().access.insert(drawing_id.to_string(), (access, Instant::now()));
        }
    }
}

/// Emit an event to everyone in a drawing room (used by HTTP routes).
pub fn emit_to_drawing(st: &AppState, drawing_id: &str, event: &'static str, payload: &Value) {
    if let Some(io) = st.io() {
        let (io, room, payload) = (io.clone(), format!("drawing_{drawing_id}"), payload.clone());
        tokio::spawn(async move {
            let _ = io.to(room).emit(event, &payload).await;
        });
    }
}
