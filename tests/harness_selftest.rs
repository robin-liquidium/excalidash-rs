mod common;
use common::*;

#[test]
fn seeded_session_is_authenticated() {
    let s = TestServer::start(&[]);
    let (c, id) = user_session(&s, "alice@example.test", "USER");
    // /drawings requires auth; with the stub router it 404s, but auth must not 401 on the csrf path.
    let r = c.get("/csrf-token");
    assert_eq!(r.status, 200);
    assert!(!id.is_empty());
}
