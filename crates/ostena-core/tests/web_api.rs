//! The web listener against an in-memory store (ADR-0020): the route
//! enumeration test (every refusal on every route of the table), the
//! session cookie, CSRF, security headers, bounds and TLS groups. No
//! database: `tests/web_pg.rs` covers the PostgreSQL store.

#![allow(clippy::unwrap_used, reason = "test")]

mod web_stub;

use std::net::IpAddr;

use hyper::StatusCode;
use ostena_common::api::web::{LoginSessionList, SessionInfo};
use ostena_core::web::routes::{Access, ROUTES, Verb};
use ostena_core::web::session::SessionEnd;
use ostena_core::web::{OPENAPI, SECURITY_HEADERS, WebSettings};
use ostena_crypto::tls::WebGroups;
use ostena_crypto::tls::testing::{Offer, browser_client_config};
use web_stub::{Connection, Fixture, ORIGIN, Reply, bare, cookie, login_body, now, request};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn settings() -> WebSettings {
    WebSettings::new(ORIGIN.into())
}

const ID: &str = "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70";

/// A concrete path for a pattern.
fn concrete(pattern: &str) -> String {
    pattern.replace("{id}", ID)
}

/// A body the route would accept, so that only the check under test fails.
fn body_for(path: &str, method: Verb) -> String {
    match (method, path) {
        (Verb::Post, "/api/v1/session") => login_body("alice"),
        (Verb::Post, "/api/v1/session/reauthenticate") => {
            r#"{"password":"good","totp":"123456"}"#.into()
        }
        (Verb::Delete, "/api/v1/login-sessions/{id}") => r#"{"reason":"test"}"#.into(),
        _ => String::new(),
    }
}

/// Every security header, with its value, and no `Server` header.
fn assert_secured(reply: &Reply, at: &str) {
    for (name, value) in SECURITY_HEADERS {
        assert_eq!(
            reply.headers.get(*name).map(|v| v.to_str().unwrap()),
            Some(*value),
            "{at}: {name}"
        );
    }
    assert!(reply.headers.get("server").is_none(), "{at}: server");
    assert!(reply.headers.get("cache-control").is_some(), "{at}: cache");
    assert!(reply.headers.get("content-encoding").is_none(), "{at}");
}

#[test]
fn public_routes_are_a_closed_list() {
    let public: Vec<_> = ROUTES
        .iter()
        .filter(|r| r.access == Access::Public)
        .map(|r| (r.method, r.path))
        .collect();
    assert_eq!(
        public,
        [
            (Verb::Get, "/"),
            (Verb::Get, "/api/v1/health"),
            (Verb::Post, "/api/v1/csp-report"),
            (Verb::Post, "/api/v1/session"),
        ]
    );
}

/// The enumeration test of ADR-0020: walks the table itself, so that a
/// route added without a test is covered.
#[test]
#[expect(clippy::too_many_lines, reason = "one pass over the whole route table")]
fn every_route_refuses_what_it_must() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        let stub = &f.stub;
        let now = now();
        let (user, d) = cookie();
        stub.insert(d, "alice", |_| {});
        let (admin, d) = cookie();
        stub.insert(d, "root", |_| {});
        let (stale_admin, d) = cookie();
        stub.insert(d, "root", |r| r.authenticated_at = now - 301);
        let (unknown, _) = cookie();
        let (expired, d) = cookie();
        stub.insert(d, "root", |r| {
            r.authenticated_at = now - 100;
            r.last_activity_at = now - 10;
            r.expires_at = now - 1;
        });
        let (revoked, d) = cookie();
        stub.insert(d, "root", |r| r.revoked = true);
        let (disabled, d) = cookie();
        stub.insert(d, "root", |r| r.user_active = false);
        let (idle, d) = cookie();
        stub.insert(d, "root", |r| {
            r.authenticated_at = now - 1000;
            r.last_activity_at = now - 901;
        });
        let refused = [
            None,
            Some(unknown.as_str()),
            Some(expired.as_str()),
            Some(revoked.as_str()),
            Some(disabled.as_str()),
            Some(idle.as_str()),
            Some("not-a-cookie"),
        ];

        for route in ROUTES {
            let method = route.method.method();
            let method = method.as_str();
            let path = concrete(route.path);
            let body = body_for(route.path, route.method);
            let at = format!("{method} {path}");

            if route.access != Access::Public {
                let before = stub.effects();
                for cookie in refused {
                    let reply = f.send(request(method, &path, cookie, &body)).await;
                    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{at} {cookie:?}");
                    assert_eq!(reply.code(), "WEB-E001", "{at} {cookie:?}");
                    assert!(reply.cookie().is_none(), "{at}");
                    assert_secured(&reply, &at);
                }
                assert_eq!(stub.effects(), before, "{at}: no effect without a session");
            }
            if let Access::Role(_) = route.access {
                let before = stub.effects();
                let reply = f.send(request(method, &path, Some(&user), &body)).await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{at}");
                assert_eq!(reply.code(), "WEB-E004", "{at}");
                assert_secured(&reply, &at);
                assert!(stub.effects() <= before + 1, "{at}: at most the activity");
            }
            if route.fresh {
                let reply = f
                    .send(request(method, &path, Some(&stale_admin), &body))
                    .await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{at}");
                assert_eq!(reply.code(), "WEB-E007", "{at}");
            }
            if route.method != Verb::Get && route.csrf {
                let session = (route.access != Access::Public).then_some(admin.as_str());
                let cookie_header = session.map(|c| format!("__Host-ostena_session={c}"));
                let cases: [(&[(&str, &str)], &str); 9] = [
                    (&[("origin", "")], "WEB-E002"),
                    (&[("origin", "https://evil.test")], "WEB-E002"),
                    (&[("origin", "https://core.test/")], "WEB-E002"),
                    (&[("origin", "http://core.test")], "WEB-E002"),
                    (&[("origin", "null")], "WEB-E002"),
                    (&[("sec-fetch-site", "cross-site")], "WEB-E003"),
                    (&[("sec-fetch-site", "same-site")], "WEB-E003"),
                    (&[("content-type", "text/plain")], "WEB-E003"),
                    (
                        &[("content-type", "application/x-www-form-urlencoded")],
                        "WEB-E003",
                    ),
                ];
                let before = stub.effects();
                for (changes, code) in cases {
                    let mut builder = hyper::Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("host", "core.test");
                    for (name, default) in [
                        ("origin", ORIGIN),
                        ("sec-fetch-site", "same-origin"),
                        ("content-type", "application/json"),
                    ] {
                        let value = changes
                            .iter()
                            .find(|(n, _)| *n == name)
                            .map_or(default, |(_, v)| *v);
                        if !value.is_empty() {
                            builder = builder.header(name, value);
                        }
                    }
                    if let Some(c) = &cookie_header {
                        builder = builder.header("cookie", c);
                    }
                    let req = builder
                        .body(http_body_util::Full::new(hyper::body::Bytes::from(
                            body.clone(),
                        )))
                        .unwrap();
                    let reply = f.send(req).await;
                    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{at} {changes:?}");
                    assert_eq!(reply.code(), code, "{at} {changes:?}");
                    assert_secured(&reply, &at);
                }
                // Two Origin headers, one of them right: refused.
                let mut builder = hyper::Request::builder()
                    .method(method)
                    .uri(&path)
                    .header("host", "core.test")
                    .header("origin", ORIGIN)
                    .header("origin", "https://evil.test")
                    .header("content-type", "application/json");
                if let Some(c) = &cookie_header {
                    builder = builder.header("cookie", c);
                }
                let req = builder
                    .body(http_body_util::Full::new(hyper::body::Bytes::from(
                        body.clone(),
                    )))
                    .unwrap();
                assert_eq!(f.send(req).await.code(), "WEB-E002", "{at}");
                // Only the activity of the admin session may have been
                // recorded, nothing on behalf of the requests.
                assert!(
                    stub.effects() <= before + 1,
                    "{at}: CSRF refusal had an effect"
                );
            }
        }

        // Unknown routes: 401 without a session, 404 with one.
        for (method, path) in [
            ("GET", "/api/v1/nothing"),
            ("POST", "/api/v1/nothing"),
            ("PUT", "/api/v1/session"),
            ("GET", "/api/v1/session/x"),
            ("GET", "/api/v1/login-sessions/not-a-uuid"),
            ("GET", "/api/"),
        ] {
            for cookie in refused {
                let reply = f.send(request(method, path, cookie, "")).await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
                assert_eq!(reply.code(), "WEB-E001");
                assert_secured(&reply, path);
            }
            let reply = f.send(request(method, path, Some(&user), "")).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(reply.code(), "WEB-E005");
            assert_secured(&reply, path);
        }
        // The idle session was revoked by the core, with its record.
        let ended = stub.ended.lock().unwrap().clone();
        assert!(ended.iter().all(|(_, e)| *e == SessionEnd::Idle));
        assert_ne!(ended, []);
        f.listener.close();
    });
}

#[test]
fn a_session_lives_rotates_and_ends() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        // A wrong factor: AUTH-E001, no cookie.
        let bad = r#"{"username":"alice","password":"bad","totp":"123456"}"#;
        let reply = f.send(request("POST", "/api/v1/session", None, bad)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "AUTH-E001");
        assert!(reply.headers.get("set-cookie").is_none());

        let reply = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        assert_secured(&reply, "login");
        let set = reply.headers["set-cookie"].to_str().unwrap().to_owned();
        assert!(set.starts_with("__Host-ostena_session="));
        for attribute in ["; Path=/", "; Secure", "; HttpOnly", "; SameSite=Strict"] {
            assert!(set.contains(attribute), "{set}");
        }
        assert!(!set.contains("Domain") && !set.contains("Max-Age") && !set.contains("Expires"));
        let first = reply.cookie().unwrap();
        assert_eq!(first.len(), 43);
        let info = SessionInfo::parse(&reply.body).unwrap();
        assert_eq!(info.username, "alice");
        assert!(info.expires_at <= now() + 8 * 3600);
        assert!(info.idle_expires_at <= now() + 15 * 60);
        // The store keeps the digest, never the value.
        let stored: Vec<_> = f.stub.sessions.lock().unwrap().keys().copied().collect();
        assert_eq!(stored.len(), 1);
        assert_ne!(&stored[0][..], first.as_bytes());

        let reply = f.send(bare("GET", "/api/v1/session", Some(&first))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(SessionInfo::parse(&reply.body).unwrap(), info);
        // The API is never compressed, nor cached.
        let mut get = bare("GET", "/api/v1/session", Some(&first));
        get.headers_mut()
            .insert("accept-encoding", "gzip, br".parse().unwrap());
        let reply = f.send(get).await;
        assert!(reply.headers.get("content-encoding").is_none());
        assert_eq!(reply.headers["cache-control"], "no-store");

        // Re-authentication: a new value, the old one is dead.
        let reply = f
            .send(request(
                "POST",
                "/api/v1/session/reauthenticate",
                Some(&first),
                r#"{"password":"good","totp":"123456"}"#,
            ))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        let second = reply.cookie().unwrap();
        assert_ne!(first, second);
        let reply = f.send(bare("GET", "/api/v1/session", Some(&first))).await;
        assert_eq!(reply.code(), "WEB-E001");
        let reply = f.send(bare("GET", "/api/v1/session", Some(&second))).await;
        assert_eq!(reply.status, StatusCode::OK);
        // A wrong factor on re-authentication: refused, the session stays.
        let reply = f
            .send(request(
                "POST",
                "/api/v1/session/reauthenticate",
                Some(&second),
                r#"{"password":"bad","totp":"123456"}"#,
            ))
            .await;
        assert_eq!(reply.code(), "AUTH-E001");
        assert!(reply.cookie().is_none());

        // The OpenAPI document, to sessions only.
        let reply = f
            .send(bare("GET", "/api/v1/openapi.json", Some(&second)))
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, OPENAPI.as_bytes());

        // Logout: revoked, cookie cleared, site data cleared.
        let reply = f
            .send(request("DELETE", "/api/v1/session", Some(&second), ""))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert_eq!(reply.headers["clear-site-data"], "\"cookies\", \"storage\"");
        let cleared = reply.headers["set-cookie"].to_str().unwrap();
        assert!(cleared.starts_with("__Host-ostena_session=;") && cleared.contains("Max-Age=0"));
        let reply = f.send(bare("GET", "/api/v1/session", Some(&second))).await;
        assert_eq!(reply.code(), "WEB-E001");
        f.listener.close();
    });
}

#[test]
fn bodies_are_bounded_and_strict() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        for (body, status) in [
            ("{", StatusCode::BAD_REQUEST),
            (
                r#"{"username":"alice","password":"good"}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"username":"alice","password":"good","totp":"1","admin":true}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"username":"Alice","password":"good","totp":"123456"}"#,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let reply = f.send(request("POST", "/api/v1/session", None, body)).await;
            assert_eq!(reply.status, status, "{body}");
            assert_eq!(reply.code(), "WEB-E006", "{body}");
        }
        let big = " ".repeat(64 * 1024 + 1);
        let reply = f.send(request("POST", "/api/v1/session", None, &big)).await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(reply.code(), "WEB-E006");
        assert_eq!(f.stub.effects(), 0);
        f.listener.close();
    });
}

#[test]
fn a_session_is_bound_to_its_source() {
    runtime().block_on(async {
        let here: IpAddr = "127.0.0.1".parse().unwrap();
        let there: IpAddr = "127.0.0.2".parse().unwrap();
        let f = Fixture::start(settings(), 600).await;
        let reply = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await;
        let value = reply.cookie().unwrap();
        let mut elsewhere = f.connect_from(there).await;
        let reply = elsewhere
            .send(bare("GET", "/api/v1/session", Some(&value)))
            .await;
        assert_eq!(reply.code(), "WEB-E001");
        // Revoked for good, also from its own source.
        let reply = f
            .connect_from(here)
            .await
            .send(bare("GET", "/api/v1/session", Some(&value)))
            .await;
        assert_eq!(reply.code(), "WEB-E001");
        let ended = f.stub.ended.lock().unwrap().clone();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].1, SessionEnd::SourceChanged);
        f.listener.close();

        // Unbound (development only): another source is accepted.
        let f = Fixture::start(
            WebSettings {
                bind_source: false,
                ..settings()
            },
            600,
        )
        .await;
        let reply = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await;
        let value = reply.cookie().unwrap();
        let reply = f
            .connect_from(there)
            .await
            .send(bare("GET", "/api/v1/session", Some(&value)))
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        f.listener.close();
    });
}

#[test]
fn login_attempts_share_the_limiter() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 2).await;
        let bad = r#"{"username":"alice","password":"bad","totp":"123456"}"#;
        for _ in 0..2 {
            let reply = f.send(request("POST", "/api/v1/session", None, bad)).await;
            assert_eq!(reply.code(), "AUTH-E001");
        }
        let reply = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await;
        assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(reply.code(), "AUTH-E002");
        // The login listener of `ostena login` sees the same counter.
        assert!(matches!(
            f.attempts.admit("127.0.0.1".parse().unwrap(), now()),
            ostena_core::api::Admission::Refused { .. }
        ));
        f.listener.close();
    });
}

#[test]
fn administrators_list_and_revoke_sessions() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        let alice = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await
            .cookie()
            .unwrap();
        let root = f
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("root"),
            ))
            .await
            .cookie()
            .unwrap();
        let reply = f
            .send(bare("GET", "/api/v1/login-sessions", Some(&root)))
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        let list = LoginSessionList::parse(&reply.body).unwrap();
        assert_eq!(list.sessions.len(), 2);
        let target = list
            .sessions
            .iter()
            .find(|s| s.username == "alice")
            .unwrap()
            .id
            .clone();
        let path = format!("/api/v1/login-sessions/{target}");
        let reply = f
            .send(request("DELETE", &path, Some(&root), r#"{"reason":""}"#))
            .await;
        assert_eq!(reply.code(), "WEB-E006");
        let reply = f
            .send(request(
                "DELETE",
                &path,
                Some(&root),
                r#"{"reason":"poste perdu"}"#,
            ))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        let reply = f.send(bare("GET", "/api/v1/session", Some(&alice))).await;
        assert_eq!(reply.code(), "WEB-E001");
        assert_eq!(f.stub.revoked.lock().unwrap()[0].1, "poste perdu");
        let reply = f
            .send(request(
                "DELETE",
                &format!("/api/v1/login-sessions/{ID}"),
                Some(&root),
                r#"{"reason":"x"}"#,
            ))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.code(), "WEB-E005");
        f.listener.close();
    });
}

#[test]
fn public_routes_health_reports_and_portal() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        let reply = f.send(bare("GET", "/api/v1/health", None)).await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert_eq!(reply.body, b"");
        assert_secured(&reply, "health");
        // CSP reports: no Origin needed, their own content types, 8 KiB.
        let report = |content_type: &str, body: String| {
            hyper::Request::builder()
                .method("POST")
                .uri("/api/v1/csp-report")
                .header("host", "core.test")
                .header("content-type", content_type)
                .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
                .unwrap()
        };
        for content_type in ["application/csp-report", "application/reports+json"] {
            let reply = f.send(report(content_type, "{}".into())).await;
            assert_eq!(reply.status, StatusCode::NO_CONTENT, "{content_type}");
        }
        let reply = f.send(report("application/json", "{}".into())).await;
        assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(reply.code(), "WEB-E006");
        let reply = f
            .send(report("application/csp-report", "x".repeat(8 * 1024 + 1)))
            .await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
        // No portal in this binary yet.
        for path in ["/", "/index.html", "/assets/app.js"] {
            let reply = f.send(bare("GET", path, None)).await;
            assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(reply.code(), "WEB-E008");
            assert_secured(&reply, path);
        }
        let reply = f.send(request("POST", "/", None, "")).await;
        assert_eq!(reply.code(), "WEB-E005");
        f.listener.close();
    });
}

#[test]
fn connections_are_persistent() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        let mut connection = f.connect_from("127.0.0.1".parse().unwrap()).await;
        let value = connection
            .send(request(
                "POST",
                "/api/v1/session",
                None,
                &login_body("alice"),
            ))
            .await
            .cookie()
            .unwrap();
        for _ in 0..20 {
            let reply = connection
                .send(bare("GET", "/api/v1/session", Some(&value)))
                .await;
            assert_eq!(reply.status, StatusCode::OK);
        }
        f.listener.close();
    });
}

#[test]
fn browsers_need_a_hybrid_group() {
    runtime().block_on(async {
        let f = Fixture::start(settings(), 600).await;
        let root = f.pki.root_anchor();
        let from: IpAddr = "127.0.0.1".parse().unwrap();
        for offer in [Offer::Secp256r1, Offer::X25519, Offer::Aes128Suite] {
            let config = browser_client_config(offer, &root).unwrap();
            assert!(
                Connection::open(f.addr(), from, config).await.is_err(),
                "{offer:?}"
            );
        }
        let ok = browser_client_config(Offer::X25519MlKem768, &root).unwrap();
        assert!(Connection::open(f.addr(), from, ok).await.is_ok());
        f.listener.close();

        // The classical fallback (refused in production) accepts P-256.
        let f = Fixture::start_with(settings(), 600, WebGroups::HybridThenClassic).await;
        let config = browser_client_config(Offer::Secp256r1, &f.pki.root_anchor()).unwrap();
        let mut c = Connection::open(f.addr(), from, config).await.unwrap();
        assert_eq!(
            c.send(bare("GET", "/api/v1/health", None)).await.status,
            StatusCode::NO_CONTENT
        );
        f.listener.close();
    });
}
