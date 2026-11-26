//! The static route table of the web listener (ADR-0020, § 2).
//!
//! [`ROUTES`] is at once the router and the list that the tests walk: the
//! enumeration test checks every refusal on every route, and the `OpenAPI`
//! test checks that `api/openapi.json` describes exactly these routes. A
//! path is made of fixed segments and typed parameters (`{id}`, a
//! canonical UUID), never a wildcard.

use hyper::Method;
use ostena_common::api::web::Role;
use ostena_tunnel::Uuid;

/// The methods of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `GET`, never an effect.
    Get,
    /// `POST`.
    Post,
    /// `DELETE`.
    Delete,
}

impl Verb {
    /// The HTTP method.
    pub fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Delete => Method::DELETE,
        }
    }

    /// Lower-case name, as in `OpenAPI`.
    pub const fn openapi(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Delete => "delete",
        }
    }
}

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone: a closed list, checked by the tests.
    Public,
    /// A valid browser session.
    Session,
    /// A valid browser session whose user has the role.
    Role(Role),
}

/// What a route does; the dispatch is a `match` on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    /// The root of the portal.
    Portal,
    /// `204`, no body.
    Health,
    /// A CSP violation report, logged at a limited rate.
    CspReport,
    /// Opens a browser session (name, password, TOTP).
    Login,
    /// The current session.
    WhoAmI,
    /// Closes the current session.
    Logout,
    /// Both factors again: a new cookie value.
    Reauthenticate,
    /// The `OpenAPI` document.
    OpenApi,
    /// The open login sessions.
    ListLoginSessions,
    /// Revokes a login session.
    RevokeLoginSession,
}

/// One route.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Method.
    pub method: Verb,
    /// Path pattern, as written in the `OpenAPI` document.
    pub path: &'static str,
    /// Who may call it.
    pub access: Access,
    /// The CSRF checks apply to it when its method changes state: only the
    /// CSP reports, sent by the browser itself, are exempt.
    pub csrf: bool,
    /// It needs an authentication of less than five minutes (`WEB-E007`).
    pub fresh: bool,
    /// Largest body.
    pub max_body: usize,
    /// What it does.
    pub handler: Handler,
}

const JSON: usize = ostena_common::api::web::MAX_BODY;

const fn route(method: Verb, path: &'static str, access: Access, handler: Handler) -> Route {
    Route {
        method,
        path,
        access,
        csrf: true,
        fresh: false,
        max_body: JSON,
        handler,
    }
}

/// Every route of the web listener.
pub static ROUTES: &[Route] = &[
    route(Verb::Get, "/", Access::Public, Handler::Portal),
    route(Verb::Get, "/api/v1/health", Access::Public, Handler::Health),
    Route {
        csrf: false,
        max_body: ostena_common::api::web::MAX_CSP_REPORT,
        ..route(
            Verb::Post,
            "/api/v1/csp-report",
            Access::Public,
            Handler::CspReport,
        )
    },
    route(
        Verb::Post,
        "/api/v1/session",
        Access::Public,
        Handler::Login,
    ),
    route(
        Verb::Get,
        "/api/v1/session",
        Access::Session,
        Handler::WhoAmI,
    ),
    route(
        Verb::Delete,
        "/api/v1/session",
        Access::Session,
        Handler::Logout,
    ),
    route(
        Verb::Post,
        "/api/v1/session/reauthenticate",
        Access::Session,
        Handler::Reauthenticate,
    ),
    route(
        Verb::Get,
        "/api/v1/openapi.json",
        Access::Session,
        Handler::OpenApi,
    ),
    route(
        Verb::Get,
        "/api/v1/login-sessions",
        Access::Role(Role::Admin),
        Handler::ListLoginSessions,
    ),
    Route {
        fresh: true,
        ..route(
            Verb::Delete,
            "/api/v1/login-sessions/{id}",
            Access::Role(Role::Admin),
            Handler::RevokeLoginSession,
        )
    },
];

/// The typed parameters of a matched path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Params {
    /// `{id}`.
    pub id: Option<Uuid>,
}

/// Matches `path` against `pattern`.
fn matches(pattern: &str, path: &str) -> Option<Params> {
    let mut params = Params::default();
    let mut want = pattern.split('/');
    let mut got = path.split('/');
    loop {
        match (want.next(), got.next()) {
            (None, None) => return Some(params),
            (Some("{id}"), Some(segment)) => {
                // Canonical form only: one spelling per resource.
                if !ostena_common::api::login::is_uuid(segment) {
                    return None;
                }
                params.id = Some(Uuid::parse(segment)?);
            }
            (Some(a), Some(b)) if a == b => {}
            _ => return None,
        }
    }
}

/// The route of `method` and `path`, with its parameters. `HEAD` is never
/// routed: the API has no use for it.
pub fn find(method: &Method, path: &str) -> Option<(&'static Route, Params)> {
    ROUTES
        .iter()
        .filter(|r| r.method.method() == *method)
        .find_map(|r| matches(r.path, path).map(|p| (r, p)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_matched_exactly() {
        let id = "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70";
        let (route, params) =
            find(&Method::DELETE, &format!("/api/v1/login-sessions/{id}")).unwrap();
        assert_eq!(route.handler, Handler::RevokeLoginSession);
        assert_eq!(params.id, Uuid::parse(id));
        for path in [
            "/api/v1/login-sessions/0B8F4C1E-7A52-4D0E-9F3B-2C6D1A9E8F70",
            "/api/v1/login-sessions/x",
            "/api/v1/login-sessions/",
            "/api/v1/login-sessions",
        ] {
            assert!(find(&Method::DELETE, path).is_none(), "{path}");
        }
        for path in [
            "/api/v1/session/",
            "/api/v1//session",
            "/api/v1/session/x",
            "/API/v1/session",
        ] {
            assert!(find(&Method::GET, path).is_none(), "{path}");
        }
        assert!(find(&Method::PUT, "/api/v1/session").is_none());
        assert!(find(&Method::HEAD, "/api/v1/health").is_none());
        assert_eq!(find(&Method::GET, "/").unwrap().0.handler, Handler::Portal);
    }

    #[test]
    fn the_table_is_sound() {
        for (i, r) in ROUTES.iter().enumerate() {
            assert!(r.path.starts_with('/'), "{}", r.path);
            // No two routes for one method and path.
            assert!(
                !ROUTES[..i]
                    .iter()
                    .any(|o| o.method == r.method && o.path == r.path),
                "{:?} {}",
                r.method,
                r.path
            );
            // The CSRF exemption is a closed list.
            assert!(r.csrf || r.handler == Handler::CspReport, "{}", r.path);
            // A fresh authentication only makes sense with a session.
            assert!(!r.fresh || r.access != Access::Public, "{}", r.path);
            // Every route but the portal root is under /api/v1.
            assert!(
                r.path == "/" || r.path.starts_with("/api/v1/"),
                "{}",
                r.path
            );
        }
    }
}
