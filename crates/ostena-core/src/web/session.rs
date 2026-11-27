//! Browser sessions of the portal (ADR-0020, § 3): the cookie, the decision
//! on a presented session, and the store behind them.
//!
//! The cookie `__Host-ostena_session` holds 256 random bits drawn by
//! `ostena-crypto`, in base64url; the store keeps only their SHA-256. The
//! decision ([`decide`]) is pure: every store (PostgreSQL, the in-memory
//! store of the tests) goes through it.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyper::header::{COOKIE, HeaderMap};
use ostena_common::api::web::{
    AccessGrant, AccessRequest, LoginSessionList, ReauthenticateRequest, Role, SessionInfo,
    SessionRequest,
};
use ostena_tunnel::Uuid;
use zeroize::Zeroizing;

use super::WebError;
use super::gateway::{GatewayStream, Relayed};
use crate::api::ApiError;

/// Name of the session cookie. The `__Host-` prefix makes the browser
/// require `Secure`, `Path=/` and no `Domain`.
pub const COOKIE_NAME: &str = "__Host-ostena_session";
/// Random bits of a cookie value, in bytes.
pub const COOKIE_BYTES: usize = 32;
/// Length of a cookie value in base64url without padding.
pub const COOKIE_LEN: usize = 43;
/// Header of the background requests of the portal, which do not push the
/// idle deadline back.
pub const BACKGROUND_HEADER: &str = "x-ostena-background";
/// Most seconds since the last authentication for a sensitive action.
pub const REAUTH_SECS: u64 = 300;
/// The last activity is written at most this often, in seconds: the idle
/// deadline is exact to this much, never later.
pub const TOUCH_SECS: u64 = 10;

/// A new cookie value: its text for `Set-Cookie`, and the SHA-256 the
/// store keeps.
///
/// # Errors
///
/// [`ApiError::unavailable`] if the random generator fails.
pub fn new_cookie() -> Result<(Zeroizing<String>, [u8; 32]), ApiError> {
    let raw = Zeroizing::new(
        ostena_crypto::rand::array::<COOKIE_BYTES>().map_err(|_| ApiError::unavailable())?,
    );
    let text = Zeroizing::new(URL_SAFE_NO_PAD.encode(&raw[..]));
    Ok((text, ostena_crypto::sha256::digest(&raw[..])))
}

/// The `Set-Cookie` value for `value`: session cookie (no expiry), sent
/// only over TLS, never to scripts, never on cross-site requests.
pub fn set_cookie(value: &str) -> String {
    format!("{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Strict")
}

/// The `Set-Cookie` value that removes the cookie.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The SHA-256 of the session cookie of `headers`, if exactly one is
/// present and well formed (43 base64url characters, 32 bytes). Several
/// cookies of that name are refused: the browser would not send two.
pub fn presented(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let text = header.to_str().ok()?;
        for pair in text.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE_NAME {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    let value = found?;
    if value.len() != COOKIE_LEN {
        return None;
    }
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).ok()?);
    (raw.len() == COOKIE_BYTES).then(|| ostena_crypto::sha256::digest(&raw))
}

/// A browser session as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Its login session.
    pub login_session: Uuid,
    /// The user.
    pub user: Uuid,
    /// The user name.
    pub username: String,
    /// The display name.
    pub display_name: String,
    /// The roles of the user, sorted.
    pub roles: Vec<Role>,
    /// The source it is bound to ([`crate::api::source_of`]).
    pub source: IpAddr,
    /// End whatever the activity, Unix seconds.
    pub expires_at: u64,
    /// Last authentication with both factors, Unix seconds.
    pub authenticated_at: u64,
    /// Last request that was not a background one, Unix seconds.
    pub last_activity_at: u64,
    /// The login session is revoked.
    pub revoked: bool,
    /// The user is active.
    pub user_active: bool,
}

impl SessionRecord {
    /// End without activity, at `idle_secs` after the last activity, never
    /// after the absolute end.
    pub fn idle_expires_at(&self, idle_secs: u64) -> u64 {
        self.last_activity_at
            .saturating_add(idle_secs)
            .min(self.expires_at)
    }

    /// What `GET /api/v1/session` answers.
    pub fn info(&self, idle_secs: u64) -> SessionInfo {
        SessionInfo {
            login_session: self.login_session.to_string(),
            user: self.user.to_string(),
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            roles: self.roles.clone(),
            authenticated_at: self.authenticated_at,
            expires_at: self.expires_at,
            idle_expires_at: self.idle_expires_at(idle_secs),
        }
    }
}

/// The decision on a presented session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Valid: the request goes on.
    Valid,
    /// Revoked, or its user disabled.
    Revoked,
    /// Past its absolute end.
    Expired,
    /// Presented from another source: it is revoked.
    SourceChanged,
    /// No activity for the idle time: it is revoked.
    Idle,
}

/// Decides on `record` presented at `now` from `source`. The deadlines are
/// the server's: nothing the browser keeps can push them back.
pub fn decide(
    record: &SessionRecord,
    now: u64,
    idle_secs: u64,
    bind_source: bool,
    source: IpAddr,
) -> Verdict {
    if record.revoked || !record.user_active {
        Verdict::Revoked
    } else if now >= record.expires_at {
        Verdict::Expired
    } else if bind_source && record.source != source {
        Verdict::SourceChanged
    } else if now >= record.idle_expires_at(idle_secs) {
        Verdict::Idle
    } else {
        Verdict::Valid
    }
}

/// Why the core ends a browser session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// `DELETE /api/v1/session`.
    Logout,
    /// No activity for the idle time (`web_session.expired`).
    Idle,
    /// Presented from another source (`web_session.source_changed`).
    SourceChanged,
}

/// The store of the browser sessions, and the authentication behind them.
pub trait WebBackend: Send + Sync + 'static {
    /// Checks the two factors of `request` and opens a browser session of
    /// `session_secs` bound to `source`, whose cookie has the SHA-256
    /// `cookie_sha256`. Every refusal is `AUTH-E001`.
    fn open(
        &self,
        request: SessionRequest,
        cookie_sha256: [u8; 32],
        source: IpAddr,
        session_secs: u64,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<SessionRecord, ApiError>> + Send;

    /// Checks the two factors of the user of `session` again and gives the
    /// session the cookie `cookie_sha256`: the old value stops working.
    fn reauthenticate(
        &self,
        session: &SessionRecord,
        request: ReauthenticateRequest,
        cookie_sha256: [u8; 32],
        peer: SocketAddr,
    ) -> impl Future<Output = Result<SessionRecord, ApiError>> + Send;

    /// The session whose cookie has the SHA-256 `cookie_sha256`.
    fn find(
        &self,
        cookie_sha256: [u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRecord>, ApiError>> + Send;

    /// Records an activity of `session` at `now`.
    fn touch(&self, session: Uuid, now: u64) -> impl Future<Output = Result<(), ApiError>> + Send;

    /// Revokes `session` for `end`, seen from `peer`, with its audit record.
    fn end(
        &self,
        session: &SessionRecord,
        end: SessionEnd,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<(), ApiError>> + Send;

    /// The open login sessions, most recent first.
    fn login_sessions(&self) -> impl Future<Output = Result<LoginSessionList, ApiError>> + Send;

    /// Revokes the login session `id` for `reason`, by the administrator
    /// of `by`. `false` if there is no such session; revoking a revoked
    /// one changes nothing.
    fn revoke(
        &self,
        by: &SessionRecord,
        id: Uuid,
        reason: &str,
    ) -> impl Future<Output = Result<bool, ApiError>> + Send;

    /// Decides an access to `account@resource` for `session`, asked from
    /// `peer` (`POST /api/v1/access`): a grant for the browser gateway. A
    /// store without access decision refuses (`GTW-E003`).
    fn grant_access(
        &self,
        session: &SessionRecord,
        request: AccessRequest,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<AccessGrant, WebError>> + Send {
        let _ = (session, request, peer);
        std::future::ready(Err(WebError::refused(
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            crate::access::NO_AGENT,
            crate::access::label(crate::access::NO_AGENT),
        )))
    }

    /// Opens the gateway session of `grant`, presented by `session` from
    /// `peer` on the WebSocket `/api/v1/gateway`: the grant is checked and
    /// marked presented, then the agent opens the session on a browser
    /// stream of the tunnel. A store without access decision refuses
    /// (`GTW-E003`).
    fn open_gateway(
        &self,
        session: &SessionRecord,
        grant: &str,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<GatewayStream, WebError>> + Send {
        let _ = (session, grant, peer);
        std::future::ready(Err(WebError::refused(
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            crate::access::NO_AGENT,
            crate::access::label(crate::access::NO_AGENT),
        )))
    }

    /// Records the end of the gateway session `opened` (session, jti) of
    /// `session`.
    fn gateway_closed(
        &self,
        session: &SessionRecord,
        peer: SocketAddr,
        opened: (Uuid, Uuid),
        ended: &Relayed,
    ) -> impl Future<Output = ()> + Send {
        let _ = (session, peer, opened, ended);
        std::future::ready(())
    }

    /// Revokes the browser sessions idle since before `now - idle_secs`
    /// (`web_session.expired`), so that their gateway sessions are cut
    /// without waiting for a request; returns how many.
    fn sweep(
        &self,
        now: u64,
        idle_secs: u64,
    ) -> impl Future<Output = Result<usize, ApiError>> + Send {
        let _ = (now, idle_secs);
        std::future::ready(Ok(0))
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    fn record() -> SessionRecord {
        SessionRecord {
            login_session: Uuid::from_bytes([1; 16]),
            user: Uuid::from_bytes([2; 16]),
            username: "alice".into(),
            display_name: "Alice".into(),
            roles: vec![],
            source: "192.0.2.1".parse().unwrap(),
            expires_at: 10_000,
            authenticated_at: 1_000,
            last_activity_at: 1_000,
            revoked: false,
            user_active: true,
        }
    }

    #[test]
    fn decisions() {
        let r = record();
        let here: IpAddr = "192.0.2.1".parse().unwrap();
        let there: IpAddr = "192.0.2.9".parse().unwrap();
        assert_eq!(decide(&r, 1_899, 900, true, here), Verdict::Valid);
        assert_eq!(decide(&r, 1_900, 900, true, here), Verdict::Idle);
        assert_eq!(decide(&r, 1_100, 900, true, there), Verdict::SourceChanged);
        assert_eq!(decide(&r, 1_100, 900, false, there), Verdict::Valid);
        assert_eq!(decide(&r, 10_000, 900, true, here), Verdict::Expired);
        let revoked = SessionRecord {
            revoked: true,
            ..r.clone()
        };
        assert_eq!(decide(&revoked, 1_100, 900, true, here), Verdict::Revoked);
        let disabled = SessionRecord {
            user_active: false,
            ..r.clone()
        };
        assert_eq!(decide(&disabled, 1_100, 900, true, here), Verdict::Revoked);
        // The idle deadline never passes the absolute end.
        let late = SessionRecord {
            last_activity_at: 9_500,
            ..r
        };
        assert_eq!(late.idle_expires_at(900), 10_000);
        assert_eq!(late.info(900).idle_expires_at, 10_000);
    }

    #[test]
    fn cookies() {
        let (value, digest) = new_cookie().unwrap();
        assert_eq!(value.len(), COOKIE_LEN);
        let (other, _) = new_cookie().unwrap();
        assert_ne!(*value, *other);
        let set = set_cookie(&value);
        assert!(set.starts_with("__Host-ostena_session="));
        for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(set.contains(attribute), "{attribute}");
        }
        assert!(!set.contains("Domain") && !set.contains("Expires") && !set.contains("Max-Age"));
        assert!(clear_cookie().contains("Max-Age=0"));

        let headers = |values: &[&str]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(COOKIE, HeaderValue::from_str(v).unwrap());
            }
            h
        };
        let good = format!("theme=dark; {COOKIE_NAME}={}", *value);
        assert_eq!(presented(&headers(&[&good])), Some(digest));
        assert_eq!(
            presented(&headers(&["a=b", &format!("{COOKIE_NAME}={}", *value)])),
            Some(digest)
        );
        assert_eq!(presented(&headers(&[])), None);
        assert_eq!(presented(&headers(&["ostena_session=x"])), None);
        let twice = format!("{good}; {COOKIE_NAME}={}", *other);
        assert_eq!(presented(&headers(&[&twice])), None);
        for bad in [
            format!("{COOKIE_NAME}="),
            format!("{COOKIE_NAME}={}", &value[1..]),
            format!("{COOKIE_NAME}={}=", &value[1..]),
            format!("{COOKIE_NAME}={}+", &value[1..]),
        ] {
            assert_eq!(presented(&headers(&[&bad])), None, "{bad}");
        }
    }
}
