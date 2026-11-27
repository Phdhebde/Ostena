//! Messages of the REST API of the portal (`/api/v1`, ADR-0020).
//!
//! Strict JSON: unknown fields, duplicate fields, a body over its bound or
//! a field out of bounds are refused. The contract is
//! `crates/ostena-core/api/openapi.json`, whose examples are checked
//! against these types. The parsers are pure and fuzzed (`web_messages`):
//! the core parses requests, the portal and the tests parse responses.
//!
//! The password and the TOTP code are read into [`SecretString`]s; the
//! caller wipes the body it read.

use serde::{Deserialize, Serialize};

use super::login::{
    MAX_PASSWORD, MAX_TOTP, is_account, is_resource, is_username, is_uuid, secret_from_string,
    secret_len, secret_to_string,
};
use crate::secret::SecretString;

/// Largest JSON body of a request or a response.
pub const MAX_BODY: usize = 64 * 1024;
/// Largest CSP violation report.
pub const MAX_CSP_REPORT: usize = 8 * 1024;
/// Longest display name, in characters.
pub const MAX_DISPLAY_NAME: usize = 128;
/// Longest revocation reason, in characters.
pub const MAX_REASON: usize = 256;
/// Longest error message, in bytes.
pub const MAX_MESSAGE: usize = 512;
/// Most login sessions in one list.
pub const MAX_LISTED_SESSIONS: usize = 500;

/// Why a message is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Not the expected JSON (syntax, unknown, duplicate or missing field,
    /// type).
    #[error("message JSON invalide : {0}")]
    Json(String),
    /// Body larger than [`MAX_BODY`].
    #[error("message de plus de 64 Kio")]
    TooLarge,
    /// A field out of bounds.
    #[error("champ « {0} » invalide : {1}")]
    Field(&'static str, &'static str),
}

fn parse_json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, WireError> {
    if body.len() > MAX_BODY {
        return Err(WireError::TooLarge);
    }
    serde_json::from_slice(body).map_err(|e| WireError::Json(e.to_string()))
}

fn check_factors(password: &SecretString, totp: &SecretString) -> Result<(), WireError> {
    let password = secret_len(password);
    if password == 0 || password > MAX_PASSWORD {
        return Err(WireError::Field("password", "1 à 1024 octets"));
    }
    let totp = secret_len(totp);
    if totp == 0 || totp > MAX_TOTP {
        return Err(WireError::Field("totp", "1 à 16 octets"));
    }
    Ok(())
}

fn is_clean_text(s: &str, max_chars: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max_chars && !s.chars().any(char::is_control)
}

/// Browser → core: `POST /api/v1/session`, name, password and TOTP code in
/// one request. No `Debug`: it holds secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    /// The user name.
    pub username: String,
    /// The password, 1 to 1024 bytes.
    #[serde(
        deserialize_with = "secret_from_string",
        serialize_with = "secret_to_string"
    )]
    pub password: SecretString,
    /// The TOTP code (six digits, checked by the core).
    #[serde(
        deserialize_with = "secret_from_string",
        serialize_with = "secret_to_string"
    )]
    pub totp: SecretString,
}

impl SessionRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        if !is_username(&request.username) {
            return Err(WireError::Field(
                "username",
                "[a-z0-9._-], 1 à 64 octets, commençant par une lettre ou un chiffre",
            ));
        }
        check_factors(&request.password, &request.totp)?;
        Ok(request)
    }
}

/// Browser → core: `POST /api/v1/session/reauthenticate`, the two factors
/// again, for a sensitive action. No `Debug`: it holds secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReauthenticateRequest {
    /// The password, 1 to 1024 bytes.
    #[serde(
        deserialize_with = "secret_from_string",
        serialize_with = "secret_to_string"
    )]
    pub password: SecretString,
    /// The TOTP code.
    #[serde(
        deserialize_with = "secret_from_string",
        serialize_with = "secret_to_string"
    )]
    pub totp: SecretString,
}

impl ReauthenticateRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        check_factors(&request.password, &request.totp)?;
        Ok(request)
    }
}

/// A role of a user in the portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Administration of the users, the groups and the inventory.
    Admin,
    /// Administration of the access rules and the rights (ADR-0022).
    Policy,
    /// Reading of the audit chain, the sessions and their transcripts;
    /// incompatible with the two others (ADR-0022).
    Audit,
}

impl Role {
    /// Every role.
    pub const ALL: [Self; 3] = [Self::Admin, Self::Policy, Self::Audit];

    /// The name stored and sent, e.g. `admin`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Policy => "policy",
            Self::Audit => "audit",
        }
    }

    /// The role named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == name)
    }
}

/// Core → browser: the current browser session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    /// The login session (canonical UUID).
    pub login_session: String,
    /// The user (canonical UUID).
    pub user: String,
    /// The user name.
    pub username: String,
    /// The display name.
    pub display_name: String,
    /// The roles of the user, sorted.
    pub roles: Vec<Role>,
    /// Last authentication with both factors, Unix seconds.
    pub authenticated_at: u64,
    /// End of the session whatever the activity, Unix seconds.
    pub expires_at: u64,
    /// End of the session without activity, Unix seconds (never after
    /// `expires_at`).
    pub idle_expires_at: u64,
}

impl SessionInfo {
    /// Parses and checks a response body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let info: Self = parse_json(body)?;
        if !is_uuid(&info.login_session) {
            return Err(WireError::Field("login_session", "UUID canonique attendu"));
        }
        if !is_uuid(&info.user) {
            return Err(WireError::Field("user", "UUID canonique attendu"));
        }
        if !is_username(&info.username) {
            return Err(WireError::Field("username", "nom d'utilisateur attendu"));
        }
        if !is_clean_text(&info.display_name, MAX_DISPLAY_NAME) {
            return Err(WireError::Field(
                "display_name",
                "1 à 128 caractères, sans caractère de contrôle",
            ));
        }
        if !info.roles.windows(2).all(|w| w[0] < w[1]) {
            return Err(WireError::Field("roles", "rôles triés, sans doublon"));
        }
        if info.idle_expires_at > info.expires_at || info.authenticated_at > info.expires_at {
            return Err(WireError::Field(
                "idle_expires_at",
                "échéances incohérentes avec expires_at",
            ));
        }
        Ok(info)
    }
}

/// How a login session was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// `ostena login` (user certificate).
    Cli,
    /// The portal (browser cookie).
    Web,
}

impl Channel {
    /// The name stored and sent, e.g. `web`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Web => "web",
        }
    }

    /// The channel named `name`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "cli" => Some(Self::Cli),
            "web" => Some(Self::Web),
            _ => None,
        }
    }
}

/// One open login session, in [`LoginSessionList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSessionItem {
    /// The login session (canonical UUID).
    pub id: String,
    /// The user (canonical UUID).
    pub user: String,
    /// The user name.
    pub username: String,
    /// How it was opened.
    pub channel: Channel,
    /// Start, Unix seconds.
    pub started_at: u64,
    /// End whatever the activity, Unix seconds.
    pub expires_at: u64,
}

/// Core → browser: `GET /api/v1/login-sessions`, the open login sessions
/// (not revoked, not expired), most recent first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSessionList {
    /// At most [`MAX_LISTED_SESSIONS`].
    pub sessions: Vec<LoginSessionItem>,
}

impl LoginSessionList {
    /// Parses and checks a response body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let list: Self = parse_json(body)?;
        if list.sessions.len() > MAX_LISTED_SESSIONS {
            return Err(WireError::Field("sessions", "500 sessions au plus"));
        }
        for s in &list.sessions {
            if !is_uuid(&s.id) || !is_uuid(&s.user) {
                return Err(WireError::Field("sessions", "UUID canonique attendu"));
            }
            if !is_username(&s.username) {
                return Err(WireError::Field("username", "nom d'utilisateur attendu"));
            }
            if s.expires_at <= s.started_at {
                return Err(WireError::Field("expires_at", "après started_at"));
            }
        }
        Ok(list)
    }
}

/// Browser → core: `DELETE /api/v1/login-sessions/{id}`, the reason of a
/// revocation by an administrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// 1 to 256 characters, no control character.
    pub reason: String,
}

impl RevokeRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        if !is_clean_text(&request.reason, MAX_REASON) {
            return Err(WireError::Field(
                "reason",
                "1 à 256 caractères, sans caractère de contrôle",
            ));
        }
        Ok(request)
    }
}

/// Length of the text form of a grant (ADR-0004): 184 bytes in base64url
/// without padding. It travels as the subprotocol `ostena-grant.<grant>`.
pub const GRANT_TEXT_LEN: usize = 246;

/// The protocols a browser session may ask for. RDP comes with the display
/// of PR 13 (ADR-0020, § 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessProtocol {
    /// An SSH terminal.
    Ssh,
}

impl AccessProtocol {
    /// The name stored and sent, e.g. `ssh`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
        }
    }
}

/// Browser → core: `POST /api/v1/access`, an access to `account@resource`
/// for the current browser session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    /// The resource (`[a-z0-9][a-z0-9.-]{0,62}`).
    pub resource: String,
    /// The account on the resource.
    pub account: String,
    /// The protocol.
    pub protocol: AccessProtocol,
}

impl AccessRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        if !is_resource(&request.resource) {
            return Err(WireError::Field(
                "resource",
                "[a-z0-9][a-z0-9.-], 1 à 63 octets",
            ));
        }
        if !is_account(&request.account) {
            return Err(WireError::Field(
                "account",
                "1 à 256 octets, sans caractère de contrôle ni espace aux extrémités",
            ));
        }
        Ok(request)
    }
}

/// Core → browser: the grant of an access, to present once, within its
/// validity, in the opening of the WebSocket `/api/v1/gateway`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    /// The grant, text form ([`GRANT_TEXT_LEN`] base64url characters). It
    /// carries the authorisation, never a secret of the target.
    pub grant: String,
    /// The resource.
    pub resource: String,
    /// The account on the resource.
    pub account: String,
    /// The protocol.
    pub protocol: AccessProtocol,
    /// End of validity of the grant, Unix seconds.
    pub expires_at: u64,
    /// Longest session it allows, seconds.
    pub max_session_secs: u32,
}

impl AccessGrant {
    /// Parses and checks a response body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let grant: Self = parse_json(body)?;
        if grant.grant.len() != GRANT_TEXT_LEN
            || !grant
                .grant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(WireError::Field(
                "grant",
                "246 caractères base64url attendus",
            ));
        }
        if !is_resource(&grant.resource) || !is_account(&grant.account) {
            return Err(WireError::Field("resource", "ressource ou compte invalide"));
        }
        if grant.expires_at == 0 || grant.max_session_secs == 0 {
            return Err(WireError::Field(
                "expires_at",
                "échéance et durée non nulles",
            ));
        }
        Ok(grant)
    }
}

/// Core → browser: every refusal. The portal shows the translation of
/// `code`, never `message`, which is for the logs and the tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Stable code, e.g. `WEB-E001`.
    pub code: String,
    /// Message in French, at most 512 bytes.
    pub message: String,
}

impl ErrorBody {
    /// Parses and checks a response body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let error: Self = parse_json(body)?;
        let code_ok = error.code.split_once('-').is_some_and(|(prefix, number)| {
            (2..=4).contains(&prefix.len())
                && prefix.bytes().all(|b| b.is_ascii_uppercase())
                && number.len() == 4
                && number.starts_with('E')
                && number[1..].bytes().all(|b| b.is_ascii_digit())
        });
        if !code_ok {
            return Err(WireError::Field("code", "code stable attendu (XXX-E000)"));
        }
        if error.message.len() > MAX_MESSAGE || error.message.chars().any(char::is_control) {
            return Err(WireError::Field(
                "message",
                "512 octets au plus, sans caractère de contrôle",
            ));
        }
        Ok(error)
    }
}

/// Fuzz entry point (`web_messages`): what is accepted must serialise and
/// parse back to the same value.
///
/// # Panics
///
/// When an accepted message does not round-trip: a finding.
pub fn fuzz(data: &[u8]) {
    if let Ok(r) = SessionInfo::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| SessionInfo::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = LoginSessionList::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(
            again.and_then(|b| LoginSessionList::parse(&b).ok()),
            Some(r)
        );
    }
    if let Ok(r) = RevokeRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| RevokeRequest::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = ErrorBody::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| ErrorBody::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = AccessRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| AccessRequest::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = AccessGrant::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| AccessGrant::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = SessionRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        let back = again.and_then(|b| SessionRequest::parse(&b).ok());
        assert!(back.is_some_and(|b| b.username == r.username));
    }
    if let Ok(r) = ReauthenticateRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert!(again.is_some_and(|b| ReauthenticateRequest::parse(&b).is_ok()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_request_is_strict() {
        let ok = br#"{"username":"alice","password":"pw","totp":"123456"}"#;
        let r = SessionRequest::parse(ok).unwrap();
        assert_eq!(r.username, "alice");
        for bad in [
            &br#"{"username":"alice","password":"pw"}"#[..],
            br#"{"username":"alice","password":"pw","totp":"1","x":1}"#,
            br#"{"username":"alice","username":"bob","password":"pw","totp":"1"}"#,
            br#"{"username":"Alice","password":"pw","totp":"1"}"#,
            br#"{"username":"alice","password":"","totp":"1"}"#,
            br#"{"username":"alice","password":"pw","totp":""}"#,
            br#"{"username":"alice","password":"pw","totp":"12345678901234567"}"#,
        ] {
            assert!(
                SessionRequest::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let big = vec![b' '; MAX_BODY + 1];
        assert_eq!(SessionRequest::parse(&big).err(), Some(WireError::TooLarge));
        assert!(ReauthenticateRequest::parse(br#"{"password":"pw","totp":"1"}"#).is_ok());
        assert!(ReauthenticateRequest::parse(br#"{"password":"pw"}"#).is_err());
    }

    #[test]
    fn responses_are_checked() {
        let info = SessionInfo {
            login_session: "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70".into(),
            user: "5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
            roles: vec![Role::Admin],
            authenticated_at: 100,
            expires_at: 200,
            idle_expires_at: 150,
        };
        let body = serde_json::to_vec(&info).unwrap();
        assert_eq!(SessionInfo::parse(&body).unwrap(), info);
        let mut late = info.clone();
        late.idle_expires_at = 201;
        assert!(SessionInfo::parse(&serde_json::to_vec(&late).unwrap()).is_err());
        let mut twice = info;
        twice.roles = vec![Role::Admin, Role::Admin];
        assert!(SessionInfo::parse(&serde_json::to_vec(&twice).unwrap()).is_err());
        assert!(ErrorBody::parse(br#"{"code":"WEB-E001","message":"x"}"#).is_ok());
        assert!(ErrorBody::parse(br#"{"code":"AUTH-E001","message":"x"}"#).is_ok());
        for bad in [
            "web-E001",
            "WEB-001",
            "WEB-E00a",
            "WEBE0001",
            "W-E001",
            "WEBXY-E001",
            "WEB-E0001",
        ] {
            let body = format!(r#"{{"code":"{bad}","message":"x"}}"#);
            assert!(ErrorBody::parse(body.as_bytes()).is_err(), "{bad}");
        }
        assert!(RevokeRequest::parse(br#"{"reason":"poste perdu"}"#).is_ok());
        assert!(RevokeRequest::parse(br#"{"reason":""}"#).is_err());
        assert!(RevokeRequest::parse(br#"{"reason":"a\nb"}"#).is_err());
    }

    #[test]
    fn access_messages_are_strict() {
        let ok = br#"{"resource":"srv-01","account":"root","protocol":"ssh"}"#;
        let r = AccessRequest::parse(ok).unwrap();
        assert_eq!(
            (r.resource.as_str(), r.account.as_str(), r.protocol),
            ("srv-01", "root", AccessProtocol::Ssh)
        );
        for bad in [
            &br#"{"resource":"srv-01","account":"root"}"#[..],
            br#"{"resource":"srv-01","account":"root","protocol":"rdp"}"#,
            br#"{"resource":"Srv","account":"root","protocol":"ssh"}"#,
            br#"{"resource":"srv-01","account":" root","protocol":"ssh"}"#,
            br#"{"resource":"srv-01","account":"root","protocol":"ssh","x":1}"#,
        ] {
            assert!(
                AccessRequest::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let grant = AccessGrant {
            grant: "A".repeat(GRANT_TEXT_LEN),
            resource: "srv-01".into(),
            account: "root".into(),
            protocol: AccessProtocol::Ssh,
            expires_at: 1_800_000_060,
            max_session_secs: 3600,
        };
        let body = serde_json::to_vec(&grant).unwrap();
        assert_eq!(AccessGrant::parse(&body).unwrap(), grant);
        let edits: [fn(&mut AccessGrant); 3] = [
            |g| g.grant.push('A'),
            |g| g.grant.replace_range(..1, "+"),
            |g| g.max_session_secs = 0,
        ];
        for edit in edits {
            let mut bad = grant.clone();
            edit(&mut bad);
            assert!(AccessGrant::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("policy"), Some(Role::Policy));
        assert_eq!(Role::parse("audit"), Some(Role::Audit));
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{}\"", role.as_str())
            );
        }
        assert_eq!(Role::parse("root"), None);
        assert_eq!(Channel::parse(Channel::Web.as_str()), Some(Channel::Web));
        assert_eq!(Channel::parse(Channel::Cli.as_str()), Some(Channel::Cli));
    }

    proptest::proptest! {
        #[test]
        fn fuzz_never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..256)) {
            fuzz(&data);
        }
    }
}
