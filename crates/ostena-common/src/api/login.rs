//! Messages of the login API (`ostena login`, ADR-0010 step 1, ADR-0015).
//!
//! Strict JSON over HTTPS: unknown fields, duplicate fields, a body over
//! [`MAX_BODY`] or a field out of bounds are refused. The parsers are pure
//! and fuzzed (`login_messages`): the core parses requests, the client parses
//! responses, and both come from the network.
//!
//! The password and the TOTP code are read into [`SecretString`]s. The
//! intermediate buffers of the JSON parser are not wiped; the caller wipes
//! the body it read.

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Version of the login protocol.
pub const PROTOCOL: u16 = 1;
/// Path of the login request.
pub const LOGIN_PATH: &str = "/v1/login";
/// Path of the logout request.
pub const LOGOUT_PATH: &str = "/v1/logout";
/// Path of the list of the user's SSH accesses (`ostena config ssh`).
pub const SSH_HOSTS_PATH: &str = "/v1/ssh-hosts";
/// Largest body, in either direction.
pub const MAX_BODY: usize = 16 * 1024;
/// Longest user name, in bytes.
pub const MAX_USERNAME: usize = 64;
/// Longest password, in bytes (as `ostena_crypto::password`).
pub const MAX_PASSWORD: usize = 1024;
/// Longest TOTP field accepted by the parser; the code itself has 6 digits.
pub const MAX_TOTP: usize = 16;
/// Longest login session, in seconds (8 h).
pub const MAX_SESSION_SECS: u64 = 8 * 3600;
/// Margin of a certificate validity beyond the session: its start is set
/// back for the clocks (5 min at most, as `ostena_ssh::cert`).
pub const VALIDITY_MARGIN_SECS: u64 = 300;
/// Longest certificate or public key line.
pub const MAX_SSH_LINE: usize = 8192;
/// Longest error message.
pub const MAX_MESSAGE: usize = 512;
/// Most host patterns.
pub const MAX_SSH_HOSTS: usize = 16;
/// Largest body of an [`SshHostsResponse`].
pub const MAX_HOSTS_BODY: usize = 256 * 1024;
/// Most accesses in an [`SshHostsResponse`].
pub const MAX_SSH_ACCESSES: usize = 512;
/// Longest target account, in bytes (as the inventory).
pub const MAX_ACCOUNT: usize = 256;

/// Why a message is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Not the expected JSON (syntax, unknown or missing field, type).
    #[error("message JSON invalide : {0}")]
    Json(String),
    /// Body larger than [`MAX_BODY`] ([`MAX_HOSTS_BODY`] for a list of
    /// accesses).
    #[error("message trop long")]
    TooLarge,
    /// Another protocol version.
    #[error("version de protocole {0} non prise en charge (attendu : 1)")]
    Protocol(u16),
    /// A field out of bounds.
    #[error("champ « {0} » invalide : {1}")]
    Field(&'static str, &'static str),
}

/// A user name: `[a-z0-9._-]`, 1 to 64 bytes, starting with a letter or
/// a digit.
pub fn is_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_USERNAME
        && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// A canonical UUID: 36 lower-case characters, `8-4-4-4-12`.
pub fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// Printable ASCII, no control character: SSH lines and host patterns.
fn is_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(super) fn secret_from_string<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<SecretString, D::Error> {
    let text = String::deserialize(d)?;
    Ok(SecretString::from(text))
}

pub(super) fn secret_to_string<S: Serializer>(
    value: &SecretString,
    s: S,
) -> Result<S::Ok, S::Error> {
    // SECRET-EXPOSURE: written into the request body, sent over TLS once.
    #[expect(clippy::disallowed_methods)]
    let text = value.expose_secret();
    s.serialize_str(text)
}

pub(super) fn secret_len(value: &SecretString) -> usize {
    // SECRET-EXPOSURE: only the length is read.
    #[expect(clippy::disallowed_methods)]
    let len = value.expose_secret().len();
    len
}

fn parse_json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, WireError> {
    parse_json_within(body, MAX_BODY)
}

fn parse_json_within<'a, T: Deserialize<'a>>(body: &'a [u8], max: usize) -> Result<T, WireError> {
    if body.len() > max {
        return Err(WireError::TooLarge);
    }
    let value: T = serde_json::from_slice(body).map_err(|e| WireError::Json(e.to_string()))?;
    Ok(value)
}

fn check_protocol(protocol: u16) -> Result<(), WireError> {
    if protocol == PROTOCOL {
        Ok(())
    } else {
        Err(WireError::Protocol(protocol))
    }
}

/// Client → core: `POST /v1/login`. No `Debug`: it holds secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// [`PROTOCOL`].
    pub protocol: u16,
    /// The user name ([`is_username`]).
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
    /// The new public key: SEC1 uncompressed P-256 point (65 bytes),
    /// base64url without padding.
    pub p256_public: String,
    /// Requested session length, at most the core maximum (8 h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

impl LoginRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        check_protocol(request.protocol)?;
        if !is_username(&request.username) {
            return Err(WireError::Field(
                "username",
                "[a-z0-9._-], 1 à 64 octets, commençant par une lettre ou un chiffre",
            ));
        }
        let password = secret_len(&request.password);
        if password == 0 || password > MAX_PASSWORD {
            return Err(WireError::Field("password", "1 à 1024 octets"));
        }
        let totp = secret_len(&request.totp);
        if totp == 0 || totp > MAX_TOTP {
            return Err(WireError::Field("totp", "1 à 16 octets"));
        }
        // 65 bytes in base64url without padding: 87 characters.
        if request.p256_public.len() != 87 || !is_base64url(&request.p256_public) {
            return Err(WireError::Field(
                "p256_public",
                "point P-256 non compressé de 65 octets en base64url",
            ));
        }
        if let Some(ttl) = request.ttl_secs
            && !(60..=MAX_SESSION_SECS).contains(&ttl)
        {
            return Err(WireError::Field("ttl_secs", "de 60 à 28800 secondes"));
        }
        Ok(request)
    }
}

/// Core → client: the session and its certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginResponse {
    /// [`PROTOCOL`].
    pub protocol: u16,
    /// The login session (canonical UUID), key identifier of the certificate.
    pub login_session: String,
    /// The user (canonical UUID), principal of the certificate.
    pub user: String,
    /// The OpenSSH user certificate line
    /// (`ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA… comment`).
    pub certificate: String,
    /// Start of validity, Unix seconds.
    pub valid_after: u64,
    /// End of validity (excluded), Unix seconds.
    pub valid_before: u64,
    /// The host CA of the agents, OpenSSH public key line
    /// (`ecdsa-sha2-nistp256 AAAA…`), for the `@cert-authority` line.
    pub host_ca: String,
    /// Host names or patterns of the bastion.
    pub ssh_hosts: Vec<String>,
    /// Port of the agents' SSH servers.
    pub ssh_port: u16,
}

impl LoginResponse {
    /// Parses and checks a response body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let response: Self = parse_json(body)?;
        check_protocol(response.protocol)?;
        if !is_uuid(&response.login_session) {
            return Err(WireError::Field("login_session", "UUID canonique attendu"));
        }
        if !is_uuid(&response.user) {
            return Err(WireError::Field("user", "UUID canonique attendu"));
        }
        for (field, line, prefix) in [
            (
                "certificate",
                &response.certificate,
                "ecdsa-sha2-nistp256-cert-v01@openssh.com ",
            ),
            ("host_ca", &response.host_ca, "ecdsa-sha2-nistp256 "),
        ] {
            if line.len() > MAX_SSH_LINE || !is_printable(line) || !line.starts_with(prefix) {
                return Err(WireError::Field(
                    field,
                    "ligne OpenSSH ECDSA P-256 imprimable attendue",
                ));
            }
        }
        if response.valid_before <= response.valid_after
            || response.valid_before - response.valid_after
                > MAX_SESSION_SECS + VALIDITY_MARGIN_SECS
        {
            return Err(WireError::Field(
                "valid_before",
                "durée de 8 h 5 min au plus",
            ));
        }
        if response.ssh_hosts.is_empty()
            || response.ssh_hosts.len() > MAX_SSH_HOSTS
            || !response.ssh_hosts.iter().all(|h| is_host_pattern(h))
        {
            return Err(WireError::Field(
                "ssh_hosts",
                "1 à 16 noms ou motifs d'hôte",
            ));
        }
        if response.ssh_port == 0 {
            return Err(WireError::Field("ssh_port", "port non nul attendu"));
        }
        Ok(response)
    }
}

/// A host name or `ssh_config` pattern (as `core.login.ssh_hosts`).
pub fn is_host_pattern(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'*' | b'?'))
        // Wildcards and dots alone (`*`, `*.*`) would match every host.
        && s.bytes().any(|b| b.is_ascii_alphanumeric())
}

/// Client → core: `POST /v1/logout`, signed with the session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutRequest {
    /// [`PROTOCOL`].
    pub protocol: u16,
    /// The login session to close.
    pub login_session: String,
    /// The certificate of that session (OpenSSH line): the core checks its
    /// SHA-256 against the session and verifies the signature with its key.
    pub certificate: String,
    /// When the request was signed, Unix seconds (accepted within
    /// ±[`LOGOUT_SKEW_SECS`]).
    pub issued_at: u64,
    /// ECDSA P-256 / SHA-256 signature `r ‖ s` (64 bytes, base64url) of
    /// [`logout_message`].
    pub signature: String,
}

/// Domain separation of the logout signature.
const LOGOUT_DOMAIN: &[u8] = b"ostena-logout-v1\0";

/// Tolerance on [`LogoutRequest::issued_at`], seconds, either way.
pub const LOGOUT_SKEW_SECS: u64 = 60;

/// The bytes signed by a logout request.
pub fn logout_message(login_session: &str, issued_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(LOGOUT_DOMAIN.len() + 36 + 8);
    out.extend_from_slice(LOGOUT_DOMAIN);
    out.extend_from_slice(login_session.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out
}

impl LogoutRequest {
    /// Parses and checks a request body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let request: Self = parse_json(body)?;
        check_protocol(request.protocol)?;
        if !is_uuid(&request.login_session) {
            return Err(WireError::Field("login_session", "UUID canonique attendu"));
        }
        if request.certificate.len() > MAX_SSH_LINE
            || !is_printable(&request.certificate)
            || !request
                .certificate
                .starts_with("ecdsa-sha2-nistp256-cert-v01@openssh.com ")
        {
            return Err(WireError::Field(
                "certificate",
                "ligne de certificat OpenSSH ECDSA P-256 attendue",
            ));
        }
        // 64 bytes in base64url without padding: 86 characters.
        if request.signature.len() != 86 || !is_base64url(&request.signature) {
            return Err(WireError::Field(
                "signature",
                "signature de 64 octets en base64url",
            ));
        }
        Ok(request)
    }
}

/// Client → core: `POST /v1/ssh-hosts`, the accesses of the session's user.
/// The same fields as a [`LogoutRequest`], signed by the session key under
/// another domain ([`ssh_hosts_message`]): a logout cannot be replayed as a
/// listing, nor the reverse.
pub type SshHostsRequest = LogoutRequest;

/// Domain separation of the listing signature.
const SSH_HOSTS_DOMAIN: &[u8] = b"ostena-ssh-hosts-v1\0";

/// The bytes signed by an [`SshHostsRequest`].
pub fn ssh_hosts_message(login_session: &str, issued_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SSH_HOSTS_DOMAIN.len() + 36 + 8);
    out.extend_from_slice(SSH_HOSTS_DOMAIN);
    out.extend_from_slice(login_session.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out
}

/// Core → client: the SSH accesses the user holds now, to write `Host`
/// aliases (`ostena config ssh`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshHostsResponse {
    /// [`PROTOCOL`].
    pub protocol: u16,
    /// Port of the agents' SSH servers.
    pub ssh_port: u16,
    /// At most [`MAX_SSH_ACCESSES`], sorted by resource then account, each
    /// pair once.
    pub accesses: Vec<SshAccess>,
}

/// One account of one resource the user may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAccess {
    /// The resource, as typed after the account (`[a-z0-9][a-z0-9.-]{0,62}`).
    pub resource: String,
    /// The account on the resource.
    pub account: String,
    /// The bastion host name to join it through (no pattern).
    pub host: String,
    /// End of the longest right, Unix seconds.
    pub valid_until: u64,
}

/// A resource name, as the inventory stores it.
pub fn is_resource(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

/// A target account, as the inventory stores it: 1 to 256 bytes, no
/// control character, no space at either end.
pub fn is_account(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ACCOUNT
        && !s.chars().any(char::is_control)
        && !s.starts_with(char::is_whitespace)
        && !s.ends_with(char::is_whitespace)
}

impl SshHostsResponse {
    /// Parses and checks a response body (up to [`MAX_HOSTS_BODY`]).
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let response: Self = parse_json_within(body, MAX_HOSTS_BODY)?;
        check_protocol(response.protocol)?;
        if response.ssh_port == 0 {
            return Err(WireError::Field("ssh_port", "port non nul attendu"));
        }
        if response.accesses.len() > MAX_SSH_ACCESSES {
            return Err(WireError::Field("accesses", "512 accès au plus"));
        }
        for access in &response.accesses {
            if !is_resource(&access.resource) {
                return Err(WireError::Field("resource", "nom de ressource invalide"));
            }
            if !is_account(&access.account) {
                return Err(WireError::Field("account", "compte invalide"));
            }
            if !is_host_pattern(&access.host) || access.host.contains(['*', '?']) {
                return Err(WireError::Field("host", "nom d'hôte sans motif attendu"));
            }
        }
        let sorted = response.accesses.windows(2).all(|w| {
            (w[0].resource.as_str(), w[0].account.as_str())
                < (w[1].resource.as_str(), w[1].account.as_str())
        });
        if !sorted {
            return Err(WireError::Field(
                "accesses",
                "triés par ressource puis compte, sans doublon",
            ));
        }
        Ok(response)
    }
}

/// Core → client: a refusal, with its stable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    /// [`PROTOCOL`].
    pub protocol: u16,
    /// Stable code, e.g. `AUTH-E001`.
    pub code: String,
    /// Message in French.
    pub message: String,
}

impl ErrorResponse {
    /// Parses and checks an error body.
    ///
    /// # Errors
    ///
    /// [`WireError`].
    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let response: Self = parse_json(body)?;
        check_protocol(response.protocol)?;
        let code = response.code.as_bytes();
        let well_formed = code.len() == 9
            && code[..4].iter().all(u8::is_ascii_uppercase)
            && &code[4..6] == b"-E"
            && code[6..].iter().all(u8::is_ascii_digit);
        if !well_formed {
            return Err(WireError::Field("code", "code AAAA-E000 attendu"));
        }
        if response.message.len() > MAX_MESSAGE || response.message.chars().any(char::is_control) {
            return Err(WireError::Field(
                "message",
                "512 octets au plus, sans caractère de contrôle",
            ));
        }
        Ok(response)
    }
}

/// Fuzzing entry point: every parser on arbitrary bytes, and what is
/// accepted must serialise and parse back to the same value.
///
/// # Panics
///
/// When an accepted message does not round-trip: a finding.
pub fn fuzz(data: &[u8]) {
    if let Ok(r) = LoginResponse::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(
            again.and_then(|b| LoginResponse::parse(&b).ok()),
            Some(r),
            "login response does not round-trip"
        );
    }
    if let Ok(r) = LogoutRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| LogoutRequest::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = SshHostsResponse::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(
            again.and_then(|b| SshHostsResponse::parse(&b).ok()),
            Some(r)
        );
    }
    if let Ok(r) = ErrorResponse::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        assert_eq!(again.and_then(|b| ErrorResponse::parse(&b).ok()), Some(r));
    }
    if let Ok(r) = LoginRequest::parse(data) {
        let again = serde_json::to_vec(&r).ok();
        let back = again.and_then(|b| LoginRequest::parse(&b).ok());
        assert!(
            back.is_some_and(|b| b.username == r.username && b.p256_public == r.p256_public),
            "login request does not round-trip"
        );
    }
}

#[cfg(test)]
mod tests;
