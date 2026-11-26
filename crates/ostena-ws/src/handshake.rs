//! The checks of an upgrade request (RFC 6455, § 4.2.1).
//!
//! The caller passes the method, whether the request is HTTP/1.1, and the
//! headers as (name, value) pairs; the names are compared without regard
//! to case. What the request asks beyond the protocol (its origin, its
//! session, the subprotocol it must offer) is the caller's to decide.
//! Extensions (`Sec-WebSocket-Extensions`) are ignored: none is ever
//! negotiated.

use std::fmt;

/// Most subprotocols a request may offer.
pub const MAX_PROTOCOLS: usize = 4;
/// Longest subprotocol token, in bytes.
pub const MAX_PROTOCOL_LEN: usize = 512;
/// Length of a `Sec-WebSocket-Key`: 16 bytes in padded base64.
pub const KEY_LEN: usize = 24;

/// Why an upgrade request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeError {
    /// Not a `GET`.
    Method,
    /// Not HTTP/1.1.
    HttpVersion,
    /// No `Upgrade: websocket`.
    Upgrade,
    /// No `upgrade` token in `Connection`.
    Connection,
    /// `Sec-WebSocket-Version` absent, repeated or other than 13: the
    /// answer is `426` with `Sec-WebSocket-Version: 13`.
    Version,
    /// `Sec-WebSocket-Key` absent, repeated or not 16 bytes in base64.
    Key,
    /// `Sec-WebSocket-Protocol` malformed, or too many or too long tokens.
    Protocol,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Method => "méthode autre que GET",
            Self::HttpVersion => "version HTTP autre que 1.1",
            Self::Upgrade => "en-tête Upgrade: websocket absent",
            Self::Connection => "jeton upgrade absent de l'en-tête Connection",
            Self::Version => "Sec-WebSocket-Version absent ou autre que 13",
            Self::Key => "Sec-WebSocket-Key absent ou invalide",
            Self::Protocol => "Sec-WebSocket-Protocol invalide",
        })
    }
}

impl std::error::Error for HandshakeError {}

/// An upgrade request that passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade<'a> {
    /// The `Sec-WebSocket-Key`, as received, for
    /// `ostena_crypto::websocket::accept_key`.
    pub key: &'a str,
    protocols: Vec<&'a str>,
}

impl<'a> Upgrade<'a> {
    /// The subprotocols offered, in order.
    pub fn protocols(&self) -> &[&'a str] {
        &self.protocols
    }

    /// Whether `protocol` is offered.
    pub fn offers(&self, protocol: &str) -> bool {
        self.protocols.contains(&protocol)
    }

    /// The offered subprotocols that start with `prefix`, without it.
    pub fn with_prefix<'p>(&'p self, prefix: &'p str) -> impl Iterator<Item = &'a str> + 'p {
        self.protocols
            .iter()
            .filter_map(move |p| p.strip_prefix(prefix))
    }
}

/// A token character (RFC 9110, § 5.6.2).
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The comma-separated elements of a header value, trimmed, empty ones
/// skipped (RFC 9110, § 5.6.1).
fn elements(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|b| *b == b',')
        .map(<[u8]>::trim_ascii)
        .filter(|e| !e.is_empty())
}

fn base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Whether `key` is 16 bytes in canonical padded base64: 22 characters,
/// the last of which carries only 2 bits, then `==`.
fn valid_key(key: &[u8]) -> bool {
    key.len() == KEY_LEN
        && key[..21].iter().all(|b| base64(*b))
        && b"AQgw".contains(&key[21])
        && &key[22..] == b"=="
}

/// Checks an upgrade request.
///
/// # Errors
///
/// The first check that fails, see [`HandshakeError`].
pub fn check<'a, I>(method: &str, http_1_1: bool, headers: I) -> Result<Upgrade<'a>, HandshakeError>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    if method != "GET" {
        return Err(HandshakeError::Method);
    }
    if !http_1_1 {
        return Err(HandshakeError::HttpVersion);
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut version = None;
    let mut versions = 0usize;
    let mut key = None;
    let mut keys = 0usize;
    let mut protocols = Vec::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= elements(value).any(|e| e.eq_ignore_ascii_case(b"websocket"));
        } else if name.eq_ignore_ascii_case("connection") {
            connection |= elements(value).any(|e| e.eq_ignore_ascii_case(b"upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            versions += 1;
            version = Some(value.trim_ascii());
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            keys += 1;
            key = Some(value.trim_ascii());
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            for token in elements(value) {
                if protocols.len() == MAX_PROTOCOLS
                    || token.len() > MAX_PROTOCOL_LEN
                    || !token.iter().all(|b| tchar(*b))
                {
                    return Err(HandshakeError::Protocol);
                }
                // Token characters are ASCII.
                let token = std::str::from_utf8(token).map_err(|_| HandshakeError::Protocol)?;
                protocols.push(token);
            }
        }
    }
    if !upgrade {
        return Err(HandshakeError::Upgrade);
    }
    if !connection {
        return Err(HandshakeError::Connection);
    }
    if versions != 1 || version != Some(b"13".as_slice()) {
        return Err(HandshakeError::Version);
    }
    let key = match key {
        Some(k) if keys == 1 && valid_key(k) => k,
        _ => return Err(HandshakeError::Key),
    };
    // Base64 characters are ASCII.
    let key = std::str::from_utf8(key).map_err(|_| HandshakeError::Key)?;
    Ok(Upgrade { key, protocols })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn base() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("Host", b"portail.example".as_slice()),
            ("Upgrade", b"websocket"),
            ("Connection", b"keep-alive, Upgrade"),
            ("Sec-WebSocket-Version", b"13"),
            ("Sec-WebSocket-Key", KEY.as_bytes()),
            (
                "Sec-WebSocket-Protocol",
                b"ostena-frame.v1, ostena-grant.AbC-_9",
            ),
        ]
    }

    fn without(name: &str) -> Vec<(&'static str, &'static [u8])> {
        base().into_iter().filter(|(n, _)| *n != name).collect()
    }

    fn with(name: &'static str, value: &'static [u8]) -> Vec<(&'static str, &'static [u8])> {
        let mut h = without(name);
        h.push((name, value));
        h
    }

    #[test]
    fn a_valid_request_passes() {
        let up = check("GET", true, base()).unwrap();
        assert_eq!(up.key, KEY);
        assert_eq!(up.protocols(), ["ostena-frame.v1", "ostena-grant.AbC-_9"]);
        assert!(up.offers("ostena-frame.v1"));
        assert!(!up.offers("ostena-frame"));
        assert_eq!(
            up.with_prefix("ostena-grant.").collect::<Vec<_>>(),
            ["AbC-_9"]
        );
        // Lower-case names, as hyper gives them; no protocol at all.
        let lower: Vec<_> = without("Sec-WebSocket-Protocol")
            .into_iter()
            .map(|(n, v)| (if n == "Upgrade" { "upgrade" } else { n }, v))
            .collect();
        assert_eq!(
            check("GET", true, lower).unwrap().protocols(),
            [] as [&str; 0]
        );
        // Protocols over several headers.
        let mut split = without("Sec-WebSocket-Protocol");
        split.push(("sec-websocket-protocol", b"a"));
        split.push(("sec-websocket-protocol", b" b ,, c"));
        assert_eq!(
            check("GET", true, split).unwrap().protocols(),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn each_check_refuses() {
        assert_eq!(check("POST", true, base()), Err(HandshakeError::Method));
        assert_eq!(
            check("GET", false, base()),
            Err(HandshakeError::HttpVersion)
        );
        assert_eq!(
            check("GET", true, without("Upgrade")),
            Err(HandshakeError::Upgrade)
        );
        assert_eq!(
            check("GET", true, with("Upgrade", b"h2c")),
            Err(HandshakeError::Upgrade)
        );
        assert_eq!(
            check("GET", true, with("Connection", b"keep-alive")),
            Err(HandshakeError::Connection)
        );
        for v in [b"12".as_slice(), b"13, 8", b""] {
            assert_eq!(
                check("GET", true, with("Sec-WebSocket-Version", v)),
                Err(HandshakeError::Version)
            );
        }
        let mut twice = base();
        twice.push(("Sec-WebSocket-Version", b"13"));
        assert_eq!(check("GET", true, twice), Err(HandshakeError::Version));
        for k in [
            b"".as_slice(),
            b"dGhlIHNhbXBsZSBub25jZQ",
            b"dGhlIHNhbXBsZSBub25jZR==",
            b"dGhlIHNhbXBsZSBub25jZQ=",
            b"dGhlIHNhbXBsZSBub25j*Q==",
            b"dGhlIHNhbXBsZSBub25jZQ==AA",
        ] {
            assert_eq!(
                check("GET", true, with("Sec-WebSocket-Key", k)),
                Err(HandshakeError::Key),
                "{k:?}"
            );
        }
        let mut twice = base();
        twice.push(("Sec-WebSocket-Key", KEY.as_bytes()));
        assert_eq!(check("GET", true, twice), Err(HandshakeError::Key));
        for p in [b"a b".as_slice(), b"a, \"b\"", b"a,b,c,d,e"] {
            assert_eq!(
                check("GET", true, with("Sec-WebSocket-Protocol", p)),
                Err(HandshakeError::Protocol),
                "{p:?}"
            );
        }
        let long = vec![b'a'; MAX_PROTOCOL_LEN + 1].leak();
        assert_eq!(
            check("GET", true, with("Sec-WebSocket-Protocol", long)),
            Err(HandshakeError::Protocol)
        );
    }
}
