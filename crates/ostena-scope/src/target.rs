//! Target parsing: refuse ambiguous forms before they reach the resolver.

use std::fmt;
use std::net::IpAddr;

use crate::error::Code;
use crate::net::{parse_decimal, parse_ipv4_strict, parse_ipv6};

/// A host name, normalised: ASCII lower case, no trailing dot, LDH labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// The normalised name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A single label, resolved through search suffixes, LLMNR or NetBIOS.
    pub fn is_short(&self) -> bool {
        !self.0.contains('.')
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The host part of a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// An IP literal.
    Ip(IpAddr),
    /// A name, to resolve once.
    Name(Hostname),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            Self::Ip(IpAddr::V4(v4)) => write!(f, "{v4}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

/// A host and a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    host: Host,
    port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// A target refused before resolution (`SCP-E001` to `SCP-E005`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("[{code}] cible refusée : {message}")]
pub struct TargetError {
    /// Stable code.
    pub code: Code,
    /// French explanation.
    pub message: &'static str,
}

fn refuse(code: Code, message: &'static str) -> TargetError {
    TargetError { code, message }
}

/// Longest accepted host text (253 for the name, plus one trailing dot).
const MAX_HOST_LEN: usize = 254;

/// Whether a label reads as a number to `inet_aton`-style parsers.
fn is_numeric_label(label: &str) -> bool {
    let hex = label
        .strip_prefix("0x")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_hexdigit()));
    hex || (!label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// Parses and normalises a host: `name`, `a.b.c.d`, `[v6]` or a bare IPv6.
///
/// # Errors
///
/// [`TargetError`] for an empty, overlong or malformed host (`SCP-E001`), a
/// non-ASCII name (`SCP-E002`, no IDNA), an ambiguous numeric form such as
/// `0x7f.1`, `2130706433` or `0177.0.0.1` (`SCP-E003`), a reserved name
/// (`SCP-E004`) or an IPv6 zone identifier (`SCP-E005`).
pub fn parse_host(input: &str) -> Result<Host, TargetError> {
    if input.is_empty() || input.len() > MAX_HOST_LEN {
        return Err(refuse(Code::InvalidTarget, "hôte vide ou trop long"));
    }
    let bracketed = input.strip_prefix('[').map(|rest| rest.strip_suffix(']'));
    if let Some(inner) = bracketed {
        let inner = inner.ok_or(refuse(Code::InvalidTarget, "crochet fermant manquant"))?;
        return ipv6_literal(inner);
    }
    if input.contains(':') {
        return ipv6_literal(input);
    }
    if !input.is_ascii() {
        return Err(refuse(
            Code::NonAscii,
            "nom non ASCII (les noms internationalisés ne sont pas pris en charge)",
        ));
    }
    let lower = input.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() || name.split('.').any(str::is_empty) {
        return Err(refuse(Code::InvalidTarget, "étiquette vide dans le nom"));
    }
    // A name never ends with a numeric label: treat it as an IPv4 attempt,
    // accepted only in strict dotted-decimal form.
    if name.rsplit('.').next().is_some_and(is_numeric_label) {
        return parse_ipv4_strict(name)
            .map(|v4| Host::Ip(IpAddr::V4(v4)))
            .ok_or(refuse(
                Code::AmbiguousNumeric,
                "forme numérique ambiguë (seule la notation décimale pointée stricte est acceptée)",
            ));
    }
    if name.len() > 253 {
        return Err(refuse(Code::InvalidTarget, "nom de plus de 253 caractères"));
    }
    for label in name.split('.') {
        if label.contains('_') {
            return Err(refuse(
                Code::InvalidTarget,
                "caractère « _ » refusé dans un nom d'hôte",
            ));
        }
        let ldh = label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ldh {
            return Err(refuse(
                Code::InvalidTarget,
                "étiquette invalide (lettres, chiffres et tirets, 63 caractères au plus)",
            ));
        }
    }
    // `name` is already lower case.
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "a DNS suffix, already lower case"
    )]
    let reserved = name == "localhost"
        || name.ends_with(".localhost")
        || name == "local"
        || name.ends_with(".local");
    if reserved {
        return Err(refuse(
            Code::ReservedName,
            "nom réservé (localhost) ou résolu par mDNS (.local)",
        ));
    }
    Ok(Host::Name(Hostname(name.to_owned())))
}

fn ipv6_literal(s: &str) -> Result<Host, TargetError> {
    if s.contains('%') {
        return Err(refuse(Code::ZoneId, "identifiant de zone IPv6 refusé"));
    }
    parse_ipv6(s)
        .map(|v6| Host::Ip(IpAddr::V6(v6)))
        .ok_or(refuse(Code::InvalidTarget, "adresse IPv6 invalide"))
}

impl Target {
    /// A target from a host (see [`parse_host`]) and a port.
    ///
    /// # Errors
    ///
    /// See [`parse_host`].
    pub fn new(host: &str, port: u16) -> Result<Self, TargetError> {
        Ok(Self {
            host: parse_host(host)?,
            port,
        })
    }

    /// Parses `host:port` or `[ipv6]:port`.
    ///
    /// # Errors
    ///
    /// See [`parse_host`]; a missing or malformed port, or an IPv6 address
    /// without brackets, is `SCP-E001`.
    pub fn parse(input: &str) -> Result<Self, TargetError> {
        let (host, port) = if input.starts_with('[') {
            let end = input
                .find("]:")
                .ok_or(refuse(Code::InvalidTarget, "attendu [ipv6]:port"))?;
            (&input[..=end], &input[end + 2..])
        } else {
            let (h, p) = input.rsplit_once(':').ok_or(refuse(
                Code::InvalidTarget,
                "port manquant (attendu hôte:port)",
            ))?;
            if h.contains(':') {
                return Err(refuse(Code::InvalidTarget, "adresse IPv6 sans crochets"));
            }
            (h, p)
        };
        let port =
            parse_decimal::<u16>(port).ok_or(refuse(Code::InvalidTarget, "port invalide"))?;
        Self::new(host, port)
    }

    /// The host.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(s: &str) -> Code {
        parse_host(s).unwrap_err().code
    }

    #[test]
    fn names_are_normalised() {
        assert_eq!(
            parse_host("SRV01.Corp.Example."),
            Ok(Host::Name(Hostname("srv01.corp.example".into())))
        );
        assert_eq!(
            parse_host("a-b.c"),
            Ok(Host::Name(Hostname("a-b.c".into())))
        );
        assert_eq!(
            parse_host("0x7f.example.com")
                .map(|h| h.to_string())
                .as_deref(),
            Ok("0x7f.example.com")
        );
        assert!(matches!(parse_host("srv01"), Ok(Host::Name(n)) if n.is_short()));
    }

    #[test]
    fn literals() {
        assert_eq!(
            parse_host("10.0.0.1"),
            Ok(Host::Ip("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parse_host("10.0.0.1."),
            Ok(Host::Ip("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parse_host("[2001:db8::1]"),
            Ok(Host::Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parse_host("2001:db8::1"),
            Ok(Host::Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parse_host("::ffff:127.0.0.1"),
            Ok(Host::Ip("::ffff:127.0.0.1".parse().unwrap()))
        );
    }

    #[test]
    fn e001_syntax() {
        for bad in [
            "",
            "a..b",
            ".a",
            "a b",
            "-a.b",
            "a-.b",
            "a_b.c",
            "[::1",
            "a/b",
            &"a".repeat(64),
            "[1.2.3.4]",
        ] {
            assert_eq!(code(bad), Code::InvalidTarget, "{bad:?}");
        }
        let long = format!("{}.com", ["abcdefghij"; 25].join("."));
        assert_eq!(code(&long), Code::InvalidTarget);
    }

    #[test]
    fn e002_non_ascii() {
        assert_eq!(code("bücher.example"), Code::NonAscii);
        assert_eq!(code("ex\u{0430}mple.com"), Code::NonAscii); // Cyrillic a
    }

    #[test]
    fn e003_ambiguous_numeric() {
        for bad in [
            "0x7f.1",
            "2130706433",
            "0177.0.0.1",
            "127.1",
            "0x7f000001",
            "1.2.3.4.5",
            "10.0.0.256",
            "a.1",
            "example.0x10",
            "0x",
        ] {
            assert_eq!(code(bad), Code::AmbiguousNumeric, "{bad}");
        }
    }

    #[test]
    fn e004_reserved() {
        for bad in [
            "localhost",
            "LOCALHOST.",
            "x.localhost",
            "printer.local",
            "local",
        ] {
            assert_eq!(code(bad), Code::ReservedName, "{bad}");
        }
    }

    #[test]
    fn e005_zone() {
        assert_eq!(code("fe80::1%eth0"), Code::ZoneId);
        assert_eq!(code("[fe80::1%25eth0]"), Code::ZoneId);
    }

    #[test]
    fn target_parsing() {
        let t = Target::parse("srv.example:3389").unwrap();
        assert_eq!(t.port(), 3389);
        assert_eq!(t.to_string(), "srv.example:3389");
        assert_eq!(
            Target::parse("[2001:db8::1]:22").unwrap().to_string(),
            "[2001:db8::1]:22"
        );
        for bad in [
            "srv.example",
            "srv.example:",
            "srv.example:65536",
            "srv.example:022",
            "2001:db8::1:22",
            "[2001:db8::1]22",
            "srv:-1",
        ] {
            assert_eq!(
                Target::parse(bad).unwrap_err().code,
                Code::InvalidTarget,
                "{bad}"
            );
        }
        assert_eq!(Target::parse("srv.example:0").unwrap().port(), 0);
    }
}
