//! Strict parsing of addresses, networks and ports, and IPv6 normalisation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Family {
    V4,
    V6,
}

/// An address as a family and a 128-bit key (IPv4 uses the low 32 bits).
pub(crate) fn key(ip: IpAddr) -> (Family, u128) {
    match ip {
        IpAddr::V4(v4) => (Family::V4, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (Family::V6, u128::from(v6)),
    }
}

/// Dotted-decimal IPv4 only: exactly four parts of 1 to 3 digits, no leading
/// zero, each at most 255. Octal, hexadecimal and shortened forms are refused.
pub(crate) fn parse_ipv4_strict(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty()
            || part.len() > 3
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

/// IPv6 literal without zone identifier.
pub(crate) fn parse_ipv6(s: &str) -> Option<Ipv6Addr> {
    if s.contains('%') {
        return None;
    }
    s.parse().ok()
}

/// Strict decimal number: digits only, no leading zero (except "0").
pub(crate) fn parse_decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Judges IPv4 addresses hidden in IPv6 as IPv4: mapped (`::ffff:a.b.c.d`),
/// SIIT translated (`::ffff:0:a.b.c.d`), well-known NAT64 (`64:ff9b::/96`) and
/// compatible (`::a.b.c.d`, except `::` and `::1`). Returns the address to
/// judge and, when it changed, the original IPv6.
///
/// Teredo, 6to4 and local-use NAT64 are not normalised: the floor refuses them.
pub fn normalize(ip: IpAddr) -> (IpAddr, Option<Ipv6Addr>) {
    let IpAddr::V6(v6) = ip else {
        return (ip, None);
    };
    let bits = u128::from(v6);
    let high = bits >> 32;
    let embedded = high == 0xffff                       // mapped
        || high == 0xffff_0000                          // SIIT translated
        || high == 0x0064_ff9b_0000_0000_0000_0000      // NAT64 well-known
        || (high == 0 && bits > 1); // compatible
    if embedded {
        #[expect(clippy::cast_possible_truncation, reason = "low 32 bits on purpose")]
        let v4 = Ipv4Addr::from(bits as u32);
        (IpAddr::V4(v4), Some(v6))
    } else {
        (ip, None)
    }
}

/// Inclusive key range of a prefix.
pub(crate) const fn prefix_range(addr: u128, prefix: u32, bits: u32) -> (u128, u128) {
    let host_bits = bits - prefix;
    let host_mask = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let start = addr & !host_mask;
    (start, start | host_mask)
}

/// A network in CIDR notation, parsed strictly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

/// Why a network string is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    /// Not an IPv4 or IPv6 address.
    Address,
    /// Prefix length missing, malformed or too large.
    Prefix,
    /// Bits set after the prefix (probable typo, e.g. `10.0.0.1/8`).
    HostBits,
}

impl NetworkError {
    /// French explanation.
    pub fn message(self) -> &'static str {
        match self {
            Self::Address => "adresse invalide (IPv4 décimale stricte ou IPv6, sans zone)",
            Self::Prefix => "longueur de préfixe invalide",
            Self::HostBits => "bits d'hôte non nuls après le préfixe (faute de frappe probable)",
        }
    }
}

impl Network {
    /// Parses `addr` or `addr/prefix`. A bare address is a single host.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] for a malformed address or prefix, or host bits set.
    pub fn parse(s: &str) -> Result<Self, NetworkError> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr = if let Some(v4) = parse_ipv4_strict(addr_part) {
            IpAddr::V4(v4)
        } else if let Some(v6) = parse_ipv6(addr_part) {
            IpAddr::V6(v6)
        } else {
            return Err(NetworkError::Address);
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            None => max,
            Some(p) => parse_decimal::<u8>(p)
                .filter(|p| *p <= max)
                .ok_or(NetworkError::Prefix)?,
        };
        let net = Self { addr, prefix };
        let (_, k) = key(addr);
        if prefix_range(k, u32::from(prefix), u32::from(max)).0 != k {
            return Err(NetworkError::HostBits);
        }
        Ok(net)
    }

    /// Address family and inclusive key range.
    pub(crate) fn range(&self) -> (Family, u128, u128) {
        let (family, k) = key(self.addr);
        let bits = if family == Family::V4 { 32 } else { 128 };
        let (start, end) = prefix_range(k, u32::from(self.prefix), bits);
        (family, start, end)
    }

    /// Whether this IPv6 network lies entirely inside a range that
    /// [`normalize`] turns into IPv4: a rule on it could never match.
    pub(crate) fn is_inside_normalized_range(&self) -> bool {
        let (family, start, end) = self.range();
        family == Family::V6 && self.prefix >= 96 && {
            let high = start >> 32;
            (end >> 32) == high
                && (high == 0xffff
                    || high == 0xffff_0000
                    || high == 0x0064_ff9b_0000_0000_0000_0000
                    || high == 0)
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Inclusive port range, parsed from `"22"` or `"8000-8100"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    pub(crate) start: u16,
    pub(crate) end: u16,
}

impl PortRange {
    /// Parses a port or an inclusive range, 1 to 65535.
    pub fn parse(s: &str) -> Option<Self> {
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let start = parse_decimal::<u16>(a).filter(|p| *p > 0)?;
        let end = parse_decimal::<u16>(b).filter(|p| *p >= start)?;
        Some(Self { start, end })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_ipv4() {
        assert_eq!(
            parse_ipv4_strict("10.0.0.1"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(parse_ipv4_strict("0.0.0.0"), Some(Ipv4Addr::UNSPECIFIED));
        for bad in [
            "0177.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.0.0.1",
            "1.2.3.256",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "",
            "1.2.3.4 ",
            "+1.2.3.4",
            "01.2.3.4",
        ] {
            assert_eq!(parse_ipv4_strict(bad), None, "{bad}");
        }
    }

    #[test]
    fn networks() {
        assert!(Network::parse("10.0.0.0/8").is_ok());
        assert!(Network::parse("10.1.2.3").is_ok());
        assert!(Network::parse("0.0.0.0/0").is_ok());
        assert!(Network::parse("::/0").is_ok());
        assert!(Network::parse("2001:db8::/32").is_ok());
        assert_eq!(Network::parse("10.0.0.1/8"), Err(NetworkError::HostBits));
        assert_eq!(Network::parse("10.0.0.0/33"), Err(NetworkError::Prefix));
        assert_eq!(Network::parse("10.0.0.0/08"), Err(NetworkError::Prefix));
        assert_eq!(Network::parse("10.0.0.0/"), Err(NetworkError::Prefix));
        assert_eq!(Network::parse("010.0.0.0/8"), Err(NetworkError::Address));
        assert_eq!(Network::parse("fe80::1%eth0"), Err(NetworkError::Address));
        let (_, s, e) = Network::parse("192.168.1.0/24").unwrap().range();
        assert_eq!((s, e), (0xc0a8_0100, 0xc0a8_01ff));
        let (_, s, e) = Network::parse("::/0").unwrap().range();
        assert_eq!((s, e), (0, u128::MAX));
    }

    #[test]
    fn normalized_ranges_are_detected() {
        assert!(
            Network::parse("::ffff:10.0.0.0/104")
                .unwrap()
                .is_inside_normalized_range()
        );
        assert!(
            Network::parse("64:ff9b::/96")
                .unwrap()
                .is_inside_normalized_range()
        );
        assert!(!Network::parse("::/0").unwrap().is_inside_normalized_range());
        assert!(
            !Network::parse("2001:db8::/32")
                .unwrap()
                .is_inside_normalized_range()
        );
    }

    #[test]
    fn ports() {
        assert_eq!(
            PortRange::parse("22"),
            Some(PortRange { start: 22, end: 22 })
        );
        assert_eq!(
            PortRange::parse("8000-8100"),
            Some(PortRange {
                start: 8000,
                end: 8100
            })
        );
        for bad in [
            "0", "65536", "022", "10-5", "-5", "5-", "a", "", "1-2-3", " 22",
        ] {
            assert_eq!(PortRange::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn normalization() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        for form in [
            "::ffff:10.1.2.3",
            "::ffff:0:10.1.2.3",
            "64:ff9b::10.1.2.3",
            "::10.1.2.3",
        ] {
            let v6: Ipv6Addr = form.parse().unwrap();
            assert_eq!(normalize(IpAddr::V6(v6)), (v4, Some(v6)), "{form}");
        }
        for kept in [
            "::",
            "::1",
            "2001::1",
            "2002:a01:203::1",
            "64:ff9b:1::a01:203",
            "2001:db8::1",
        ] {
            let v6: Ipv6Addr = kept.parse().unwrap();
            assert_eq!(normalize(IpAddr::V6(v6)), (IpAddr::V6(v6), None), "{kept}");
        }
    }
}
