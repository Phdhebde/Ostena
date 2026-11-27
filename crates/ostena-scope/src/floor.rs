//! The floor: addresses refused whatever the policy (ADR-0005).
//!
//! Only a development-mode exception can lift it. Sources for each cloud
//! metadata address are listed in ADR-0005.

use std::net::IpAddr;

use crate::net::{Family, prefix_range};

/// Why an address belongs to the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloorCause {
    /// Unspecified or "this network" (`0.0.0.0/8`, `::`).
    Unspecified,
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Cloud instance metadata or platform service.
    CloudMetadata,
    /// Multicast (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// Limited broadcast (`255.255.255.255`).
    Broadcast,
    /// Reserved (`240.0.0.0/4`).
    Reserved,
    /// Deprecated IPv6 site-local (`fec0::/10`).
    SiteLocal,
    /// Teredo tunnel (`2001::/32`).
    Teredo,
    /// 6to4 tunnel (`2002::/16`).
    SixToFour,
    /// Local-use NAT64 (`64:ff9b:1::/48`).
    Nat64LocalUse,
    /// An address of the gateway host itself.
    AgentAddress,
}

impl FloorCause {
    /// Stable identifier for audit.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::CloudMetadata => "cloud-metadata",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
            Self::SiteLocal => "site-local",
            Self::Teredo => "teredo",
            Self::SixToFour => "6to4",
            Self::Nat64LocalUse => "nat64-local-use",
            Self::AgentAddress => "agent-address",
        }
    }

    /// French description.
    pub fn description(self) -> &'static str {
        match self {
            Self::Unspecified => "adresse non spécifiée",
            Self::Loopback => "boucle locale",
            Self::LinkLocal => "adresse de lien local",
            Self::CloudMetadata => "service de métadonnées ou de plateforme cloud",
            Self::Multicast => "multicast",
            Self::Broadcast => "diffusion générale",
            Self::Reserved => "plage réservée",
            Self::SiteLocal => "site-local IPv6 (obsolète)",
            Self::Teredo => "tunnel Teredo",
            Self::SixToFour => "tunnel 6to4",
            Self::Nat64LocalUse => "NAT64 à usage local",
            Self::AgentAddress => "adresse de la passerelle elle-même",
        }
    }
}

const fn v4(
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    prefix: u32,
    cause: FloorCause,
) -> (u128, u128, FloorCause) {
    let addr = ((a as u128) << 24) | ((b as u128) << 16) | ((c as u128) << 8) | (d as u128);
    let (start, end) = prefix_range(addr, prefix, 32);
    (start, end, cause)
}

const fn v6(addr: u128, prefix: u32, cause: FloorCause) -> (u128, u128, FloorCause) {
    let (start, end) = prefix_range(addr, prefix, 128);
    (start, end, cause)
}

/// IPv4 floor; the first matching entry gives the cause.
const FLOOR_V4: [(u128, u128, FloorCause); 9] = [
    v4(0, 0, 0, 0, 8, FloorCause::Unspecified),
    v4(127, 0, 0, 0, 8, FloorCause::Loopback),
    v4(169, 254, 169, 254, 32, FloorCause::CloudMetadata), // AWS, Azure, GCP, OCI
    v4(169, 254, 0, 0, 16, FloorCause::LinkLocal),
    v4(100, 100, 100, 200, 32, FloorCause::CloudMetadata), // Alibaba Cloud
    v4(168, 63, 129, 16, 32, FloorCause::CloudMetadata),   // Azure WireServer
    v4(192, 0, 0, 192, 32, FloorCause::CloudMetadata),     // Oracle Compute Classic
    v4(224, 0, 0, 0, 4, FloorCause::Multicast),
    v4(255, 255, 255, 255, 32, FloorCause::Broadcast),
];

/// Checked after [`FLOOR_V4`] so that broadcast keeps its own cause.
const RESERVED_V4: (u128, u128, FloorCause) = v4(240, 0, 0, 0, 4, FloorCause::Reserved);

/// IPv6 floor; the first matching entry gives the cause.
const FLOOR_V6: [(u128, u128, FloorCause); 10] = [
    v6(0, 128, FloorCause::Unspecified),
    v6(1, 128, FloorCause::Loopback),
    v6(
        0xfd00_0ec2_0000_0000_0000_0000_0000_0000,
        64,
        FloorCause::CloudMetadata,
    ), // AWS
    v6(
        0xfd20_00ce_0000_0000_0000_0000_0000_0254,
        128,
        FloorCause::CloudMetadata,
    ), // GCP
    v6(
        0xfe80_0000_0000_0000_0000_0000_0000_0000,
        10,
        FloorCause::LinkLocal,
    ),
    v6(
        0xfec0_0000_0000_0000_0000_0000_0000_0000,
        10,
        FloorCause::SiteLocal,
    ),
    v6(
        0xff00_0000_0000_0000_0000_0000_0000_0000,
        8,
        FloorCause::Multicast,
    ),
    v6(
        0x2001_0000_0000_0000_0000_0000_0000_0000,
        32,
        FloorCause::Teredo,
    ),
    v6(
        0x2002_0000_0000_0000_0000_0000_0000_0000,
        16,
        FloorCause::SixToFour,
    ),
    v6(
        0x0064_ff9b_0001_0000_0000_0000_0000_0000,
        48,
        FloorCause::Nat64LocalUse,
    ),
];

/// Floor cause of a normalised address, if any (static part only).
pub(crate) fn static_floor(family: Family, key: u128) -> Option<FloorCause> {
    let table: &[(u128, u128, FloorCause)] = match family {
        Family::V4 => &FLOOR_V4,
        Family::V6 => &FLOOR_V6,
    };
    let hit = table
        .iter()
        .find(|(s, e, _)| (*s..=*e).contains(&key))
        .map(|(_, _, c)| *c);
    match (hit, family) {
        (None, Family::V4) if (RESERVED_V4.0..=RESERVED_V4.1).contains(&key) => Some(RESERVED_V4.2),
        _ => hit,
    }
}

/// Floor cause of any address, IPv4 hidden in IPv6 judged as IPv4 (static
/// part only: the addresses of the host are not known here).
///
/// For the connections that bypass the scope policy, such as the core
/// towards its LDAPS directories, which refuse the cloud metadata services
/// only (ADR-0021).
pub fn floor_cause(ip: IpAddr) -> Option<FloorCause> {
    let (ip, _) = crate::net::normalize(ip);
    let (family, key) = crate::net::key(ip);
    static_floor(family, key)
}

/// Every static floor range, for tests and property generators.
#[doc(hidden)]
pub fn static_ranges() -> impl Iterator<Item = (bool, u128, u128, FloorCause)> {
    FLOOR_V4
        .iter()
        .chain(std::iter::once(&RESERVED_V4))
        .map(|(s, e, c)| (true, *s, *e, *c))
        .chain(FLOOR_V6.iter().map(|(s, e, c)| (false, *s, *e, *c)))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::net::{key, normalize};

    fn cause(s: &str) -> Option<FloorCause> {
        let (ip, _) = normalize(s.parse::<IpAddr>().unwrap());
        let (f, k) = key(ip);
        static_floor(f, k)
    }

    #[test]
    fn floor_causes() {
        use FloorCause::*;
        let cases = [
            ("0.0.0.0", Unspecified),
            ("0.1.2.3", Unspecified),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("169.254.169.254", CloudMetadata),
            ("169.254.170.2", LinkLocal),
            ("100.100.100.200", CloudMetadata),
            ("168.63.129.16", CloudMetadata),
            ("192.0.0.192", CloudMetadata),
            ("224.0.0.1", Multicast),
            ("239.255.255.255", Multicast),
            ("255.255.255.255", Broadcast),
            ("240.0.0.1", Reserved),
            ("::", Unspecified),
            ("::1", Loopback),
            ("fd00:ec2::254", CloudMetadata),
            ("fd00:ec2::23", CloudMetadata),
            ("fd20:ce::254", CloudMetadata),
            ("fe80::1", LinkLocal),
            ("febf::1", LinkLocal),
            ("fec0::1", SiteLocal),
            ("ff02::1", Multicast),
            ("2001::1", Teredo),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Teredo),
            ("2002:7f00:1::1", SixToFour),
            ("64:ff9b:1::7f00:1", Nat64LocalUse),
            // IPv4 hidden in IPv6 is judged as IPv4.
            ("::ffff:127.0.0.1", Loopback),
            ("::ffff:169.254.169.254", CloudMetadata),
            ("64:ff9b::a9fe:a9fe", CloudMetadata),
            ("::ffff:0:7f00:1", Loopback),
        ];
        for (addr, expected) in cases {
            assert_eq!(cause(addr), Some(expected), "{addr}");
            assert_eq!(floor_cause(addr.parse().unwrap()), Some(expected), "{addr}");
        }
        for ok in [
            "10.0.0.1",
            "8.8.8.8",
            "100.64.0.1",
            "192.0.0.191",
            "fd00:ec3::1",
            "fd20:ce::253",
            "2001:db8::1",
            "2003::1",
        ] {
            assert_eq!(cause(ok), None, "{ok}");
        }
    }
}
