//! Stable codes, decision refusals and errors (ADR-0005).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use crate::floor::FloorCause;
use crate::target::TargetError;

/// Stable codes. Never renumber or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// Malformed target.
    InvalidTarget,
    /// Non-ASCII name (no IDNA).
    NonAscii,
    /// Ambiguous numeric host.
    AmbiguousNumeric,
    /// Reserved name (`localhost`, `.local`).
    ReservedName,
    /// IPv6 zone identifier.
    ZoneId,
    /// Port 0 or port not allowed for this network.
    PortNotAllowed,
    /// Address in the floor.
    Floor,
    /// Address in a denied network.
    Denied,
    /// No allowed network covers the address.
    NotAllowed,
    /// Resolution failed, empty, too large or timed out.
    Resolution,
    /// One of the resolved addresses is refused.
    ResolvedAddressRefused,
    /// Invalid policy.
    InvalidPolicy,
    /// Floor exception in production.
    FloorExceptionInProduction,
    /// Short (single-label) name refused.
    ShortName,
    /// `allow_short_names` in production without justification.
    ShortNamesInProduction,
    /// Address of an Ostena infrastructure component.
    Infrastructure,
    /// Short names waiver: justification too short, expiry missing, invalid
    /// or more than a year ahead.
    ShortNamesWaiver,
    /// Short names waiver expired.
    ShortNamesExpired,
}

impl Code {
    /// The code as written in messages and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTarget => "SCP-E001",
            Self::NonAscii => "SCP-E002",
            Self::AmbiguousNumeric => "SCP-E003",
            Self::ReservedName => "SCP-E004",
            Self::ZoneId => "SCP-E005",
            Self::PortNotAllowed => "SCP-E006",
            Self::Floor => "SCP-E007",
            Self::Denied => "SCP-E008",
            Self::NotAllowed => "SCP-E009",
            Self::Resolution => "SCP-E010",
            Self::ResolvedAddressRefused => "SCP-E011",
            Self::InvalidPolicy => "SCP-E012",
            Self::FloorExceptionInProduction => "SCP-E013",
            Self::ShortName => "SCP-E014",
            Self::ShortNamesInProduction => "SCP-E015",
            Self::Infrastructure => "SCP-E016",
            Self::ShortNamesWaiver => "SCP-E017",
            Self::ShortNamesExpired => "SCP-E018",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The rule behind a refusal (indices refer to the policy specification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Floor entry.
    Floor(FloorCause),
    /// Ostena infrastructure entry.
    Infrastructure(u32),
    /// Deny rule.
    Denied(u32),
    /// Default deny: no allow rule covers the address.
    NoAllowedNetwork,
    /// Port 0.
    PortZero,
    /// The allow rules covering the address do not include the port.
    PortNotAllowed,
}

/// A refused address. `Copy` and allocation-free: decisions never allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Stable code.
    pub code: Code,
    /// Address judged (normalised).
    pub address: IpAddr,
    /// Original IPv6 when it hid an IPv4.
    pub original: Option<Ipv6Addr>,
    /// Port.
    pub port: u16,
    /// Rule that refused.
    pub rule: Rule,
}

/// Why a target cannot be pinned. Each variant maps to a stable code; the
/// `scope.refused` event carries the same information.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// Refused while parsing (`SCP-E001` to `SCP-E005`).
    #[error("{source} (cible « {requested} »)")]
    Target {
        /// Target as requested.
        requested: String,
        /// Parse refusal.
        source: TargetError,
    },
    /// Single-label name refused (`SCP-E014`).
    #[error(
        "[SCP-E014] nom court « {requested} » refusé : sans domaine, il peut être résolu par \
         LLMNR ou NetBIOS (non authentifiés) ; utilisez un nom complet"
    )]
    ShortName {
        /// Target as requested.
        requested: String,
    },
    /// Single-label name refused because the waiver expired (`SCP-E018`).
    #[error(
        "[SCP-E018] nom court « {requested} » refusé : la dérogation allow_short_names a \n         expiré le {expired_on}"
    )]
    ShortNameExpired {
        /// Target as requested.
        requested: String,
        /// Last valid day of the waiver.
        expired_on: String,
    },
    /// Resolution failed (`SCP-E010`).
    #[error("[SCP-E010] résolution de « {requested} » impossible : {reason}")]
    Resolution {
        /// Target as requested.
        requested: String,
        /// Reason.
        reason: String,
    },
    /// An address is refused by the policy or the floor.
    #[error("[{}] cible « {requested} » refusée : {address} {} ({rule})", self.code(), if *via_name { "(adresse résolue)" } else { "" })]
    Refused {
        /// Target as requested.
        requested: String,
        /// The decision.
        refusal: Refusal,
        /// Readable rule description.
        rule: String,
        /// The address came from resolving a name (`SCP-E011`).
        via_name: bool,
        /// Formatted address, for the message.
        address: String,
    },
}

impl ScopeError {
    /// The stable code.
    pub fn code(&self) -> Code {
        match self {
            Self::Target { source, .. } => source.code,
            Self::ShortName { .. } => Code::ShortName,
            Self::ShortNameExpired { .. } => Code::ShortNamesExpired,
            Self::Resolution { .. } => Code::Resolution,
            Self::Refused { via_name: true, .. } => Code::ResolvedAddressRefused,
            Self::Refused { refusal, .. } => refusal.code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_numbered() {
        let all = [
            Code::InvalidTarget,
            Code::NonAscii,
            Code::AmbiguousNumeric,
            Code::ReservedName,
            Code::ZoneId,
            Code::PortNotAllowed,
            Code::Floor,
            Code::Denied,
            Code::NotAllowed,
            Code::Resolution,
            Code::ResolvedAddressRefused,
            Code::InvalidPolicy,
            Code::FloorExceptionInProduction,
            Code::ShortName,
            Code::ShortNamesInProduction,
            Code::Infrastructure,
            Code::ShortNamesWaiver,
            Code::ShortNamesExpired,
        ];
        for (i, c) in all.iter().enumerate() {
            assert_eq!(c.as_str(), format!("SCP-E{:03}", i + 1));
        }
    }
}
