//! Stable codes and errors (ADR-0022).

use crate::model::RuleId;

/// Stable codes. Never renumber or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// No valid rule allows the access: refused by default.
    NoRule,
    /// A valid refusing rule applies: the refusal wins.
    DeniedByRule,
    /// No policy is installed, or it was invalidated: refused.
    Unavailable,
    /// Invalid policy: not compiled, the installed one stays.
    InvalidPolicy,
    /// A policy older than the installed one: not installed.
    StaleVersion,
    /// One account holds the audit role and a role that widens accesses.
    RoleCumulation,
}

impl Code {
    /// The code as written in messages, logs and audit records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRule => "POL-E001",
            Self::DeniedByRule => "POL-E002",
            Self::Unavailable => "POL-E003",
            Self::InvalidPolicy => "POL-E004",
            Self::StaleVersion => "POL-E005",
            Self::RoleCumulation => "POL-E006",
        }
    }

    /// A generic label, the only thing a refused user is told.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoRule => "aucune autorisation",
            Self::DeniedByRule => "accès interdit par une règle",
            Self::Unavailable => "politique d'accès indisponible",
            Self::InvalidPolicy => "politique d'accès invalide",
            Self::StaleVersion => "politique d'accès plus ancienne que celle en place",
            Self::RoleCumulation => "rôles d'administration incompatibles",
        }
    }
}

/// Why a policy was not compiled or installed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Two rules have the same identifier.
    #[error("POL-E004: règle {0} en double")]
    DuplicateRule(RuleId),
    /// A rule without protocol.
    #[error("POL-E004: règle {0} sans protocole")]
    NoProtocol(RuleId),
    /// A rule that ends before it starts.
    #[error("POL-E004: règle {0} : fin de validité avant le début")]
    Window(RuleId),
    /// An allowing rule valid longer than [`crate::MAX_ALLOW_SECS`].
    #[error("POL-E004: règle {0} : autorisation de plus de 366 jours")]
    AllowTooLong(RuleId),
    /// An allowing rule whose session length is out of bounds.
    #[error("POL-E004: règle {0} : durée de session hors de [60 s, 12 h]")]
    SessionLength(RuleId),
    /// A refusal of functions that names none.
    #[error("POL-E004: règle {0} : refus de fonctions sans fonction")]
    NoFunction(RuleId),
    /// More items than the PDP indexes.
    #[error("POL-E004: trop d'éléments ({what} : {count}, {max} au plus)")]
    TooMany {
        /// What overflows.
        what: &'static str,
        /// How many there are.
        count: usize,
        /// The bound.
        max: usize,
    },
    /// A version older than the installed one.
    #[error("POL-E005: version {offered} plus ancienne que la version en place {installed}")]
    Stale {
        /// The installed version.
        installed: u64,
        /// The version offered.
        offered: u64,
    },
}

impl PolicyError {
    /// Its stable code.
    pub const fn code(&self) -> Code {
        match self {
            Self::Stale { .. } => Code::StaleVersion,
            _ => Code::InvalidPolicy,
        }
    }
}
