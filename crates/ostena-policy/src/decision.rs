//! A request to the PDP and its decision (ADR-0022).

use crate::error::Code;
use crate::model::{AccountId, Functions, Protocol, RuleId, UserId};

/// Can `user` open an access to `account` with `protocol` at `now`?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The user, already authenticated and active.
    pub user: UserId,
    /// The account on the target.
    pub account: AccountId,
    /// The protocol.
    pub protocol: Protocol,
    /// Functions the caller needs (for example those signed in a grant,
    /// checked again when the session opens). Only orders the allowing
    /// rules: [`Allowed::missing`] tells what was not granted.
    pub wanted: Functions,
    /// Now, Unix seconds.
    pub now: u64,
}

/// The decision, with what the audit record needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allowed.
    Allow(Allowed),
    /// Refused.
    Deny(Denied),
}

impl Decision {
    /// Whether the access is allowed.
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }

    /// The policy version that decided; `None` when no policy was
    /// installed.
    pub const fn version(&self) -> Option<u64> {
        match self {
            Self::Allow(a) => Some(a.version),
            Self::Deny(d) => d.version,
        }
    }
}

/// An allowed access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    /// The policy version that decided.
    pub version: u64,
    /// The allowing rule retained.
    pub rule: RuleId,
    /// Functions granted, for the protocol, after the refused ones were
    /// taken away.
    pub functions: Functions,
    /// Functions wanted (for the protocol) and not granted.
    pub missing: Functions,
    /// When a refusal of functions took some of the retained rule away: the
    /// smallest identifier among the refusals of functions that apply.
    pub restricted_by: Option<RuleId>,
    /// Longest session now: the rule's, and no later than its end.
    pub max_session_secs: u32,
    /// End of validity of the retained rule, Unix seconds.
    pub valid_until: u64,
}

/// A refused access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The policy version that decided; `None` when none is installed.
    pub version: Option<u64>,
    /// Why: [`Code::NoRule`], [`Code::DeniedByRule`] or
    /// [`Code::Unavailable`].
    pub code: Code,
    /// For [`Code::DeniedByRule`], the refusing rule (the smallest
    /// identifier when several apply).
    pub rule: Option<RuleId>,
}
