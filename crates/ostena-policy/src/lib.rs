//! The policy decision point (PDP) of the core and the separate
//! administration roles (ADR-0022).
//!
//! - [`Snapshot`]: one version of the policy as the core read it: members
//!   of the groups of users and of accounts, and the [`Rule`]s (subject:
//!   user or group of users; target: account or group of accounts;
//!   protocols; effect: allow with functions, deny, or deny functions;
//!   validity window).
//! - [`CompiledPolicy::compile`] checks and indexes it once; a decision
//!   then reads only the rules of the account and of its groups, without
//!   allocation.
//! - [`Pdp`] holds the policy in place; the core [installs](Pdp::install) a
//!   new version as a whole after each change, never an older one, and
//!   [invalidates](Pdp::invalidate) it when it cannot reload.
//! - Refused by default; a refusal wins over any allowance
//!   ([`CompiledPolicy::decide`]).
//! - [`roles`]: the audit role is incompatible with the roles that can
//!   widen an access.
//!
//! No database, no API, no I/O: the crate is tested alone.
//!
//! Codes: `POL-E001` to `POL-E006` ([`Code`]).

#![forbid(unsafe_code)]

mod compiled;
mod decision;
mod error;
mod model;
mod pdp;
pub mod roles;

pub use compiled::{
    CompiledPolicy, MAX_ALLOW_SECS, MAX_ITEMS, MAX_SESSION_SECS, MIN_SESSION_SECS, Stats,
};
pub use decision::{Allowed, Decision, Denied, Request};
pub use error::{Code, PolicyError};
pub use model::{
    AccountGroupId, AccountId, Effect, Function, Functions, Protocol, Protocols, Rule, RuleId,
    Snapshot, Subject, Target, UserGroupId, UserId,
};
pub use pdp::{Installed, Pdp};
