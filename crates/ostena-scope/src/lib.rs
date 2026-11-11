//! Target scope control and anti-SSRF (ADR-0005), used by every driver.
//!
//! 1. [`target`] — strict parsing: ambiguous numeric forms, non-ASCII names,
//!    zone identifiers and reserved names are refused before any resolution.
//! 2. [`resolve`] — a name is resolved once; every address must pass.
//! 3. [`net::normalize`] — an IPv4 hidden in IPv6 is judged as the IPv4.
//! 4. [`policy`] — floor, then deny, then allow with ports, without allocation.
//!
//! Drivers receive a [`PinnedTarget`] and connect only to its addresses.

#![forbid(unsafe_code)]

mod date;
mod error;
pub mod floor;
pub mod local;
pub mod net;
pub mod policy;
pub mod resolve;
pub mod target;

#[doc(hidden)]
pub mod fuzz;

pub use error::{Code, Refusal, Rule, ScopeError};
pub use floor::FloorCause;
pub use local::{LocalAddresses, Refresher, SharedLocalAddresses};
pub use net::{Network, PortRange, normalize};
pub use policy::{
    AllowRuleSpec, Allowed, CompiledPolicy, DenyRuleSpec, FloorExceptionSpec, InfrastructureRole,
    InfrastructureSpec, PolicyError, PolicySpec, ShortNames,
};
pub use resolve::{Clock, PinnedTarget, ResolveError, Resolver, Scope, SystemResolver};
pub use target::{Host, Hostname, Target, TargetError, parse_host};
