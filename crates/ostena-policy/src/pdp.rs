//! The policy decision point: the current compiled policy, replaced as a
//! whole, or invalidated (ADR-0022).

use std::sync::{Arc, PoisonError, RwLock};

use crate::compiled::CompiledPolicy;
use crate::decision::{Decision, Denied, Request};
use crate::error::{Code, PolicyError};

#[derive(Debug, Default)]
struct State {
    current: Option<Arc<CompiledPolicy>>,
    /// Highest version ever installed, kept after an invalidation.
    installed: Option<u64>,
}

/// The policy decision point of the core. Shared by the request handlers;
/// a decision takes the read lock only to clone the current policy, and
/// decides outside it.
#[derive(Debug, Default)]
pub struct Pdp {
    state: RwLock<State>,
}

/// What [`Pdp::install`] replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// The version now in place.
    pub version: u64,
    /// The version it replaced, if one was in place (not invalidated).
    pub previous: Option<u64>,
}

impl Pdp {
    /// A PDP without policy: everything is refused (`POL-E003`) until a
    /// policy is installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs `policy` in place of the current one. Its version must not
    /// be older than the highest version ever installed: a reload that
    /// finishes after a newer one never brings an older policy back. The
    /// same version is accepted again (a reload after an invalidation).
    ///
    /// # Errors
    ///
    /// [`PolicyError::Stale`] (`POL-E005`); the policy in place stays.
    pub fn install(&self, policy: Arc<CompiledPolicy>) -> Result<Installed, PolicyError> {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let offered = policy.version();
        if let Some(installed) = state.installed
            && offered < installed
        {
            return Err(PolicyError::Stale { installed, offered });
        }
        let previous = state.current.replace(policy).map(|p| p.version());
        state.installed = Some(offered);
        Ok(Installed {
            version: offered,
            previous,
        })
    }

    /// Drops the current policy: everything is refused (`POL-E003`) until
    /// the next [`Pdp::install`]. The core calls it when it cannot reload
    /// the policy after a change. Returns the version dropped, if any.
    pub fn invalidate(&self) -> Option<u64> {
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        state.current.take().map(|p| p.version())
    }

    /// The policy in place, if any.
    pub fn current(&self) -> Option<Arc<CompiledPolicy>> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .clone()
    }

    /// Decides `request` with the policy in place; without one, refused
    /// (`POL-E003`).
    pub fn decide(&self, request: &Request) -> Decision {
        match self.current() {
            Some(policy) => policy.decide(request),
            None => Decision::Deny(Denied {
                version: None,
                code: Code::Unavailable,
                rule: None,
            }),
        }
    }
}
