//! Single resolution and pinning (ADR-0005).
//!
//! A name is resolved once; every returned address must pass the policy, or
//! the target is refused (no silent filtering). Drivers then connect only to
//! the addresses in the [`PinnedTarget`], which closes the door to DNS
//! rebinding.

use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::error::{Refusal, ScopeError};
use crate::local::SharedLocalAddresses;
use crate::policy::CompiledPolicy;
use crate::target::{Host, Hostname, Target};

/// Largest number of addresses accepted in one answer.
pub const MAX_ADDRESSES: usize = 32;

/// The resolver failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ResolveError(pub String);

/// Name resolution, behind a trait for tests.
pub trait Resolver {
    /// Every address of `name`, in the resolver's preference order.
    fn resolve(
        &self,
        name: &Hostname,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send;
}

/// The operating system resolver (`getaddrinfo`): it honours the client's DNS
/// (Active Directory), hosts file and search suffixes.
///
/// `getaddrinfo` blocks and cannot be cancelled: each resolution runs on its
/// own thread, the answer is abandoned after `timeout`, and a thread still
/// running counts towards `max_in_flight` until it returns.
#[derive(Debug, Clone)]
pub struct SystemResolver {
    timeout: Duration,
    max_in_flight: usize,
    in_flight: Arc<AtomicUsize>,
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new(Duration::from_secs(3), 32)
    }
}

impl SystemResolver {
    /// A resolver with a timeout and a bound on concurrent resolutions.
    pub fn new(timeout: Duration, max_in_flight: usize) -> Self {
        Self {
            timeout,
            max_in_flight: max_in_flight.max(1),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

type Answer = Result<Vec<IpAddr>, ResolveError>;

#[derive(Default)]
struct Slot {
    answer: Option<Answer>,
    waker: Option<Waker>,
}

fn complete(slot: &Mutex<Slot>, answer: Answer) {
    if let Ok(mut s) = slot.lock()
        && s.answer.is_none()
    {
        s.answer = Some(answer);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
}

/// Future completed by the resolution thread or by the timeout thread.
struct SlotFuture(Arc<Mutex<Slot>>);

impl Future for SlotFuture {
    type Output = Answer;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answer> {
        let Ok(mut s) = self.0.lock() else {
            return Poll::Ready(Err(ResolveError("état du résolveur corrompu".into())));
        };
        if let Some(answer) = s.answer.take() {
            Poll::Ready(answer)
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, name: &Hostname) -> impl Future<Output = Answer> + Send {
        let slot = Arc::new(Mutex::new(Slot::default()));
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= self.max_in_flight {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            complete(
                &slot,
                Err(ResolveError("trop de résolutions simultanées".into())),
            );
            return SlotFuture(slot);
        }
        let host = name.as_str().to_owned();
        let in_flight = Arc::clone(&self.in_flight);
        let worker_slot = Arc::clone(&slot);
        let worker = std::thread::Builder::new()
            .name("ostena-scope-resolve".into())
            .spawn(move || {
                let answer = (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|it| it.map(|s| s.ip()).collect())
                    .map_err(|e| ResolveError(e.to_string()));
                in_flight.fetch_sub(1, Ordering::AcqRel);
                complete(&worker_slot, answer);
            });
        if let Err(e) = worker {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            complete(
                &slot,
                Err(ResolveError(format!("thread de résolution : {e}"))),
            );
            return SlotFuture(slot);
        }
        let timer_slot = Arc::clone(&slot);
        let timeout = self.timeout;
        let timer = std::thread::Builder::new()
            .name("ostena-scope-timeout".into())
            .spawn(move || {
                std::thread::sleep(timeout);
                complete(
                    &timer_slot,
                    Err(ResolveError(format!(
                        "délai de {} s dépassé",
                        timeout.as_secs()
                    ))),
                );
            });
        if timer.is_err() {
            // Without a timer, wait for getaddrinfo itself.
            tracing::warn!(
                event = "scope.resolve_timer_failed",
                "délai de résolution non appliqué"
            );
        }
        SlotFuture(slot)
    }
}

/// A target whose every address passed the policy. Drivers must connect only
/// to [`PinnedTarget::addrs`]; the name is kept for TLS SNI, Kerberos SPNs
/// and certificate checks, never to resolve again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    addrs: Vec<SocketAddr>,
    name: Option<Hostname>,
}

impl PinnedTarget {
    /// Verified addresses, in the resolver's preference order (at most
    /// [`MAX_ADDRESSES`], never empty).
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The requested name, if the target was a name.
    pub fn name(&self) -> Option<&Hostname> {
        self.name.as_ref()
    }
}

/// Policy, gateway addresses and resolver of one gateway group.
#[derive(Debug)]
pub struct Scope<R> {
    policy: Arc<CompiledPolicy>,
    local: SharedLocalAddresses,
    resolver: R,
}

impl<R: Resolver + Sync> Scope<R> {
    /// Assembles a scope.
    pub fn new(policy: Arc<CompiledPolicy>, local: SharedLocalAddresses, resolver: R) -> Self {
        Self {
            policy,
            local,
            resolver,
        }
    }

    /// The compiled policy.
    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    /// Parses `host`, resolves it once and checks every address. Emits
    /// `scope.pinned` or `scope.refused`.
    ///
    /// # Errors
    ///
    /// [`ScopeError`], whose code is also in the event.
    pub async fn pin(&self, host: &str, port: u16) -> Result<PinnedTarget, ScopeError> {
        let result = match Target::new(host, port) {
            Ok(target) => self.pin_target(&target).await,
            Err(source) => Err(ScopeError::Target {
                requested: format!("{host}:{port}"),
                source,
            }),
        };
        match &result {
            Ok(pinned) => tracing::info!(
                event = "scope.pinned",
                requested = %format_args!("{host}:{port}"),
                addresses = ?pinned.addrs,
                gateway_group = self.policy.gateway_group(),
            ),
            Err(e) => self.log_refusal(host, port, e),
        }
        result
    }

    async fn pin_target(&self, target: &Target) -> Result<PinnedTarget, ScopeError> {
        let requested = target.to_string();
        let local = self.local.snapshot();
        let (ips, name) = match target.host() {
            Host::Ip(ip) => (vec![*ip], None),
            Host::Name(name) => {
                if name.is_short() {
                    if !self.policy.allow_short_names() {
                        return Err(ScopeError::ShortName { requested });
                    }
                    tracing::info!(event = "scope.short_name_used", requested = %requested);
                }
                let mut ips =
                    self.resolver
                        .resolve(name)
                        .await
                        .map_err(|e| ScopeError::Resolution {
                            requested: requested.clone(),
                            reason: e.0,
                        })?;
                dedup_keep_order(&mut ips);
                if ips.is_empty() {
                    return Err(ScopeError::Resolution {
                        requested,
                        reason: "aucune adresse".into(),
                    });
                }
                if ips.len() > MAX_ADDRESSES {
                    return Err(ScopeError::Resolution {
                        requested,
                        reason: format!(
                            "{} adresses, au-delà du maximum de {MAX_ADDRESSES}",
                            ips.len()
                        ),
                    });
                }
                (ips, Some(name.clone()))
            }
        };
        let via_name = name.is_some();
        let mut addrs = Vec::with_capacity(ips.len());
        for ip in ips {
            let addr = SocketAddr::new(ip, target.port());
            match self.policy.check(addr, &local) {
                Ok(allowed) => {
                    if let Some(i) = allowed.floor_exception {
                        tracing::warn!(
                            event = "scope.floor_exception_used",
                            requested = %requested,
                            address = %addr,
                            reason = self.policy.exception_reason(i),
                        );
                    }
                    addrs.push(addr);
                }
                Err(refusal) => return Err(self.refused(requested, refusal, via_name)),
            }
        }
        Ok(PinnedTarget { addrs, name })
    }

    fn refused(&self, requested: String, refusal: Refusal, via_name: bool) -> ScopeError {
        ScopeError::Refused {
            requested,
            address: SocketAddr::new(refusal.address, refusal.port).to_string(),
            rule: self.policy.describe(refusal.rule),
            refusal,
            via_name,
        }
    }

    fn log_refusal(&self, host: &str, port: u16, e: &ScopeError) {
        let (address, original, rule) = match e {
            ScopeError::Refused { refusal, .. } => (
                Some(SocketAddr::new(refusal.address, refusal.port).to_string()),
                refusal.original.map(|o| o.to_string()),
                Some(self.policy.rule_id(refusal.rule)),
            ),
            _ => (None, None, None),
        };
        tracing::warn!(
            event = "scope.refused",
            code = e.code().as_str(),
            requested = %format_args!("{host}:{port}"),
            address = address.as_deref().unwrap_or(""),
            original_address = original.as_deref().unwrap_or(""),
            rule = rule.as_deref().unwrap_or(""),
            gateway_group = self.policy.gateway_group(),
            "{e}"
        );
    }
}

fn dedup_keep_order(ips: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(ips.len());
    ips.retain(|ip| {
        if seen.contains(ip) {
            false
        } else {
            seen.push(*ip);
            true
        }
    });
}

#[cfg(test)]
mod tests;
