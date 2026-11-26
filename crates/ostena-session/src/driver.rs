//! The trait the protocol drivers implement (ADR-0018): how the agent
//! reaches a target, SSH today, RDP and the web applications later.
//!
//! A driver is given a [`PinnedTarget`] and nothing else to dial: its
//! addresses passed the scope control (allowed networks, floor, resolution
//! pinned; ADR-0005). The control is thus applied to every driver by type,
//! not by convention. What the driver plays towards the target
//! (authentication, pinned key or certificate) is in its own
//! [`Driver::Params`].

use std::time::Duration;

use ostena_scope::PinnedTarget;

use crate::manager::Protocol;

/// A protocol driver: joins a target for a session.
pub trait Driver: Send + Sync + 'static {
    /// What the driver needs besides the target: account, pinned host key
    /// or certificate, a reference to the credential to play…
    type Params: Send;
    /// An authenticated connection to the target.
    type Connection: DriverConnection;
    /// Why the target cannot be joined; each driver has its stable codes
    /// and emits its events.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The protocol, for the quotas and the events.
    const PROTOCOL: Protocol;

    /// Joins `target` within `timeout`: connection, verification of the
    /// target (pinned key or certificate) and authentication.
    fn connect(
        &self,
        target: &PinnedTarget,
        params: Self::Params,
        timeout: Duration,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send;
}

/// A connection opened by a [`Driver`].
pub trait DriverConnection: Send + Sync + 'static {
    /// Closes the connection to the target (bounded by the driver).
    fn close(&self) -> impl Future<Output = ()> + Send;

    /// Whether the target closed the connection.
    fn is_closed(&self) -> bool;
}
