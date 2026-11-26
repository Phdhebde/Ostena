//! The session manager of the agent and the [`Driver`] trait of the
//! protocols (ADR-0018).
//!
//! One [`SessionManager`] per agent, shared by every protocol (SSH today,
//! RDP and the browser later): the quotas are those of the agent, not of a
//! protocol.
//!
//! - **Quotas**, checked and taken in one step under one lock: sessions of
//!   the agent, of one user, towards one target. A slot is
//!   [reserved](SessionManager::reserve) before the core is asked, so that a
//!   refused slot costs no request; it becomes a [`Session`] once the core
//!   gave its identifier, which must be unique (`SES-E004`).
//! - **Lengths**: maximum length (the shorter of the core's and of the
//!   agent's ceiling) and idle delay. [`Session::ended`] tells when and why a
//!   session must end; the driver then disconnects.
//! - **Cuts**: a revocation, the stop of the agent or a lost transcript cut
//!   a session, reserved or open ([`SessionManager::cut_where`]).
//! - **Observers** ([`Observer`]): told of each opening, refusal and end,
//!   outside the lock, for the audit and the recording.
//!
//! No database, no API, no I/O: the crate is tested alone.
//!
//! Codes: `SES-E001` to `SES-E005` ([`SessionError`]).

#![forbid(unsafe_code)]

mod driver;
mod error;
mod manager;

pub use driver::{Driver, DriverConnection};
pub use error::SessionError;
pub use manager::{
    Activity, Claim, EndReason, Ending, Limits, Observer, Protocol, Reservation, Session,
    SessionInfo, SessionManager,
};
