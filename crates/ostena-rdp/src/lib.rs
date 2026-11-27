//! RDP driver of the agent (ADR-0019): the hardened connection sequence
//! towards a Windows target, with the TLS validated by `ostena-crypto`, the
//! CredSSP driven by the agent and a guard on the PDUs that carry security
//! decisions; Auto-Detect, RDS licences and the target profile; the session
//! loop (without image at M2).
#![forbid(unsafe_code)]

pub mod connect;
pub mod credssp;
pub mod driver;
pub mod error;
pub mod fuzz;
pub mod guard;
pub mod profile;
pub mod session;
pub mod target_sessions;
pub mod transport;

pub use error::RdpError;
