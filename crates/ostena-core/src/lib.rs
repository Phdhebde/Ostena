//! The core (ADR-0011): agent registry and enrolment tokens in PostgreSQL,
//! tunnel and enrolment listeners, audit chain (ADR-0012), minimal
//! inventory and native SSH authorisation (ADR-0014), HTTPS login API
//! (ADR-0015).

#![forbid(unsafe_code)]

pub mod access;
pub mod api;
pub mod audit;
pub mod cache;
pub mod credential;
pub mod db;
mod error;
pub mod grant_keys;
pub mod inventory;
pub mod login;
pub mod pushes;
pub mod rate;
pub mod schema;
pub mod server;
pub mod ssh_ca;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;

pub use error::CoreError;
