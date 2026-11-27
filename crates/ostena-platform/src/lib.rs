//! Operating system integration (ADR-0007): permission checks, and in the
//! next lots services and local IPC.
//!
//! This is the only crate allowed to contain `unsafe` code, confined to the
//! Windows FFI modules and the terminal modes ([`tty`]). Every `unsafe`
//! block carries a `// SAFETY:` comment (enforced by
//! `clippy::undocumented_unsafe_blocks`) and is exercised by a test.

#![warn(clippy::undocumented_unsafe_blocks)]

pub mod acl;
pub mod control;
mod error;
pub mod memory;
pub mod private_file;
pub mod service;
pub mod tty;
pub mod wts;

pub use error::{Code, PlatformError};

use ostena_common::config::PermissionChecker;

/// The permission checker of this platform: Unix permissions (from
/// `ostena-common`) or Windows ACLs.
pub fn permission_checker() -> &'static dyn PermissionChecker {
    #[cfg(windows)]
    {
        &acl::WindowsPermissions
    }
    #[cfg(not(windows))]
    {
        &ostena_common::config::DefaultPermissions
    }
}
