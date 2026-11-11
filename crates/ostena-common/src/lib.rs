//! Shared foundations for every Ostena crate.
//!
//! - [`secret`]: `Secret<T>`, values that cannot be printed or logged.
//! - [`config`]: strict TOML configuration and its validation.
//! - [`logging`]: structured JSON logs with redaction of sensitive fields.

#![forbid(unsafe_code)]

pub mod config;
pub mod logging;
pub mod secret;

/// Product version, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver_like() {
        assert_eq!(VERSION.split('.').count(), 3);
    }
}
