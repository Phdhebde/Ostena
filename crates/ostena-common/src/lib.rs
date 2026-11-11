//! Shared foundations for every Ostena crate.
//!
//! Will host strict TOML configuration, typed errors, structured logging,
//! metrics and `Secret<…>` types. Empty during L0.

#![forbid(unsafe_code)]

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
