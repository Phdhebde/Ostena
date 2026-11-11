//! Short-lived session grants.
//!
//! Will host EdDSA (Ed25519) grant signing and verification, key sets indexed
//! by `kid` and persistent anti-replay. A grant carries the authorization,
//! never the secret. Empty during L0.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "ostena-grant");
    }
}
