//! The only crate allowed to call cryptographic primitives.
//!
//! Every other crate goes through the API exposed here; algorithms are fixed
//! according to ANSSI guidelines and never negotiated. Empty during L0.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "ostena-crypto");
    }
}
