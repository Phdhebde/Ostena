//! Randomness from the operating system generator.

use aws_lc_rs::rand::SecureRandom;

use crate::CryptoError;

/// Fills `buf` with random bytes.
///
/// # Errors
///
/// [`CryptoError::Random`] if the system generator fails.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    aws_lc_rs::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| CryptoError::Random)
}

/// Returns `N` random bytes.
///
/// # Errors
///
/// [`CryptoError::Random`] if the system generator fails.
pub fn array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        let a: [u8; 32] = array().unwrap();
        let b: [u8; 32] = array().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
