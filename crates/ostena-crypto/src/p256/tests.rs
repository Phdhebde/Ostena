use aws_lc_rs::signature::UnparsedPublicKey;
use proptest::prelude::*;

use super::*;

fn key() -> SigningKey {
    SigningKey::generate().unwrap().0
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// RFC 6979 appendix A.2.5: the P-256 test key.
const RFC6979_X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const RFC6979_UX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const RFC6979_UY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

fn rfc6979_public() -> [u8; PUBLIC_KEY_LEN] {
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&hex::<32>(RFC6979_UX));
    pk[33..].copy_from_slice(&hex::<32>(RFC6979_UY));
    pk
}

fn signature(r: &[u8; 32], s: &[u8; 32]) -> Signature {
    let mut bytes = [0u8; SIGNATURE_LEN];
    bytes[..32].copy_from_slice(r);
    bytes[32..].copy_from_slice(s);
    Signature::from_bytes(&bytes)
}

fn one() -> [u8; 32] {
    let mut v = [0u8; 32];
    v[31] = 1;
    v
}

#[test]
fn half_n_is_n_minus_one_over_two() {
    // n − (n − 1)/2 = (n − 1)/2 + 1
    assert_eq!(sub(&sub(&N, &HALF_N), &HALF_N), one());
}

#[test]
fn sign_and_verify() {
    let k = key();
    let sig = k.sign(b"message").unwrap();
    assert!(k.verifying_key().verify(b"message", &sig).is_ok());
    assert_eq!(
        k.verifying_key().verify(b"messagf", &sig),
        Err(CryptoError::BadSignature)
    );
    assert_eq!(
        key().verifying_key().verify(b"message", &sig),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn signer_always_produces_low_s() {
    let k = key();
    for i in 0u32..200 {
        let (_, s) = k.sign(&i.to_be_bytes()).unwrap().parts();
        assert!(!less_than(&HALF_N, &s));
    }
}

#[test]
fn pkcs8_round_trip() {
    let (k, pkcs8) = SigningKey::generate().unwrap();
    let reloaded = SigningKey::from_pkcs8(&pkcs8).unwrap();
    assert_eq!(k.verifying_key(), reloaded.verifying_key());
    assert!(SigningKey::from_pkcs8(&SecretBytes::from(vec![0; 48])).is_err());
}

#[test]
fn rfc6979_key_from_pkcs8() {
    let key = SigningKey::from_pkcs8(&SecretBytes::from(rfc6979_pkcs8())).unwrap();
    assert_eq!(key.verifying_key().to_bytes(), rfc6979_public());
}

/// PKCS#8 wrapping of the RFC 6979 P-256 test scalar (public test vector),
/// without the optional public key. Also used for the fuzz seed corpus.
fn rfc6979_pkcs8() -> Vec<u8> {
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&hex::<32>(RFC6979_X));
    der
}

#[test]
fn rfc6979_low_s_vector_verifies() {
    // SHA-256, message "test": s is already in the low form.
    let key = VerifyingKey::from_bytes(&rfc6979_public()).unwrap();
    let sig = signature(
        &hex("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"),
        &hex("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"),
    );
    assert!(key.verify(b"test", &sig).is_ok());
}

#[test]
fn mathematically_valid_high_s_signature_is_refused() {
    // SHA-256, message "sample": the published s is in the high form.
    let pk = rfc6979_public();
    let r = hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    let high_s = hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    assert!(less_than(&HALF_N, &high_s));
    let high = signature(&r, &high_s);

    // The plain ECDSA verification accepts it...
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk)
            .verify(b"sample", &high.to_bytes())
            .is_ok()
    );
    // ...the strict one does not.
    let key = VerifyingKey::from_bytes(&pk).unwrap();
    assert_eq!(key.verify(b"sample", &high), Err(CryptoError::BadSignature));
    // Its low form (r, n − s) is the one accepted.
    assert!(
        key.verify(b"sample", &signature(&r, &sub(&N, &high_s)))
            .is_ok()
    );
}

#[test]
fn malleated_own_signature_is_refused() {
    let k = key();
    let (r, s) = k.sign(b"m").unwrap().parts();
    assert_eq!(
        k.verifying_key().verify(b"m", &signature(&r, &sub(&N, &s))),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn zero_r_is_refused() {
    let k = key();
    let (_, s) = k.sign(b"m").unwrap().parts();
    assert_eq!(
        k.verifying_key().verify(b"m", &signature(&[0; 32], &s)),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn zero_s_is_refused() {
    let k = key();
    let (r, _) = k.sign(b"m").unwrap().parts();
    assert_eq!(
        k.verifying_key().verify(b"m", &signature(&r, &[0; 32])),
        Err(CryptoError::BadSignature)
    );
}

#[test]
fn r_out_of_range_is_refused() {
    let k = key();
    let (_, s) = k.sign(b"m").unwrap().parts();
    for bad in [N, [0xff; 32]] {
        assert_eq!(
            k.verifying_key().verify(b"m", &signature(&bad, &s)),
            Err(CryptoError::BadSignature)
        );
    }
}

#[test]
fn s_out_of_range_is_refused() {
    let k = key();
    let (r, _) = k.sign(b"m").unwrap().parts();
    for bad in [N, [0xff; 32]] {
        assert_eq!(
            k.verifying_key().verify(b"m", &signature(&r, &bad)),
            Err(CryptoError::BadSignature)
        );
    }
}

#[test]
fn public_key_off_the_curve_is_refused() {
    let mut pk = rfc6979_public();
    pk[64] ^= 1;
    assert_eq!(VerifyingKey::from_bytes(&pk), Err(CryptoError::InvalidKey));
}

#[test]
fn public_key_in_another_encoding_is_refused() {
    let valid = rfc6979_public();
    for prefix in [0x00, 0x02, 0x03, 0x06, 0x07] {
        let mut pk = valid;
        pk[0] = prefix;
        assert_eq!(VerifyingKey::from_bytes(&pk), Err(CryptoError::InvalidKey));
    }
    assert_eq!(
        VerifyingKey::from_bytes(&[0; PUBLIC_KEY_LEN]),
        Err(CryptoError::InvalidKey)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_any_bit_flip_in_signature_is_refused(msg in proptest::collection::vec(any::<u8>(), 0..64), bit in 0usize..512) {
        let k = key();
        let mut sig = k.sign(&msg).unwrap().to_bytes();
        sig[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(k.verifying_key().verify(&msg, &Signature::from_bytes(&sig)).is_err());
    }
}

#[test]
fn scalar_round_trips_on_32_bytes() {
    for _ in 0..64 {
        let (key, _) = SigningKey::generate().unwrap();
        let scalar = key.scalar().unwrap();
        // SECRET-EXPOSURE: test only.
        #[expect(clippy::disallowed_methods)]
        let len = scalar.expose_secret().len();
        assert_eq!(len, 32);
        let again = SigningKey::from_scalar(&scalar).unwrap();
        assert_eq!(again.verifying_key(), key.verifying_key());
        let signature = again.sign(b"message").unwrap();
        key.verifying_key().verify(b"message", &signature).unwrap();
    }
}

#[test]
fn scalar_with_leading_zeros_is_kept_on_32_bytes() {
    let mut bytes = [0u8; 32];
    bytes[31] = 7;
    let key = SigningKey::from_scalar(&SecretBytes::from(bytes.to_vec())).unwrap();
    // SECRET-EXPOSURE: test only.
    #[expect(clippy::disallowed_methods)]
    let back = key.scalar().unwrap().expose_secret().to_vec();
    assert_eq!(back, bytes);
}

#[test]
fn invalid_scalars_are_refused() {
    for bad in [vec![0u8; 32], N.to_vec(), vec![1u8; 31], vec![1u8; 33]] {
        assert!(SigningKey::from_scalar(&SecretBytes::from(bad)).is_err());
    }
}
