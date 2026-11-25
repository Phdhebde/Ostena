//! Fixed-size identifiers carried by a grant.

use std::fmt;

use ostena_crypto::CryptoError;
use ostena_crypto::p256::VerifyingKey;

macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Wraps 16 bytes (UUID binary form).
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// The 16 bytes.
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Display for $name {
            /// UUID text form, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for (i, b) in self.0.iter().enumerate() {
                    if matches!(i, 4 | 6 | 8 | 10) {
                        f.write_str("-")?;
                    }
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }
    };
}

uuid_id! {
    /// Unique grant identifier, random, consumed once (anti-replay).
    Jti
}
uuid_id! {
    /// User identifier in the core.
    SubjectId
}
uuid_id! {
    /// Target identifier in the inventory.
    ResourceId
}
uuid_id! {
    /// Gateway group a grant is meant for (audience).
    GatewayGroupId
}

impl Jti {
    /// A fresh random identifier.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if the system generator fails.
    pub fn random() -> Result<Self, CryptoError> {
        ostena_crypto::rand::array().map(Self)
    }
}

/// What a grant is bound to besides its claims: the login session of the
/// user and the account on the target (ADR-0004, format v2).
///
/// `SHA-256("ostena-grant-binding-v1\0" ‖ login session ‖ account length
/// (u16, big-endian) ‖ account)`, truncated to 128 bits. The verifier
/// recomputes it from what it knows and compares; it never reads the login
/// session or the account back from a grant.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Binding([u8; 16]);

/// Domain separation prefix of [`Binding`].
const BINDING_DOMAIN: &[u8] = b"ostena-grant-binding-v1\0";

impl Binding {
    /// The binding of `login_session` (UUID bytes) and `account`.
    ///
    /// An account is at most 256 bytes on every path (SSH login, tunnel);
    /// a longer one is cut at `u16::MAX` bytes for the length prefix, which
    /// keeps the function total: such an account never gets a grant.
    pub fn of(login_session: [u8; 16], account: &str) -> Self {
        let account = account.as_bytes();
        let account = &account[..account.len().min(usize::from(u16::MAX))];
        let len = u16::try_from(account.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes();
        let digest =
            ostena_crypto::sha256::digest_concat(&[BINDING_DOMAIN, &login_session, &len, account]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        Self(out)
    }

    /// Wraps 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Binding(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// Key identifier: the first 8 bytes of SHA-256 of the public key in its
/// uncompressed SEC1 form (65 bytes, `0x04 ‖ x ‖ y`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kid([u8; 8]);

impl Kid {
    /// The identifier of a public key.
    pub fn of(key: &VerifyingKey) -> Self {
        let digest = ostena_crypto::sha256::digest(&key.to_bytes());
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&digest[..8]);
        Self(kid)
    }

    /// Wraps 8 bytes.
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// The 8 bytes.
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_text_form() {
        let id = ResourceId::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        assert_eq!(id.to_string(), "12345678-9abc-def0-0123-456789abcdef");
        assert_eq!(
            format!("{id:?}"),
            "ResourceId(12345678-9abc-def0-0123-456789abcdef)"
        );
    }

    #[test]
    fn binding_separates_session_and_account() {
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        assert_eq!(Binding::of(s1, "root"), Binding::of(s1, "root"));
        assert_ne!(Binding::of(s1, "root"), Binding::of(s2, "root"));
        assert_ne!(Binding::of(s1, "root"), Binding::of(s1, "admin"));
        // The length prefix keeps the account from sliding into the session.
        assert_ne!(Binding::of(s1, "a"), Binding::of(s1, "a\0"));
        // Fixed vector: changing the construction breaks deployed agents.
        let digest = ostena_crypto::sha256::digest(
            &[
                b"ostena-grant-binding-v1\0".as_slice(),
                &s1,
                &[0, 4],
                b"root",
            ]
            .concat(),
        );
        assert_eq!(Binding::of(s1, "root").to_bytes(), digest[..16]);
    }

    #[test]
    fn kid_is_derived_from_the_key() {
        let a = ostena_crypto::p256::SigningKey::generate().unwrap().0;
        let b = ostena_crypto::p256::SigningKey::generate().unwrap().0;
        assert_eq!(Kid::of(&a.verifying_key()), Kid::of(&a.verifying_key()));
        assert_ne!(Kid::of(&a.verifying_key()), Kid::of(&b.verifying_key()));
        assert_eq!(Kid::of(&a.verifying_key()).to_string().len(), 16);
    }
}
