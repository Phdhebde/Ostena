//! Fixed-size identifiers carried by a grant.

use std::fmt;

use ostena_crypto::CryptoError;
use ostena_crypto::ed25519::VerifyingKey;

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

/// Key identifier: the first 8 bytes of SHA-256 of the public key.
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
    fn kid_is_derived_from_the_key() {
        let a = ostena_crypto::ed25519::SigningKey::generate().unwrap().0;
        let b = ostena_crypto::ed25519::SigningKey::generate().unwrap().0;
        assert_eq!(Kid::of(&a.verifying_key()), Kid::of(&a.verifying_key()));
        assert_ne!(Kid::of(&a.verifying_key()), Kid::of(&b.verifying_key()));
        assert_eq!(Kid::of(&a.verifying_key()).to_string().len(), 16);
    }
}
