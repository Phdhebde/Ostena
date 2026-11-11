//! Secret values that cannot be printed, logged or silently copied.
//!
//! [`Secret<T>`] wraps [`secrecy::SecretBox`]: the value lives on the heap and
//! is zeroized on drop. Unlike `secrecy`, it implements neither `Debug` nor
//! `Display` (not even a redacted form), so it cannot be formatted, turned into
//! a `String` or recorded as a `tracing` field. The `tests/ui` compile-fail
//! tests prove it.
//!
//! Reading the value goes through [`Secret::expose_secret`], which is a
//! `clippy::disallowed_methods` entry: every call site needs
//! `#[expect(clippy::disallowed_methods)]` right below a
//! `// SECRET-EXPOSURE: <reason>` comment, checked by `cargo xtask check-secrets`.

use std::fmt;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::Zeroize;

/// A secret value, zeroized on drop, with no formatting or conversion.
///
/// Deliberately missing: `Debug`, `Display`, `Clone`, `PartialEq`, `Serialize`,
/// `Deserialize` and any conversion to `String`. Constant-time comparison
/// belongs to `ostena-crypto`.
pub struct Secret<T: Zeroize + ?Sized>(SecretBox<T>);

/// A UTF-8 secret, such as a password.
pub type SecretString = Secret<str>;

/// A binary secret, such as key material.
pub type SecretBytes = Secret<[u8]>;

impl<T: Zeroize + ?Sized> Secret<T> {
    /// Takes ownership of a boxed value.
    pub fn new(value: Box<T>) -> Self {
        Self(SecretBox::new(value))
    }

    /// Gives read access to the secret value.
    ///
    /// Disallowed by clippy: see the module documentation.
    pub fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }

    /// Gives write access to the secret value.
    ///
    /// Disallowed by clippy: see the module documentation.
    pub fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }

    /// A placeholder for hand-written `Debug` implementations of types that
    /// hold a secret: it prints `[REDACTED]` and carries nothing.
    pub fn redacted(&self) -> Redacted {
        Redacted
    }
}

impl From<String> for SecretString {
    /// Copies into an exactly sized allocation, then zeroizes the source, so no
    /// spare capacity is freed without being wiped.
    fn from(mut value: String) -> Self {
        let boxed: Box<str> = Box::from(value.as_str());
        value.zeroize();
        Self::new(boxed)
    }
}

impl From<Vec<u8>> for SecretBytes {
    /// Same as the `String` conversion: the source buffer is zeroized.
    fn from(mut value: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = Box::from(value.as_slice());
        value.zeroize();
        Self::new(boxed)
    }
}

/// Marker printed as `[REDACTED]`, see [`Secret::redacted`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Redacted;

impl Redacted {
    /// The text printed in place of a secret, everywhere in Ostena.
    pub const TEXT: &'static str = "[REDACTED]";
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::TEXT)
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::TEXT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_round_trip() {
        let secret = SecretString::from("hunter2".to_owned());
        // SECRET-EXPOSURE: test checks the stored value.
        #[expect(clippy::disallowed_methods)]
        let exposed = secret.expose_secret();
        assert_eq!(exposed, "hunter2");
    }

    #[test]
    fn bytes_can_be_mutated() {
        let mut secret = SecretBytes::from(vec![1, 2, 3]);
        // SECRET-EXPOSURE: test mutates then checks the stored value.
        #[expect(clippy::disallowed_methods)]
        {
            secret.expose_secret_mut()[0] = 9;
            assert_eq!(secret.expose_secret(), &[9, 2, 3]);
        }
    }

    #[test]
    fn redacted_prints_placeholder() {
        let secret = SecretString::from("hunter2".to_owned());
        assert_eq!(format!("{:?}", secret.redacted()), "[REDACTED]");
        assert_eq!(secret.redacted().to_string(), "[REDACTED]");
    }
}
