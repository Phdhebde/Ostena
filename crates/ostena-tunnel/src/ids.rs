//! UUID identifiers in their canonical text form.

use std::fmt;

/// A 128-bit identifier written `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// (lowercase hexadecimal).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Wraps 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// A random identifier.
    ///
    /// # Errors
    ///
    /// If the system random generator fails.
    pub fn random() -> Result<Self, ostena_crypto::CryptoError> {
        ostena_crypto::rand::array().map(Self)
    }

    /// Parses the canonical form only: 36 characters, lowercase, dashes at
    /// 8, 13, 18 and 23.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return None;
        }
        let mut out = [0u8; 16];
        let mut nibbles = bytes
            .iter()
            .enumerate()
            .filter(|(i, _)| !matches!(i, 8 | 13 | 18 | 23));
        if [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
            return None;
        }
        for byte in &mut out {
            let hi = hex(*nibbles.next()?.1)?;
            let lo = hex(*nibbles.next()?.1)?;
            *byte = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Uuid {
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

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({self})")
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn canonical_form_only() {
        let text = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
        let id = Uuid::parse(text).unwrap();
        assert_eq!(id.to_string(), text);
        for bad in [
            "2F6C9A4E-1B2C-4D5E-8F90-A1B2C3D4E5F6",
            "2f6c9a4e1b2c4d5e8f90a1b2c3d4e5f6",
            "{2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6}",
            "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f",
            "2f6c9a4e-1b2c-4d5e-8f90_a1b2c3d4e5f6",
            "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5fg",
            "",
        ] {
            assert_eq!(Uuid::parse(bad), None, "{bad}");
        }
    }

    proptest! {
        #[test]
        fn prop_round_trip(bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(bytes);
            prop_assert_eq!(Uuid::parse(&id.to_string()), Some(id));
        }

        #[test]
        fn prop_parse_never_panics(text in ".{0,40}") {
            let _ = Uuid::parse(&text);
        }
    }
}
