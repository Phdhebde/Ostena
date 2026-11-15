//! The SSH user name `account@resource` (ADR-0010): `ssh root@srv-lab01@bastion`
//! gives the account `root` on the resource `srv-lab01`.
//!
//! Split at the **last** `@`, so that an account holding one stays whole
//! (`admin@corp.local@srv-lab01`). The agent never resolves the resource:
//! the core maps it to a target of its inventory. Pure, fuzzed alone
//! (`ssh_login`).

/// Longest account, in bytes.
pub const MAX_ACCOUNT: usize = 256;
/// Longest resource name, in bytes.
pub const MAX_RESOURCE: usize = 63;

/// An account on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Login<'a> {
    /// Account on the target, 1 to 256 bytes, no control character, no
    /// leading or trailing space.
    pub account: &'a str,
    /// Resource name, `[a-z0-9][a-z0-9.-]{0,62}`.
    pub resource: &'a str,
}

/// Why a user name is refused (`SSH-E010`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoginError {
    /// No `@`.
    #[error("[SSH-E010] nom d'utilisateur invalide : attendu compte@ressource")]
    NoResource,
    /// Invalid account.
    #[error("[SSH-E010] compte invalide : {0}")]
    Account(&'static str),
    /// Invalid resource name.
    #[error("[SSH-E010] nom de ressource invalide : {0}")]
    Resource(&'static str),
}

impl LoginError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        "SSH-E010"
    }
}

/// Whether `account` is acceptable: 1 to [`MAX_ACCOUNT`] bytes, no control
/// character, no leading or trailing white space.
///
/// # Errors
///
/// [`LoginError::Account`].
pub fn check_account(account: &str) -> Result<(), LoginError> {
    if account.is_empty() || account.len() > MAX_ACCOUNT {
        return Err(LoginError::Account("de 1 à 256 octets"));
    }
    if account.chars().any(char::is_control) {
        return Err(LoginError::Account("caractère de contrôle"));
    }
    if account.starts_with(char::is_whitespace) || account.ends_with(char::is_whitespace) {
        return Err(LoginError::Account("espace en début ou en fin"));
    }
    Ok(())
}

/// Whether `resource` is a valid resource name.
///
/// # Errors
///
/// [`LoginError::Resource`].
pub fn check_resource(resource: &str) -> Result<(), LoginError> {
    let bytes = resource.as_bytes();
    let Some(first) = bytes.first() else {
        return Err(LoginError::Resource("vide"));
    };
    if bytes.len() > MAX_RESOURCE {
        return Err(LoginError::Resource("plus de 63 caractères"));
    }
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(LoginError::Resource("doit commencer par [a-z0-9]"));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return Err(LoginError::Resource("caractères admis : [a-z0-9.-]"));
    }
    Ok(())
}

/// Splits `user` at its last `@`.
///
/// # Errors
///
/// [`LoginError`] (`SSH-E010`).
pub fn parse_login(user: &str) -> Result<Login<'_>, LoginError> {
    let (account, resource) = user.rsplit_once('@').ok_or(LoginError::NoResource)?;
    check_resource(resource)?;
    check_account(account)?;
    Ok(Login { account, resource })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn split_at_the_last_at_sign() {
        assert_eq!(
            parse_login("root@srv-lab01"),
            Ok(Login {
                account: "root",
                resource: "srv-lab01"
            })
        );
        assert_eq!(
            parse_login("admin@corp.local@srv-lab01"),
            Ok(Login {
                account: "admin@corp.local",
                resource: "srv-lab01"
            })
        );
        assert_eq!(
            parse_login("CORP\\Jean Dupont@db.01"),
            Ok(Login {
                account: "CORP\\Jean Dupont",
                resource: "db.01"
            })
        );
        assert_eq!(
            parse_login(&format!("{}@a", "x".repeat(256))).map(|l| l.account.len()),
            Ok(256)
        );
        assert!(parse_login(&format!("x@{}", "a".repeat(63))).is_ok());
    }

    #[test]
    fn refusals() {
        for bad in [
            "root",
            "root@",
            "@srv",
            "root@Srv",
            "root@-srv",
            "root@.srv",
            "root@srv_01",
            "root@srv 01",
            "root@srvé",
            " root@srv",
            "root @srv",
            "ro\tot@srv",
            "ro\u{7f}ot@srv",
            "ro\u{85}ot@srv",
        ] {
            let e = parse_login(bad).unwrap_err();
            assert_eq!(e.code(), "SSH-E010", "{bad}");
            assert!(e.to_string().starts_with("[SSH-E010]"), "{bad}");
        }
        assert!(parse_login(&format!("{}@a", "x".repeat(257))).is_err());
        assert!(parse_login(&format!("x@{}", "a".repeat(64))).is_err());
    }

    proptest! {
        /// Never panics; what is accepted rebuilds the input.
        #[test]
        fn prop_accepted_logins_rebuild_the_input(user in "\\PC{0,80}") {
            if let Ok(login) = parse_login(&user) {
                prop_assert_eq!(format!("{}@{}", login.account, login.resource), user.as_str());
                prop_assert!(!login.resource.contains('@'));
            }
        }

        #[test]
        fn prop_valid_parts_are_accepted(
            account in "[a-zA-Z0-9_.@\\\\-]([a-zA-Z0-9_. @\\\\-]{0,30}[a-zA-Z0-9_.@\\\\-])?",
            resource in "[a-z0-9][a-z0-9.-]{0,62}",
        ) {
            let user = format!("{account}@{resource}");
            let login = parse_login(&user).unwrap();
            prop_assert_eq!(login.account, account.as_str());
            prop_assert_eq!(login.resource, resource.as_str());
        }
    }
}
