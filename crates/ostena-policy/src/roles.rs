//! Separate administration roles (ADR-0022).
//!
//! Whoever can widen an access must not also be the one who reads the
//! trace of it. The audit role is therefore incompatible with every role
//! that can widen an access: the policies, and the administration of the
//! users and of the inventory (a membership added to a group is an access
//! granted). The core refuses the cumulation when a role is given, and at
//! start for the roles already given, unless an explicit, justified and
//! dated option allows it ([`Separation::CumulationAllowed`]).

use crate::error::Code;

/// One administration role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdminRole {
    /// Users, groups and inventory.
    Admin,
    /// Authorization rules.
    Policy,
    /// Read the audit chain, the sessions and their transcripts; nothing
    /// else.
    Audit,
}

impl AdminRole {
    /// Every role.
    pub const ALL: [Self; 3] = [Self::Admin, Self::Policy, Self::Audit];

    /// Its name, as stored and typed.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Policy => "policy",
            Self::Audit => "audit",
        }
    }

    /// The role of `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }

    /// Whether the role can widen an access.
    pub const fn widens_access(self) -> bool {
        matches!(self, Self::Admin | Self::Policy)
    }

    /// Whether one account may hold both roles under strict separation.
    pub const fn compatible(self, other: Self) -> bool {
        !matches!(
            (self, other),
            (Self::Audit, Self::Admin | Self::Policy) | (Self::Admin | Self::Policy, Self::Audit)
        )
    }
}

/// Whether incompatible roles may be held by one account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Separation {
    /// Refused (default, and the only choice in production without an
    /// explicit option).
    #[default]
    Strict,
    /// Allowed by an explicit option: logged at each start (ADR-0022).
    CumulationAllowed,
}

/// Two roles that one account may not hold together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("POL-E006: rôles {} et {} incompatibles pour un même compte", .held.name(), .asked.name())]
pub struct Cumulation {
    /// A role the account holds.
    pub held: AdminRole,
    /// The role that conflicts with it.
    pub asked: AdminRole,
}

impl Cumulation {
    /// Its stable code.
    pub const fn code(&self) -> Code {
        Code::RoleCumulation
    }
}

/// Checks that an account holding `held` may also receive `asked`.
///
/// # Errors
///
/// [`Cumulation`] (`POL-E006`) under [`Separation::Strict`].
pub fn check_grant(
    held: &[AdminRole],
    asked: AdminRole,
    separation: Separation,
) -> Result<(), Cumulation> {
    if separation == Separation::CumulationAllowed {
        return Ok(());
    }
    match held.iter().find(|h| !h.compatible(asked)) {
        Some(&held) => Err(Cumulation { held, asked }),
        None => Ok(()),
    }
}

/// The first pair of incompatible roles in `roles`, if any (the check at
/// start of the roles already given).
pub fn cumulation(roles: &[AdminRole]) -> Option<Cumulation> {
    roles.iter().enumerate().find_map(|(i, &held)| {
        roles
            .iter()
            .skip(i + 1)
            .find(|a| !held.compatible(**a))
            .map(|&asked| Cumulation { held, asked })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_excludes_the_roles_that_widen_an_access() {
        use AdminRole::{Admin, Audit, Policy};
        for a in AdminRole::ALL {
            for b in AdminRole::ALL {
                assert_eq!(a.compatible(b), b.compatible(a), "{a:?} {b:?}");
                let widening_and_audit =
                    (a == Audit && b.widens_access()) || (b == Audit && a.widens_access());
                assert_eq!(a.compatible(b), !widening_and_audit, "{a:?} {b:?}");
            }
        }
        assert!(Admin.compatible(Policy));
        assert!(Audit.compatible(Audit));
    }

    #[test]
    fn grant_and_start_checks() {
        use AdminRole::{Admin, Audit, Policy};
        assert_eq!(check_grant(&[Admin], Policy, Separation::Strict), Ok(()));
        let err = check_grant(&[Admin, Policy], Audit, Separation::Strict).unwrap_err();
        assert_eq!(
            err,
            Cumulation {
                held: Admin,
                asked: Audit
            }
        );
        assert_eq!(err.code().as_str(), "POL-E006");
        assert!(err.to_string().starts_with("POL-E006"));
        assert_eq!(
            check_grant(&[Audit], Policy, Separation::Strict)
                .unwrap_err()
                .held,
            Audit
        );
        assert_eq!(
            check_grant(&[Policy], Audit, Separation::CumulationAllowed),
            Ok(())
        );
        assert_eq!(cumulation(&[Admin, Policy]), None);
        assert_eq!(cumulation(&[]), None);
        assert_eq!(
            cumulation(&[Policy, Admin, Audit]),
            Some(Cumulation {
                held: Policy,
                asked: Audit
            })
        );
    }

    #[test]
    fn names_round_trip() {
        for r in AdminRole::ALL {
            assert_eq!(AdminRole::parse(r.name()), Some(r));
        }
        assert_eq!(AdminRole::parse("Audit"), None);
    }
}
