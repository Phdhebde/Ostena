use super::*;

const USER: &str = "S-1-5-21-1-2-3-1001";
const EVERYONE: &str = "S-1-1-0";
const FULL: u32 = 0x001f_01ff;
const READ_ONLY: u32 = 0x0012_0089;

fn ace(sid: &str, mask: u32) -> Ace {
    Ace {
        sid: sid.into(),
        allow: true,
        mask,
        inherit_only: false,
    }
}

fn security(owner: &str, aces: Vec<Ace>) -> Security {
    Security {
        owner: owner.into(),
        dacl: Some(aces),
    }
}

const TRUSTED: [&str; 3] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

#[test]
fn protected_file_passes() {
    let s = security(
        ADMINISTRATORS,
        vec![ace(SYSTEM, FULL), ace(ADMINISTRATORS, FULL)],
    );
    assert_eq!(evaluate("le fichier", &s, &TRUSTED, true), None);
}

#[test]
fn foreign_owner_is_refused() {
    let s = security(USER, vec![ace(SYSTEM, FULL)]);
    assert!(
        evaluate("le fichier", &s, &TRUSTED, false)
            .unwrap()
            .contains(USER)
    );
}

#[test]
fn null_dacl_is_refused() {
    let s = Security {
        owner: SYSTEM.into(),
        dacl: None,
    };
    assert!(
        evaluate("le fichier", &s, &TRUSTED, false)
            .unwrap()
            .contains("DACL nulle")
    );
}

#[test]
fn write_by_others_is_refused_read_only_if_private() {
    let writable = security(SYSTEM, vec![ace(SYSTEM, FULL), ace(EVERYONE, 0x0000_0002)]);
    assert!(
        evaluate("le fichier", &writable, &TRUSTED, false)
            .unwrap()
            .contains(EVERYONE)
    );
    let readable = security(SYSTEM, vec![ace(SYSTEM, FULL), ace(USER, READ_ONLY)]);
    assert_eq!(evaluate("le fichier", &readable, &TRUSTED, false), None);
    assert!(
        evaluate("le fichier", &readable, &TRUSTED, true)
            .unwrap()
            .contains("lisible")
    );
    for generic in [0x1000_0000, 0x4000_0000] {
        let s = security(SYSTEM, vec![ace(EVERYONE, generic)]);
        assert!(
            evaluate("le fichier", &s, &TRUSTED, false).is_some(),
            "{generic:#x}"
        );
    }
    let s = security(SYSTEM, vec![ace(EVERYONE, 0x8000_0000)]);
    assert!(evaluate("le fichier", &s, &TRUSTED, true).is_some());
}

#[test]
fn deny_and_inherit_only_entries_do_not_grant() {
    let mut deny = ace(EVERYONE, FULL);
    deny.allow = false;
    let mut inherit = ace(EVERYONE, FULL);
    inherit.inherit_only = true;
    let s = security(SYSTEM, vec![deny, inherit, ace(SYSTEM, FULL)]);
    assert_eq!(evaluate("le dossier", &s, &TRUSTED, true), None);
}

#[cfg(windows)]
mod windows {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::super::*;
    use super::{EVERYONE, TRUSTED};

    fn icacls(path: &Path, args: &[&str]) {
        let out = Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "icacls {args:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    fn current_user() -> String {
        let name = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap(),
            std::env::var("USERNAME").unwrap()
        );
        account_sid(&name).unwrap()
    }

    struct TempFile(PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp(name: &str, dir: bool) -> TempFile {
        let path = std::env::temp_dir().join(format!("ostena-acl-{name}-{}", std::process::id()));
        if dir {
            std::fs::create_dir_all(&path).unwrap();
        } else {
            std::fs::write(&path, b"x").unwrap();
        }
        TempFile(path)
    }

    #[test]
    fn well_known_accounts() {
        assert_eq!(account_sid("NT AUTHORITY\\SYSTEM").unwrap(), SYSTEM);
        // Built-in group names are localized (BUILTIN\Administrateurs in
        // French): the code uses their SIDs. "NT SERVICE" is not localized,
        // which the service account lookup relies on.
        assert_eq!(
            account_sid("NT SERVICE\\TrustedInstaller").unwrap(),
            TRUSTED_INSTALLER
        );
        assert!(account_sid("NT SERVICE\\OstenaNoSuchService").is_err());
        assert!(current_user().starts_with("S-1-5-"));
    }

    #[test]
    fn reads_the_dacl_set_by_icacls() {
        let user = current_user();
        let f = temp("read", false);
        let grant_user = format!("*{user}:F");
        icacls(
            &f.0,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
                &grant_user,
            ],
        );
        let s = read_security(&f.0).unwrap();
        let dacl = s.dacl.as_ref().unwrap();
        let mut sids: Vec<&str> = dacl.iter().map(|a| a.sid.as_str()).collect();
        sids.sort_unstable();
        let mut expected = vec![SYSTEM, ADMINISTRATORS, user.as_str()];
        expected.sort_unstable();
        assert_eq!(sids, expected);
        assert!(dacl.iter().all(|a| a.allow && a.mask == 0x001f_01ff));

        let mut trusted = TRUSTED.to_vec();
        trusted.push(&user);
        trusted.push(&s.owner);
        assert_eq!(evaluate("le fichier", &s, &trusted, true), None);

        // Everyone may write: refused.
        icacls(&f.0, &["/grant", "*S-1-1-0:(W)"]);
        let s = read_security(&f.0).unwrap();
        assert!(
            evaluate("le fichier", &s, &trusted, false)
                .unwrap()
                .contains(EVERYONE)
        );
    }

    #[test]
    fn private_file_refuses_readers_and_inherit_only_is_ignored() {
        let user = current_user();
        let d = temp("dir", true);
        let grant_user = format!("*{user}:F");
        icacls(
            &d.0,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                &grant_user,
                "/grant",
                "*S-1-1-0:(OI)(CI)(IO)(W)",
            ],
        );
        let s = read_security(&d.0).unwrap();
        assert!(
            s.dacl
                .as_ref()
                .unwrap()
                .iter()
                .any(|a| a.inherit_only && a.sid == EVERYONE)
        );
        let trusted = [SYSTEM, user.as_str(), s.owner.as_str()];
        // The inherit-only entry does not apply to the directory itself.
        assert_eq!(evaluate("le dossier", &s, &trusted, false), None);

        let f = temp("private", false);
        icacls(
            &f.0,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                &grant_user,
                "*S-1-1-0:R",
            ],
        );
        let s = read_security(&f.0).unwrap();
        let trusted = [SYSTEM, user.as_str(), s.owner.as_str()];
        assert_eq!(evaluate("le fichier", &s, &trusted, false), None);
        assert!(
            evaluate("le fichier", &s, &trusted, true)
                .unwrap()
                .contains("lisible")
        );
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(read_security(Path::new("C:\\ostena\\does\\not\\exist")).is_err());
        assert!(
            WindowsPermissions
                .not_writable_by_others(Path::new("C:\\ostena\\does\\not\\exist"))
                .is_err()
        );
    }

    use ostena_common::config::PermissionChecker;
}
