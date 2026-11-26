//! The LDAPS identity source against the Active Directory of the lab
//! (ADR-0021, ADR-0025): nightly only, through `identities-lab.yml`, with
//! `LAB_JSON` naming the entry point of the lab. Skipped without it.
//!
//! The users and their groups are read over TLS 1.3 from the domain
//! controller, a password is checked by a bind, an account disabled in the
//! directory is seen disabled within the 60 s of ADR-0021, and plain LDAP,
//! another CA and another name are refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ostena_common::config::LdapSourceConfig;
use ostena_common::secret::SecretString;
use ostena_core::identity::DirectorySource;
use ostena_core::testing::block_on;
use ostena_crypto::pki::pem_certificate;
use ostena_crypto::tls::target::testing::TargetCa;
use serde_json::Value;

/// The account disabled then enabled again by the test.
const TARGET: &str = "ostena-user1";

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn lab() -> Option<Value> {
    let path = std::env::var_os("LAB_JSON")?;
    Some(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
}

fn text<'a>(v: &'a Value, path: &str) -> &'a str {
    path.split('.')
        .fold(v, |v, k| &v[k])
        .as_str()
        .unwrap_or_else(|| panic!("lab.json : {path} absent"))
}

/// `DC=lab,DC=example` of `lab.example`.
fn base_of(fqdn: &str) -> String {
    fqdn.split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn password(lab: &Value, login: &str) -> SecretString {
    let account = lab["accounts"]["domain"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| text(a, "upn").starts_with(&format!("{login}@")))
        .unwrap();
    SecretString::from(text(account, "password").to_owned())
}

fn config(lab: &Value, server: &str) -> LdapSourceConfig {
    let fqdn = text(lab, "domain.fqdn");
    let base = base_of(fqdn);
    let mut config: LdapSourceConfig = toml::from_str(&format!(
        r#"name = "lab"
kind = "active-directory"
servers = ["{server}"]
ca_bundle = "/unused"
bind_dn = "{}"
bind_password = {{ credential = "unused" }}
user_base = "{base}"
require_group = false
suffixes = ["{fqdn}"]
groups = [{{ directory = "CN=Domain Admins,CN=Users,{base}", group = "admins" }}]
"#,
        text(lab, "accounts.administrator.upn"),
    ))
    .unwrap();
    config.connect_timeout_secs = 10;
    config
}

fn source(lab: &Value, server: &str, ca_pem: &[u8]) -> DirectorySource {
    let admin = SecretString::from(text(lab, "accounts.administrator.password").to_owned());
    DirectorySource::new(&config(lab, server), ca_pem, admin).unwrap()
}

/// Runs `script` on the domain controller through the lab channel.
fn on_dc(lab: &Value, script: &str) {
    let lab_sh = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/providers/qemu-ci/lab.sh")
        .canonicalize()
        .unwrap();
    let mut child = Command::new(lab_sh)
        .args(["exec", text(lab, "domain.dc"), "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "lab exec : {script}");
}

#[test]
#[ignore = "lab only: run by identities-lab.yml with LAB_JSON"]
fn active_directory_of_the_lab() {
    let Some(lab) = lab() else {
        eprintln!("LAB_JSON absent : test sauté");
        return;
    };
    block_on(async {
        let dc = text(&lab, "domain.dc");
        let dc_fqdn = text(&lab, &format!("machines.{dc}.fqdn")).to_owned();
        let dc_ip = text(&lab, "domain.dc_ip").to_owned();
        let ca_pem = text(&lab, "ca.pem").as_bytes().to_vec();
        let ad = source(&lab, &format!("ldaps://{dc_fqdn}:636"), &ca_pem);

        // The users of the domain and their groups, over TLS 1.3.
        let started = Instant::now();
        let listing = ad.list(now()).await.unwrap();
        println!(
            "listing: {} users, {} skipped, {:?}",
            listing.users.len(),
            listing.skipped,
            started.elapsed()
        );
        let find = |login: &str| listing.users.iter().find(|u| u.login == login).cloned();
        let admin = find("ostena-admin").expect("ostena-admin");
        assert_eq!(admin.groups, ["admins"]);
        let user = find(TARGET).expect(TARGET);
        assert_eq!(user.groups, Vec::<String>::new());
        assert!(user.disabled.is_none());
        assert_eq!(user.external_id.len(), 32);

        // A password checked by a bind as the user.
        let started = Instant::now();
        let (_, ok) = ad
            .authenticate(TARGET, Some(&password(&lab, TARGET)), now())
            .await
            .unwrap()
            .unwrap();
        assert!(ok);
        println!("login by bind: {:?}", started.elapsed());
        let (_, ok) = ad
            .authenticate(TARGET, Some(&password(&lab, "ostena-user2")), now())
            .await
            .unwrap()
            .unwrap();
        assert!(!ok);

        // Disabled in the directory: seen at the next check, well within
        // the 60 s of ADR-0021 (one check every 20 s by default).
        on_dc(&lab, &format!("Disable-ADAccount -Identity {TARGET}"));
        let disabled_at = Instant::now();
        let ids = [user.external_id.clone()];
        let seen = loop {
            let found = ad.lookup(&ids, now()).await.unwrap();
            if found.first().and_then(|u| u.disabled).is_some() {
                break disabled_at.elapsed();
            }
            assert!(disabled_at.elapsed() < Duration::from_secs(60));
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        println!("disabled in AD -> seen disabled: {seen:?}");
        let (_, ok) = ad
            .authenticate(TARGET, Some(&password(&lab, TARGET)), now())
            .await
            .unwrap()
            .unwrap();
        assert!(!ok, "a disabled account is never bound");
        on_dc(&lab, &format!("Enable-ADAccount -Identity {TARGET}"));

        // Refused: plain LDAP in the configuration, LDAPS client on the
        // plain port, another CA, another name (the address, not the name
        // of the certificate).
        let mut plain = config(&lab, &format!("ldaps://{dc_fqdn}"));
        plain.servers = vec![format!("ldap://{dc_fqdn}:389")];
        assert!(DirectorySource::new(&plain, &ca_pem, SecretString::from("x".to_owned())).is_err());
        let on_389 = source(&lab, &format!("ldaps://{dc_fqdn}:389"), &ca_pem);
        assert!(on_389.list(now()).await.is_err());
        let rogue = TargetCa::new("rogue ca").unwrap();
        let rogue_pem = pem_certificate(&rogue.certificate).into_bytes();
        let err = source(&lab, &format!("ldaps://{dc_fqdn}"), &rogue_pem)
            .list(now())
            .await
            .unwrap_err();
        println!("another CA: {err}");
        assert!(err.to_string().contains("TLS"), "{err}");
        let by_ip = source(&lab, &format!("ldaps://{dc_ip}"), &ca_pem);
        match by_ip.list(now()).await {
            Err(err) => println!("by address: {err}"),
            Ok(_) => println!("by address: accepted (the certificate names the address)"),
        }
    });
}
