//! Identity sources (ADR-0021): local accounts and LDAPS directories.
//!
//! - **Names**: a local account keeps its name (`alice`); a user of a
//!   directory is `source/identifier` (`corp/jdupont`). The same identifier
//!   in two sources gives two users, never merged.
//! - **Routing** of a login name ([`Directories::route`]): `source/name`
//!   names the source (`local/name` a local account); `name@suffix` goes to
//!   the source of that suffix; a bare name goes to `default_source`, or is
//!   a local account. Local accounts stay reachable as `local/name` (back-up
//!   accounts when a directory is down).
//! - **Synchronisation** ([`sync`]): at each login, a check of the users
//!   with an open session every `check_interval_secs`, a full pass every
//!   `sync_interval_secs`. A user disabled, deleted or out of the allowed
//!   groups in the directory is disabled in the core and their login
//!   sessions are revoked: the agents cut their sessions.

pub mod directory;
pub mod sync;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ostena_common::config::{CoreIdentityConfig, LOCAL_SOURCE};
use ostena_common::secret::SecretString;

pub use directory::{DirUser, DirectorySource, IdentityError, Listing};
pub use sync::Identity;

use crate::error::CoreError;

/// The LDAPS sources of the configuration, without the database.
#[derive(Debug)]
pub struct Directories {
    sources: Vec<Arc<DirectorySource>>,
    default_source: Option<String>,
    /// Interval of the check of the users with an open session.
    pub check_interval: Duration,
    /// Interval of the full synchronisation.
    pub sync_interval: Duration,
}

/// Where a login name goes.
#[derive(Debug, Clone)]
pub enum Route {
    /// A local account, by its name.
    Local(String),
    /// A user of a directory: the source and the identifier (lower case).
    Directory(Arc<DirectorySource>, String),
    /// A source or a suffix that does not exist.
    Unknown,
}

impl Route {
    /// The name of the user in the core (`alice`, `corp/jdupont`).
    pub fn user_name(&self) -> Option<String> {
        match self {
            Self::Local(name) => Some(name.clone()),
            Self::Directory(source, login) => Some(format!("{}/{login}", source.name)),
            Self::Unknown => None,
        }
    }
}

/// Reads a password file or credential, without its final line break.
fn read_password(
    field: &str,
    source: &ostena_common::config::KeySource,
    credentials: Option<&Path>,
) -> Result<SecretString, CoreError> {
    let bytes = crate::server::read_key(field, source, credentials)?;
    // SECRET-EXPOSURE: the password is copied once into its own secret,
    // without the line break of the file.
    #[expect(clippy::disallowed_methods)]
    let text = std::str::from_utf8(bytes.expose_secret())
        .map_err(|_| CoreError::Keys(format!("{field} : mot de passe non UTF-8")))?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if text.is_empty() {
        return Err(CoreError::Keys(format!("{field} : mot de passe vide")));
    }
    Ok(SecretString::from(text))
}

impl Directories {
    /// The sources of `config`; passwords read from their files or from
    /// `credentials` (`$CREDENTIALS_DIRECTORY`).
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] for a password or CA bundle that cannot be read,
    /// [`CoreError::Directory`] for a source that cannot be used.
    pub fn load(
        config: &CoreIdentityConfig,
        credentials: Option<&Path>,
    ) -> Result<Self, CoreError> {
        let mut sources = Vec::with_capacity(config.ldap.len());
        for (i, ldap) in config.ldap.iter().enumerate() {
            let field = format!("core.identity.ldap[{i}]");
            let password = read_password(
                &format!("{field}.bind_password"),
                &ldap.bind_password,
                credentials,
            )?;
            let ca = std::fs::read(&ldap.ca_bundle).map_err(|e| {
                CoreError::Keys(format!(
                    "{field}.ca_bundle {} : {e}",
                    ldap.ca_bundle.display()
                ))
            })?;
            let source = DirectorySource::new(ldap, &ca, password)
                .map_err(|e| CoreError::Directory(e.to_string()))?;
            sources.push(Arc::new(source));
        }
        Ok(Self::from_sources(
            sources,
            config.default_source.clone(),
            Duration::from_secs(u64::from(config.check_interval_secs)),
            Duration::from_secs(u64::from(config.sync_interval_secs)),
        ))
    }

    /// No source: local accounts only.
    pub fn local_only() -> Self {
        Self::from_sources(Vec::new(), None, Duration::ZERO, Duration::ZERO)
    }

    /// Sources already built (tests).
    pub fn from_sources(
        sources: Vec<Arc<DirectorySource>>,
        default_source: Option<String>,
        check_interval: Duration,
        sync_interval: Duration,
    ) -> Self {
        Self {
            sources,
            default_source: default_source.filter(|s| s != LOCAL_SOURCE),
            check_interval,
            sync_interval,
        }
    }

    /// The sources.
    pub fn sources(&self) -> &[Arc<DirectorySource>] {
        &self.sources
    }

    fn source(&self, name: &str) -> Option<&Arc<DirectorySource>> {
        self.sources.iter().find(|s| s.name == name)
    }

    /// Where `username` (lower case, `is_username` of the login API) goes.
    pub fn route(&self, username: &str) -> Route {
        let username = username.to_ascii_lowercase();
        if let Some((source, name)) = username.split_once('/') {
            if source == LOCAL_SOURCE {
                return Route::Local(name.to_owned());
            }
            return self.source(source).map_or(Route::Unknown, |s| {
                Route::Directory(s.clone(), name.to_owned())
            });
        }
        if let Some((name, suffix)) = username.split_once('@') {
            return self
                .sources
                .iter()
                .find(|s| s.suffixes.iter().any(|x| x == suffix))
                .map_or(Route::Unknown, |s| {
                    Route::Directory(s.clone(), name.to_owned())
                });
        }
        match &self.default_source {
            Some(default) => self
                .source(default)
                .map_or(Route::Unknown, |s| Route::Directory(s.clone(), username)),
            None => Route::Local(username),
        }
    }
}
