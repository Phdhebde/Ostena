//! Functions of an SSH right beyond the terminal and the commands
//! (ADR-0010): none by default, each granted explicitly, carried by the
//! grant as its rights bits (ADR-0004) and enforced by the agent.

use ostena_grant::Rights;

use crate::error::CoreError;

/// One function of a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Function {
    /// File transfers: the `sftp` subsystem, `scp` and `rsync`, both ways.
    Transfer,
    /// Port forwarding: local (`-L`, `-W`, `ProxyJump`) and remote (`-R`).
    PortForwarding,
    /// Agent forwarding (`-A`).
    AgentForwarding,
    /// X11 forwarding (`-X`).
    X11Forwarding,
}

impl Function {
    /// Every function, in the order they are listed.
    pub const ALL: [Self; 4] = [
        Self::Transfer,
        Self::PortForwarding,
        Self::AgentForwarding,
        Self::X11Forwarding,
    ];

    /// Its name, as stored and typed (`right grant --allow`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::PortForwarding => "port-forwarding",
            Self::AgentForwarding => "agent-forwarding",
            Self::X11Forwarding => "x11-forwarding",
        }
    }

    /// The function of `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    /// The rights bits it puts in a grant: a transfer allows both ways.
    pub const fn rights(self) -> Rights {
        match self {
            Self::Transfer => Rights::FILE_UPLOAD.with(Rights::FILE_DOWNLOAD),
            Self::PortForwarding => Rights::SSH_PORT_FORWARDING,
            Self::AgentForwarding => Rights::SSH_AGENT_FORWARDING,
            Self::X11Forwarding => Rights::SSH_X11_FORWARDING,
        }
    }
}

/// A set of functions, as stored (`access_right.functions`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Functions(u8);

impl Functions {
    /// No function: terminal and commands only.
    pub const NONE: Self = Self(0);

    const fn bit(function: Function) -> u8 {
        1 << function as u8
    }

    /// The set with `function`.
    #[must_use]
    pub const fn with(self, function: Function) -> Self {
        Self(self.0 | Self::bit(function))
    }

    /// Whether `function` is in the set.
    pub const fn contains(self, function: Function) -> bool {
        self.0 & Self::bit(function) != 0
    }

    /// The functions of the set, in [`Function::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Function> {
        Function::ALL.into_iter().filter(move |f| self.contains(*f))
    }

    /// Their names, as stored.
    pub fn names(self) -> Vec<String> {
        self.iter().map(|f| f.name().to_owned()).collect()
    }

    /// Their names, comma separated (`-` for none), for the audit records
    /// and the listings.
    pub fn label(self) -> String {
        if self == Self::NONE {
            "-".to_owned()
        } else {
            self.iter()
                .map(Function::name)
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    /// The set of `names`; a name repeated counts once.
    ///
    /// # Errors
    ///
    /// [`CoreError::Invalid`] for an unknown name.
    pub fn parse<S: AsRef<str>>(names: &[S]) -> Result<Self, CoreError> {
        names.iter().try_fold(Self::NONE, |set, name| {
            Function::parse(name.as_ref())
                .map(|f| set.with(f))
                .ok_or_else(|| {
                    CoreError::Invalid(format!(
                        "fonction inconnue : {} (attendu : {})",
                        crate::store::truncate(name.as_ref()),
                        Function::ALL.map(Function::name).join(", ")
                    ))
                })
        })
    }

    /// The set read from the database: an unknown name (which the `CHECK`
    /// constraint forbids) is dropped, never widened into something else.
    pub fn from_stored(names: &[String]) -> Self {
        names
            .iter()
            .filter_map(|n| Function::parse(n))
            .fold(Self::NONE, Self::with)
    }

    /// The rights bits of the grant.
    pub fn rights(self) -> Rights {
        self.iter()
            .fold(Rights::NONE, |rights, f| rights.with(f.rights()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_map_to_rights() {
        for f in Function::ALL {
            assert_eq!(Function::parse(f.name()), Some(f));
        }
        assert_eq!(Function::parse("Transfer"), None);
        let set = Functions::parse(&["x11-forwarding", "transfer", "transfer"]).unwrap();
        assert_eq!(set.names(), ["transfer", "x11-forwarding"]);
        assert_eq!(set.label(), "transfer,x11-forwarding");
        assert_eq!(Functions::NONE.label(), "-");
        assert_eq!(
            set.rights(),
            Rights::FILE_UPLOAD
                .with(Rights::FILE_DOWNLOAD)
                .with(Rights::SSH_X11_FORWARDING)
        );
        assert_eq!(Functions::NONE.rights(), Rights::NONE);
        assert!(Functions::parse(&["shell"]).is_err());
        assert_eq!(
            Functions::from_stored(&["agent-forwarding".into(), "bogus".into()]),
            Functions::NONE.with(Function::AgentForwarding)
        );
    }
}
