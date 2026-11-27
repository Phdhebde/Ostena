//! What the core gives the PDP: identifiers, protocols, functions and the
//! authorization rules of one policy version (ADR-0022).

use std::fmt;

macro_rules! id {
    ($($(#[$doc:meta])* $name:ident,)+) => {$(
        $(#[$doc])*
        ///
        /// Opaque to the PDP: the core puts the 128 bits of its UUID.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u128);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:032x}", self.0)
            }
        }
    )+};
}

id! {
    /// A user.
    UserId,
    /// A group of users.
    UserGroupId,
    /// An account on a target (a resource and an account name).
    AccountId,
    /// A group of target accounts.
    AccountGroupId,
    /// An authorization rule.
    RuleId,
}

/// The access protocol. The values are those of the grant (ADR-0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// SSH.
    Ssh = 1,
    /// RDP.
    Rdp = 2,
    /// VNC (RFB).
    Vnc = 3,
    /// Proxied web application.
    Web = 4,
}

impl Protocol {
    /// Every protocol.
    pub const ALL: [Self; 4] = [Self::Ssh, Self::Rdp, Self::Vnc, Self::Web];

    /// Its name, as stored and typed (`ssh`, `rdp`, `vnc`, `web`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Web => "web",
        }
    }

    /// The protocol of `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// The functions that mean something for this protocol: the others are
    /// never granted for it, whatever the rule says.
    pub const fn functions(self) -> Functions {
        match self {
            Self::Ssh => Functions::TRANSFER
                .with(Function::PortForwarding)
                .with(Function::AgentForwarding)
                .with(Function::X11Forwarding),
            Self::Rdp => Functions::CLIPBOARD
                .union(Functions::TRANSFER)
                .with(Function::DriveRedirection)
                .with(Function::PrinterRedirection)
                .with(Function::AudioRedirection),
            Self::Vnc => Functions::CLIPBOARD,
            Self::Web => Functions::CLIPBOARD.union(Functions::TRANSFER),
        }
    }
}

/// A set of protocols.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Protocols(u8);

impl Protocols {
    /// No protocol.
    pub const NONE: Self = Self(0);
    /// Every protocol.
    pub const ALL: Self = Self(0b1_1110);

    /// The set with `protocol`.
    #[must_use]
    pub const fn with(self, protocol: Protocol) -> Self {
        Self(self.0 | 1 << protocol as u8)
    }

    /// Whether `protocol` is in the set.
    pub const fn contains(self, protocol: Protocol) -> bool {
        self.0 & 1 << protocol as u8 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<Protocol> for Protocols {
    fn from_iter<I: IntoIterator<Item = Protocol>>(iter: I) -> Self {
        iter.into_iter().fold(Self::NONE, Self::with)
    }
}

/// One function of an access beyond the screen, the terminal and the
/// commands. Its value is the bit of the rights of the grant (ADR-0004):
/// the core turns a set into rights bits without a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Function {
    /// Clipboard from the user to the target.
    ClipboardToTarget = 0,
    /// Clipboard from the target to the user.
    ClipboardFromTarget = 1,
    /// File upload to the target.
    Upload = 2,
    /// File download from the target.
    Download = 3,
    /// RDP drive redirection.
    DriveRedirection = 4,
    /// RDP printer redirection.
    PrinterRedirection = 5,
    /// RDP audio redirection.
    AudioRedirection = 6,
    /// SSH port forwarding: local (`-L`, `-W`, `ProxyJump`) and remote (`-R`).
    PortForwarding = 7,
    /// SSH agent forwarding (`-A`).
    AgentForwarding = 8,
    /// SSH X11 forwarding (`-X`).
    X11Forwarding = 9,
}

impl Function {
    /// Every function, in bit order.
    pub const ALL: [Self; 10] = [
        Self::ClipboardToTarget,
        Self::ClipboardFromTarget,
        Self::Upload,
        Self::Download,
        Self::DriveRedirection,
        Self::PrinterRedirection,
        Self::AudioRedirection,
        Self::PortForwarding,
        Self::AgentForwarding,
        Self::X11Forwarding,
    ];

    /// Its name, as stored and typed.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClipboardToTarget => "clipboard-to-target",
            Self::ClipboardFromTarget => "clipboard-from-target",
            Self::Upload => "upload",
            Self::Download => "download",
            Self::DriveRedirection => "drive-redirection",
            Self::PrinterRedirection => "printer-redirection",
            Self::AudioRedirection => "audio-redirection",
            Self::PortForwarding => "port-forwarding",
            Self::AgentForwarding => "agent-forwarding",
            Self::X11Forwarding => "x11-forwarding",
        }
    }
}

/// A set of functions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Functions(u16);

impl Functions {
    /// No function.
    pub const NONE: Self = Self(0);
    /// File transfers both ways: SSH grants them together (`sftp`, `scp`
    /// and `rsync` cannot be split by direction), as the name `transfer`.
    pub const TRANSFER: Self = Self::NONE.with(Function::Upload).with(Function::Download);
    /// The clipboard both ways, as the name `clipboard`.
    pub const CLIPBOARD: Self = Self::NONE
        .with(Function::ClipboardToTarget)
        .with(Function::ClipboardFromTarget);
    const KNOWN: u16 = (1 << 10) - 1;

    /// The set with `function`.
    #[must_use]
    pub const fn with(self, function: Function) -> Self {
        Self(self.0 | 1 << function as u16)
    }

    /// Union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection of two sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The functions of `self` that are not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether every function of `other` is in the set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether `function` is in the set.
    pub const fn has(self, function: Function) -> bool {
        self.0 & 1 << function as u16 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits: the rights bits of the grant (ADR-0004).
    pub const fn bits(self) -> u32 {
        self.0 as u32
    }

    /// The set of `bits`; `None` if an unknown bit is set.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !(Self::KNOWN as u32) == 0 {
            #[expect(clippy::cast_possible_truncation, reason = "checked just above")]
            Some(Self(bits as u16))
        } else {
            None
        }
    }

    /// The functions of the set, in bit order.
    pub fn iter(self) -> impl Iterator<Item = Function> {
        Function::ALL.into_iter().filter(move |f| self.has(*f))
    }

    /// The set of `names`. Besides the names of [`Function`], `transfer`
    /// and `clipboard` name both directions. A name repeated counts once.
    ///
    /// # Errors
    ///
    /// The first unknown name.
    pub fn parse<S: AsRef<str>>(names: &[S]) -> Result<Self, String> {
        names.iter().try_fold(Self::NONE, |set, name| {
            let name = name.as_ref();
            let one = match name {
                "transfer" => Some(Self::TRANSFER),
                "clipboard" => Some(Self::CLIPBOARD),
                _ => Function::ALL
                    .into_iter()
                    .find(|f| f.name() == name)
                    .map(|f| Self::NONE.with(f)),
            };
            one.map(|f| set.union(f)).ok_or_else(|| name.to_owned())
        })
    }

    /// The functions that may be granted for `protocol`. For SSH, a
    /// transfer in one direction only is dropped: the agent cannot enforce
    /// it (ADR-0004, bits 2 and 3 together), and granting both would widen
    /// the rule.
    #[must_use]
    pub const fn for_protocol(self, protocol: Protocol) -> Self {
        let set = self.intersection(protocol.functions());
        if matches!(protocol, Protocol::Ssh) && !set.contains(Self::TRANSFER) {
            set.difference(Self::TRANSFER)
        } else {
            set
        }
    }
}

impl fmt::Display for Functions {
    /// The names, comma separated, or `-` for none (audit records).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        for (i, function) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(function.name())?;
        }
        Ok(())
    }
}

/// Who a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subject {
    /// One user (the rights of ADR-0014).
    User(UserId),
    /// Every member of a group of users.
    Group(UserGroupId),
}

/// What a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// One account on a target (the rights of ADR-0014).
    Account(AccountId),
    /// Every account of a group of accounts.
    AccountGroup(AccountGroupId),
}

/// What a rule does when it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Allows the access with these functions, for sessions of at most
    /// `max_session_secs`.
    Allow {
        /// Functions granted beyond the screen, the terminal and the
        /// commands.
        functions: Functions,
        /// Longest session, seconds.
        max_session_secs: u32,
    },
    /// Refuses the access, whatever the allowing rules.
    Deny,
    /// Takes these functions away from the access, whatever the allowing
    /// rules; the access itself stays as they decide.
    DenyFunctions(Functions),
}

/// One authorization rule: a subject, a target, protocols, an effect and a
/// validity window `[valid_from, valid_until)` in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rule {
    /// Its identifier, unique in the policy.
    pub id: RuleId,
    /// Who.
    pub subject: Subject,
    /// On what.
    pub target: Target,
    /// With which protocols; never empty.
    pub protocols: Protocols,
    /// What it does.
    pub effect: Effect,
    /// Start of validity, Unix seconds.
    pub valid_from: u64,
    /// End of validity (excluded), Unix seconds. An allowing rule always
    /// ends ([`crate::MAX_ALLOW_SECS`] at most); a refusal may last forever
    /// (`u64::MAX`).
    pub valid_until: u64,
}

/// One version of the whole policy, as the core read it.
///
/// Memberships are flat: the sources resolve nested groups before (ADR-0021).
/// A group named by a rule and absent from the memberships is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The version, which never goes back ([`crate::Pdp::install`]).
    pub version: u64,
    /// Members of the groups of users.
    pub user_groups: Vec<(UserGroupId, UserId)>,
    /// Members of the groups of accounts.
    pub account_groups: Vec<(AccountGroupId, AccountId)>,
    /// The rules, in any order.
    pub rules: Vec<Rule>,
}
