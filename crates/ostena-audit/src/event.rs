//! The documented audit events and a builder that turns one into the next
//! record of a chain (ADR-0012).

use crate::AuditError;
use crate::ids::ChainId;
use crate::record::{ActorKind, Digest, Field, Outcome, Record, Value, ZERO_DIGEST, record_hash};

macro_rules! event_kinds {
    ($($(#[$doc:meta])* $variant:ident => $name:literal,)+) => {
        /// Every event the core writes to the audit chain. The decoder accepts
        /// any well-formed name (an older verifier reads newer chains); the
        /// writer only emits these.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum EventKind {
            $($(#[$doc])* $variant,)+
        }

        impl EventKind {
            /// Every event kind.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The name written in the record.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }
    };
}

event_kinds! {
    /// First record of a chain (seq 1).
    AuditChainStarted => "audit.chain_started",
    /// The head signer started (kid, heartbeat).
    AuditSigningStarted => "audit.signing_started",
    /// Events could not be written (count, reason); written once the chain
    /// is writable again.
    AuditEventsLost => "audit.events_lost",
    /// An administrator acknowledged a reported break of the chain.
    AuditBreakAcknowledged => "audit.break_acknowledged",
    /// An export was produced (first and last seq).
    AuditExported => "audit.exported",
    /// The core started.
    CoreStarted => "core.started",
    /// The core stopped.
    CoreStopped => "core.stopped",
    /// Migrations were applied.
    CoreMigrated => "core.migrated",
    /// Applied migrations were reverted with their down migrations
    /// (`ostena core migrate --revert-to`).
    CoreMigrationReverted => "core.migration_reverted",
    /// Development only: the database did not authenticate the core by peer.
    CoreDatabaseNotPeer => "core.database_not_peer",
    /// A weakening option is in effect (outside production).
    ConfigWaiver => "config.waiver",
    /// The agent registry cannot be read.
    CoreRegistryUnavailable => "core.registry_unavailable",
    /// The agent registry is readable again.
    CoreRegistryRestored => "core.registry_restored",
    /// An enrolment token was issued (never the token itself).
    EnrollTokenIssued => "enroll.token_issued",
    /// An enrolment token was consumed.
    EnrollTokenConsumed => "enroll.token_consumed",
    /// An enrolment attempt was refused.
    EnrollTokenRejected => "enroll.token_rejected",
    /// An agent enrolled and received its certificate.
    AgentEnrolled => "agent.enrolled",
    /// An agent certificate was renewed.
    AgentCertificateRenewed => "agent.certificate_renewed",
    /// An agent was revoked.
    AgentRevoked => "agent.revoked",
    /// The tunnels of a revoked agent were closed.
    AgentRevocationApplied => "agent.revocation_applied",
    /// A certificate renewal was refused.
    AgentRenewalRefused => "agent.renewal_refused",
    /// An agent tunnel was established.
    TunnelAgentConnected => "tunnel.agent_connected",
    /// An agent tunnel was refused.
    TunnelRefused => "tunnel.refused",
    /// A grant signing key joined the key set pushed to the agents.
    GrantKeyActivated => "grant.key_activated",
    /// A native SSH access was granted: a grant issued to an agent.
    AccessSshGranted => "access.ssh_granted",
    /// A native SSH access was refused (code, reason).
    AccessSshRefused => "access.ssh_refused",
    /// A session opened: grant checked, jti consumed by the core.
    AccessSessionOpened => "access.session_opened",
    /// A session request was refused (code, reason).
    AccessSessionRefused => "access.session_refused",
    /// A session ended (reason, bytes).
    AccessSessionClosed => "access.session_closed",
    /// The SSH host key of an agent was certified.
    SshHostCertified => "ssh.host_certified",
    /// The SSH host key of an agent was not certified (code, reason).
    SshHostKeyRefused => "ssh.host_key_refused",
    /// A login session was revoked.
    LoginSessionRevoked => "login_session.revoked",
    /// The agents concerned by a login revocation were told.
    LoginSessionRevocationApplied => "login_session.revocation_applied",
    /// A user was created.
    UserCreated => "user.created",
    /// A user was disabled (their login sessions revoked).
    UserDisabled => "user.disabled",
    /// `ostena login` succeeded: a login session opened and its user
    /// certificate issued (ADR-0010).
    LoginSucceeded => "login.succeeded",
    /// `ostena login` was refused (internal cause, never told the client).
    LoginRefused => "login.refused",
    /// An account was locked after too many failed logins.
    LoginLocked => "login.locked",
    /// The password of a user was set by an administrator.
    UserPasswordSet => "user.password_set",
    /// The TOTP enrolment of a user was confirmed.
    UserTotpEnrolled => "user.totp_enrolled",
    /// The TOTP secret of a user was removed or replaced by a new pending
    /// one.
    UserTotpReset => "user.totp_reset",
    /// An administrator unlocked an account.
    UserUnlocked => "user.unlocked",
    /// A resource was added to the inventory.
    ResourceCreated => "resource.created",
    /// A target account was added to a resource.
    TargetAccountCreated => "target_account.created",
    /// A right was granted.
    RightGranted => "right.granted",
    /// A right was revoked.
    RightRevoked => "right.revoked",
    /// A gateway group was created or changed (name, SSH host names,
    /// scope policy).
    GatewayGroupUpdated => "gateway_group.updated",
    /// The command of an SSH `exec`, by its keyed hash and length
    /// (ADR-0016): its text is in the transcript.
    AccessSshExec => "access.ssh_exec",
    /// A session transcript was sealed: its file, SHA-256 and size, complete
    /// or not (ADR-0016).
    TranscriptSealed => "transcript.sealed",
    /// A transcript stream was refused (unknown session, malformed, limit,
    /// storage).
    TranscriptRefused => "transcript.refused",
    /// A browser session ended without activity, or at its absolute end
    /// (ADR-0020); its login session is revoked.
    WebSessionExpired => "web_session.expired",
    /// A browser session was presented from another source than the one
    /// that opened it; it is revoked (ADR-0020).
    WebSessionSourceChanged => "web_session.source_changed",
    /// The user of a browser session gave both factors again; the cookie
    /// got a new value (ADR-0020).
    WebSessionReauthenticated => "web_session.reauthenticated",
    /// A role was given to a user.
    UserRoleGranted => "user.role_granted",
    /// A role was taken from a user.
    UserRoleRevoked => "user.role_revoked",
    /// A file transfer (sftp, scp, rsync) started in an SSH session, under
    /// the transfer function of the right (ADR-0010): the file names are in
    /// the transcript.
    AccessSshTransfer => "access.ssh_transfer",
    /// A request of an SSH session refused by the agent for lack of a
    /// function of the right (transfer, forwarding, agent, X11), as recorded
    /// in the transcript (ADR-0010).
    AccessSshRequestRefused => "access.ssh_request_refused",
    /// A port forwarding channel (`direct-tcpip`: `-L`, `-W`, `ProxyJump`)
    /// relayed under the port forwarding function of the right (ADR-0010).
    AccessSshForward => "access.ssh_forward",
    /// A synchronisation of an identity source ended (counts, duration;
    /// ADR-0021).
    IdentitySyncCompleted => "identity.sync_completed",
    /// No server of an identity source answers (code, reason).
    IdentitySourceUnavailable => "identity.source_unavailable",
    /// A server of an identity source answers again.
    IdentitySourceRestored => "identity.source_restored",
    /// A user of an identity source was created in the core.
    IdentityUserProvisioned => "identity.user_provisioned",
    /// A user disabled by its identity source was enabled again by it.
    IdentityUserReenabled => "identity.user_reenabled",
    /// A group of users was created for a group rule of a source.
    UserGroupCreated => "user_group.created",
    /// A user joined a group of users (rule of a source).
    UserGroupMemberAdded => "user_group.member_added",
    /// A user left a group of users.
    UserGroupMemberRemoved => "user_group.member_removed",
    /// An access asked by a browser session was granted: a grant issued
    /// for the browser gateway (ADR-0020).
    AccessWebGranted => "access.web_granted",
    /// An access asked by a browser session was refused (code, reason).
    AccessWebRefused => "access.web_refused",
    /// A grant presented by its browser session opened the WebSocket of the
    /// gateway (ADR-0020): granting, with the marking of the grant.
    GatewayOpened => "gateway.opened",
    /// A WebSocket of the gateway refused after its session was
    /// authenticated (grant, agent).
    GatewayRefused => "gateway.refused",
    /// A WebSocket of the gateway ended (reason, bytes in each direction).
    GatewayClosed => "gateway.closed",
}

/// Field names of the documented events. None contains a fragment that the
/// log redaction treats as sensitive (`key`, `token`, `secret`, …), so the
/// same names can be mirrored in the structured logs: a public key is
/// `p256_public`, a key identifier `kid`, an enrolment token `enrollment_id`.
pub mod field {
    /// Agent UUID.
    pub const AGENT_ID: &str = "agent_id";
    /// Gateway group UUID.
    pub const GROUP_ID: &str = "group_id";
    /// Identifier of an enrolment token (never the token).
    pub const ENROLLMENT_ID: &str = "enrollment_id";
    /// Certificate serial number.
    pub const SERIAL: &str = "serial";
    /// SHA-256 fingerprint of a certificate.
    pub const FINGERPRINT: &str = "fingerprint";
    /// End of validity, Unix seconds.
    pub const NOT_AFTER: &str = "not_after";
    /// Key identifier (8 bytes).
    pub const KID: &str = "kid";
    /// A public key, uncompressed SEC1.
    pub const P256_PUBLIC: &str = "p256_public";
    /// Remote address.
    pub const PEER_ADDR: &str = "peer_addr";
    /// Stable error or refusal code (e.g. `TUN-E012`).
    pub const CODE: &str = "code";
    /// Human-readable reason.
    pub const REASON: &str = "reason";
    /// Number of lost events.
    pub const LOST_COUNT: &str = "lost_count";
    /// First sequence number of a range.
    pub const FIRST_SEQ: &str = "first_seq";
    /// Last sequence number of a range.
    pub const LAST_SEQ: &str = "last_seq";
    /// Head number.
    pub const HEAD_NO: &str = "head_no";
    /// Heartbeat of the head signer, in seconds.
    pub const HEARTBEAT_SECS: &str = "heartbeat_secs";
    /// Schema version after migration.
    pub const SCHEMA_VERSION: &str = "schema_version";
    /// Binary version.
    pub const VERSION: &str = "version";
    /// Name of a weakening option.
    pub const OPTION: &str = "option";
    /// Number of closed tunnels.
    pub const CLOSED_TUNNELS: &str = "closed_tunnels";
    /// Failed attempts of an enrolment token so far.
    pub const FAILURES: &str = "failures";
    /// Whether an enrolment token is burned (too many failures).
    pub const BURNED: &str = "burned";
    /// Expiry, Unix seconds.
    pub const EXPIRES_AT: &str = "expires_at";
    /// Version announced by an agent.
    pub const AGENT_VERSION: &str = "agent_version";
    /// Versions of the migrations applied, comma separated.
    pub const MIGRATIONS: &str = "migrations";
    /// Time of the first event of a range, Unix ms.
    pub const FIRST_MS: &str = "first_ms";
    /// Time of the last event of a range, Unix ms.
    pub const LAST_MS: &str = "last_ms";
    /// Number of heads (in an export).
    pub const HEAD_COUNT: &str = "head_count";
    /// User UUID.
    pub const USER_ID: &str = "user_id";
    /// Login session UUID (`ostena login`).
    pub const LOGIN_SESSION: &str = "login_session";
    /// Resource UUID.
    pub const RESOURCE_ID: &str = "resource_id";
    /// Target account UUID.
    pub const ACCOUNT_ID: &str = "account_id";
    /// Right UUID.
    pub const RIGHT_ID: &str = "right_id";
    /// Session UUID (an access, not a login session).
    pub const ACCESS_SESSION: &str = "access_session";
    /// Grant identifier (16 bytes).
    pub const JTI: &str = "jti";
    /// A name: user, resource, group.
    pub const NAME: &str = "name";
    /// Display name of a user.
    pub const DISPLAY_NAME: &str = "display_name";
    /// Resource name, as asked.
    pub const RESOURCE: &str = "resource";
    /// Account on a target.
    pub const ACCOUNT: &str = "account";
    /// Protocol (`ssh`, `rdp`, `vnc`, `web`).
    pub const PROTOCOL: &str = "protocol";
    /// Target host.
    pub const HOST: &str = "host";
    /// Target port.
    pub const PORT: &str = "port";
    /// SHA-256 of a user certificate.
    pub const CERTIFICATE_SHA256: &str = "certificate_sha256";
    /// Address of a client, `ip:port`.
    pub const CLIENT_ADDR: &str = "client_addr";
    /// Maximum session length, seconds.
    pub const MAX_SESSION_SECS: &str = "max_session_secs";
    /// End of validity of a right, Unix seconds.
    pub const VALID_UNTIL: &str = "valid_until";
    /// SSH host names of a gateway group, comma separated.
    pub const HOST_NAMES: &str = "host_names";
    /// Version of a pushed scope policy.
    pub const POLICY_VERSION: &str = "policy_version";
    /// Bytes sent to the target.
    pub const BYTES_TO_TARGET: &str = "bytes_to_target";
    /// Bytes received from the target.
    pub const BYTES_FROM_TARGET: &str = "bytes_from_target";
    /// Number of agents told.
    pub const NOTIFIED_AGENTS: &str = "notified_agents";
    /// Number of login sessions revoked.
    pub const REVOKED_SESSIONS: &str = "revoked_sessions";
    /// HMAC of a one-time code (`sha1`, `sha256`).
    pub const HMAC: &str = "hmac";
    /// End of an account lockout, Unix seconds.
    pub const LOCKED_UNTIL: &str = "locked_until";
    /// SHA-256 of a file (transcript).
    pub const SHA256: &str = "sha256";
    /// Size of a file, in bytes.
    pub const SIZE: &str = "size";
    /// Number of events (transcript lines after the header).
    pub const EVENTS: &str = "events";
    /// Invalid UTF-8 sequences replaced by U+FFFD.
    pub const INVALID_UTF8: &str = "invalid_utf8";
    /// Bytes of output recorded.
    pub const OUTPUT_BYTES: &str = "output_bytes";
    /// Keyed hash (HMAC-SHA-256) of a command.
    pub const COMMAND_HMAC: &str = "command_hmac";
    /// Length, in bytes.
    pub const LENGTH: &str = "length";
    /// Whether a transcript is complete (ended by its end frame).
    pub const COMPLETE: &str = "complete";
    /// Whether a sealed file is immutable on disk (write-once storage).
    pub const IMMUTABLE: &str = "immutable";
    /// How a login session is opened: `cli` (`ostena login`) or `web` (the
    /// portal).
    pub const CHANNEL: &str = "channel";
    /// A role of the portal (`admin`).
    pub const ROLE: &str = "role";
    /// The source a browser session is bound to (IPv4 address or IPv6 /64).
    pub const SOURCE: &str = "source";
    /// Functions of a right beyond the session, comma separated
    /// (`transfer`, `port-forwarding`, `agent-forwarding`, `x11-forwarding`).
    pub const FUNCTIONS: &str = "functions";
    /// Rights bits of a grant (ADR-0004).
    pub const RIGHTS: &str = "rights";
    /// Transfer protocol (`sftp`, `scp`, `rsync`).
    pub const TRANSFER: &str = "transfer";
    /// A refused request, as the agent names it.
    pub const REQUEST: &str = "request";
    /// Identity source of a user (`local` or the name of a directory;
    /// ADR-0021).
    pub const IDENTITY_SOURCE: &str = "identity_source";
    /// Name of a group of users.
    pub const USER_GROUP: &str = "user_group";
    /// DN of an entry in a directory.
    pub const DIRECTORY_DN: &str = "directory_dn";
    /// A directory server, `host:port`.
    pub const SERVER: &str = "server";
    /// Users read from a source.
    pub const USERS_SEEN: &str = "users_seen";
    /// Users created.
    pub const USERS_CREATED: &str = "users_created";
    /// Users updated (name, display name, groups, enabled again).
    pub const USERS_UPDATED: &str = "users_updated";
    /// Users disabled.
    pub const USERS_DISABLED: &str = "users_disabled";
    /// Duration, milliseconds.
    pub const DURATION_MS: &str = "duration_ms";

    /// Every name above.
    pub const ALL: &[&str] = &[
        AGENT_ID,
        GROUP_ID,
        ENROLLMENT_ID,
        SERIAL,
        FINGERPRINT,
        NOT_AFTER,
        KID,
        P256_PUBLIC,
        PEER_ADDR,
        CODE,
        REASON,
        LOST_COUNT,
        FIRST_SEQ,
        LAST_SEQ,
        HEAD_NO,
        HEARTBEAT_SECS,
        SCHEMA_VERSION,
        VERSION,
        OPTION,
        CLOSED_TUNNELS,
        FAILURES,
        BURNED,
        EXPIRES_AT,
        AGENT_VERSION,
        MIGRATIONS,
        FIRST_MS,
        LAST_MS,
        HEAD_COUNT,
        USER_ID,
        LOGIN_SESSION,
        RESOURCE_ID,
        ACCOUNT_ID,
        RIGHT_ID,
        ACCESS_SESSION,
        JTI,
        NAME,
        DISPLAY_NAME,
        RESOURCE,
        ACCOUNT,
        PROTOCOL,
        HOST,
        PORT,
        CERTIFICATE_SHA256,
        CLIENT_ADDR,
        MAX_SESSION_SECS,
        VALID_UNTIL,
        HOST_NAMES,
        POLICY_VERSION,
        BYTES_TO_TARGET,
        BYTES_FROM_TARGET,
        NOTIFIED_AGENTS,
        REVOKED_SESSIONS,
        HMAC,
        LOCKED_UNTIL,
        SHA256,
        SIZE,
        EVENTS,
        INVALID_UTF8,
        OUTPUT_BYTES,
        COMMAND_HMAC,
        LENGTH,
        COMPLETE,
        IMMUTABLE,
        CHANNEL,
        ROLE,
        SOURCE,
        FUNCTIONS,
        RIGHTS,
        TRANSFER,
        REQUEST,
        IDENTITY_SOURCE,
        USER_GROUP,
        DIRECTORY_DN,
        SERVER,
        USERS_SEEN,
        USERS_CREATED,
        USERS_UPDATED,
        USERS_DISABLED,
        DURATION_MS,
    ];
}

/// An audit event before it gets its place in a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    kind: EventKind,
    outcome: Outcome,
    actor_kind: ActorKind,
    actor: String,
    fields: Vec<Field>,
}

impl Event {
    /// A new event without fields.
    pub fn new(
        kind: EventKind,
        outcome: Outcome,
        actor_kind: ActorKind,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            outcome,
            actor_kind,
            actor: actor.into(),
            fields: Vec::new(),
        }
    }

    /// The kind of event.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    fn with(mut self, name: &'static str, value: Value) -> Self {
        self.fields.push(Field {
            name: name.to_owned(),
            value,
        });
        self
    }

    /// Adds a text field.
    #[must_use]
    pub fn text(self, name: &'static str, value: impl Into<String>) -> Self {
        self.with(name, Value::Text(value.into()))
    }

    /// Adds an integer field.
    #[must_use]
    pub fn u64(self, name: &'static str, value: u64) -> Self {
        self.with(name, Value::U64(value))
    }

    /// Adds a bytes field.
    #[must_use]
    pub fn bytes(self, name: &'static str, value: impl Into<Vec<u8>>) -> Self {
        self.with(name, Value::Bytes(value.into()))
    }

    /// Adds a UUID field.
    #[must_use]
    pub fn uuid(self, name: &'static str, value: [u8; 16]) -> Self {
        self.with(name, Value::Uuid(value))
    }

    /// Adds a boolean field.
    #[must_use]
    pub fn bool(self, name: &'static str, value: bool) -> Self {
        self.with(name, Value::Bool(value))
    }

    /// The record of this event at position `seq`, after the record whose
    /// hash is `prev_hash`. Fields are sorted by name.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedRecord`] for a duplicate field or any broken
    /// rule of the format (checked by encoding it).
    pub fn into_record(
        self,
        chain_id: ChainId,
        seq: u64,
        prev_hash: Digest,
        time_ms: u64,
    ) -> Result<Record, AuditError> {
        let mut fields = self.fields;
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        if fields.windows(2).any(|w| w[0].name == w[1].name) {
            return Err(AuditError::MalformedRecord("champ en double"));
        }
        let record = Record {
            chain_id,
            seq,
            prev_hash,
            time_ms,
            outcome: self.outcome,
            actor_kind: self.actor_kind,
            actor: self.actor,
            event: self.kind.name().to_owned(),
            fields,
        };
        record.encode()?;
        Ok(record)
    }
}

/// The tip of a chain: what the writer needs to append the next record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// The chain.
    pub chain_id: ChainId,
    /// Last written seq, 0 for an empty chain.
    pub seq: u64,
    /// Hash of the last record, [`ZERO_DIGEST`] for an empty chain.
    pub hash: Digest,
}

/// A record appended by [`ChainTip::append`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// Its seq.
    pub seq: u64,
    /// Its canonical encoding, to store as is.
    pub body: Vec<u8>,
    /// Its hash, the new tip.
    pub hash: Digest,
}

impl ChainTip {
    /// The tip of a new, empty chain.
    pub const fn empty(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            seq: 0,
            hash: ZERO_DIGEST,
        }
    }

    /// Encodes `event` as the next record and advances the tip. The tip is
    /// unchanged on error.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedRecord`] if the event breaks a rule of the
    /// format, or if the chain is full.
    pub fn append(&mut self, event: Event, time_ms: u64) -> Result<Appended, AuditError> {
        let seq = self
            .seq
            .checked_add(1)
            .ok_or(AuditError::MalformedRecord("chaîne pleine"))?;
        let body = event
            .into_record(self.chain_id, seq, self.hash, time_ms)?
            .encode()?;
        let hash = record_hash(&body);
        self.seq = seq;
        self.hash = hash;
        Ok(Appended { seq, body, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_are_unique_and_well_formed() {
        let mut names: Vec<&str> = EventKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), 71);
        for name in &names {
            assert!(
                (3..=64).contains(&name.len())
                    && name
                        .bytes()
                        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.')),
                "{name}"
            );
            assert!(name.contains('.'), "{name} has a domain");
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), EventKind::ALL.len(), "duplicate event name");
    }

    #[test]
    fn field_names_are_valid_unique_and_never_redacted() {
        let mut names = field::ALL.to_vec();
        for name in &names {
            assert!(crate::record::is_field_name(name.as_bytes()), "{name}");
            assert!(
                !ostena_common::logging::is_sensitive_field(name),
                "{name} would be redacted in the logs"
            );
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), field::ALL.len());
    }

    #[test]
    fn builder_sorts_fields_and_refuses_duplicates() {
        let chain = ChainId::from_bytes([7; 16]);
        let record = Event::new(
            EventKind::AgentRevoked,
            Outcome::Success,
            ActorKind::Admin,
            "alice",
        )
        .uuid(field::AGENT_ID, [1; 16])
        .text(field::REASON, "poste perdu")
        .u64(field::CLOSED_TUNNELS, 2)
        .into_record(chain, 1, ZERO_DIGEST, 1)
        .unwrap();
        let names: Vec<&str> = record.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["agent_id", "closed_tunnels", "reason"]);
        assert_eq!(record.field("closed_tunnels"), Some(&Value::U64(2)));
        assert_eq!(record.field("absent"), None);

        let duplicate = Event::new(
            EventKind::CoreStarted,
            Outcome::Success,
            ActorKind::Core,
            "",
        )
        .u64(field::VERSION, 1)
        .u64(field::VERSION, 2)
        .into_record(chain, 1, ZERO_DIGEST, 1);
        assert_eq!(
            duplicate,
            Err(AuditError::MalformedRecord("champ en double"))
        );
    }

    #[test]
    fn tip_advances_only_on_success() {
        let mut tip = ChainTip::empty(ChainId::from_bytes([1; 16]));
        let first = tip
            .append(
                Event::new(
                    EventKind::AuditChainStarted,
                    Outcome::Success,
                    ActorKind::Core,
                    "core",
                ),
                10,
            )
            .unwrap();
        assert_eq!((first.seq, tip.seq, tip.hash), (1, 1, first.hash));
        assert_eq!(first.hash, record_hash(&first.body));
        let bad = Event::new(
            EventKind::CoreStarted,
            Outcome::Success,
            ActorKind::Core,
            "a\nb",
        );
        assert!(tip.append(bad, 11).is_err());
        assert_eq!(tip.seq, 1);
        let second = tip
            .append(
                Event::new(
                    EventKind::CoreStarted,
                    Outcome::Success,
                    ActorKind::Core,
                    "core",
                ),
                12,
            )
            .unwrap();
        let decoded = Record::decode(&second.body).unwrap();
        assert_eq!((decoded.seq, decoded.prev_hash), (2, first.hash));
    }
}
