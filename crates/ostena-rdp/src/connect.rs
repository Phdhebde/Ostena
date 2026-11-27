//! The connection sequence ([MS-RDPBCGR] 1.3.1.1, ADR-0019 section 4),
//! driven by the agent around `ironrdp-connector`:
//!
//! 1. TCP towards a pinned address (scope control, ADR-0005);
//! 2. X.224, rewritten and checked by the [guard](crate::guard);
//! 3. TLS built by `ostena-crypto`, certificate validated before any
//!    credential, then CredSSP driven by the agent ([`crate::credssp`]);
//! 4. MCS Connect Initial (early capability flags filtered by the guard),
//!    channels, licences (cache of the core), capabilities, finalization.
//!
//! Each phase is timed and its round trips counted (`rdp.connect_phases`);
//! what the target showed becomes its [`TargetProfile`], compared with the
//! profile the core sent (`rdp.profile_changed`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use ironrdp_connector::{
    ClientConnector, ClientConnectorState, Config, ConnectionOutcome, ConnectionResult,
    ConnectorError, ConnectorErrorKind, Credentials, DesktopSize, MonotonicInstant, Sequence as _,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::gcc::{self, ServerEarlyCapabilityFlags};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ostena_crypto::tls::ServerName;
use ostena_crypto::tls::target::{TargetTrust, target_client_config};
use serde::Serialize;
use tokio::net::TcpStream;

use crate::credssp::{self, Authentication};
use crate::error::RdpError;
use crate::guard::{self, Confirmed};
use crate::profile::{
    Licenses, ServerSettings, StoredLicense, TargetProfile, server_settings, to_hex,
};
use crate::transport::{MAX_PDU, Transport};

/// What the connection needs besides the address.
pub struct ConnectParams {
    /// Name of the target for the TLS SNI and the certificate checks: its
    /// DNS name from the inventory, or its address.
    pub server_name: String,
    /// How the certificate of the target is trusted.
    pub trust: TargetTrust,
    /// The authentication played in CredSSP.
    pub auth: Authentication,
    /// Desktop size requested.
    pub desktop: DesktopSize,
    /// Client name presented (licences; [`crate::profile::client_identity`]).
    pub client_name: String,
    /// Hardware identifier presented (licences).
    pub hardware_id: [u32; 4],
    /// Profile of the target remembered by the core, if any.
    pub profile: Option<TargetProfile>,
    /// Licence kept by the core for this agent and target, if any.
    pub license: Option<StoredLicense>,
    /// Names the target in events (sanitised by the caller).
    pub label: String,
}

impl std::fmt::Debug for ConnectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectParams")
            .field("server_name", &self.server_name)
            .field("auth", &self.auth)
            .field("desktop", &self.desktop)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// One phase of the sequence, as logged in `rdp.connect_phases`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PhaseMeasure {
    /// Name of the phase.
    pub phase: &'static str,
    /// Duration, in milliseconds.
    pub millis: u64,
    /// Waits for the target (a read with nothing pending): the round trips.
    pub round_trips: u32,
}

/// What the sequence tells the core, in the report of the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectReport {
    /// The profile observed.
    pub profile: TargetProfile,
    /// Fields that differ from the profile sent by the core (empty without
    /// one, or when nothing changed).
    pub profile_changed: Vec<&'static str>,
    /// Licence issued by the target during this connection, to keep.
    pub license: Option<StoredLicense>,
    /// The phases, in order.
    pub phases: Vec<PhaseMeasure>,
    /// NTLM was used (admitted fallback; `rdp.ntlm_used`).
    pub ntlm_used: bool,
    /// Exchanges with a KDC.
    pub kdc_exchanges: u32,
    /// Early capability bits removed by the guard from the connector's
    /// Connect Initial.
    pub early_capabilities_removed: u32,
    /// Windows sessions of the account the driver logged off on the target
    /// before this connection (ADR-0026).
    pub sessions_logged_off: Vec<u32>,
}

/// An established connection, ready for the session loop.
pub struct Established {
    /// The transport, TLS up.
    pub transport: Transport,
    /// What the connector negotiated.
    pub result: ConnectionResult,
    /// The report.
    pub report: ConnectReport,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established")
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

/// Phases of the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Tcp,
    X224,
    Tls,
    Credssp,
    Mcs,
    Licensing,
    Activation,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::X224 => "x224",
            Self::Tls => "tls",
            Self::Credssp => "credssp",
            Self::Mcs => "mcs",
            Self::Licensing => "licensing",
            Self::Activation => "activation",
        }
    }

    fn of(state: &ClientConnectorState) -> Self {
        match state {
            ClientConnectorState::ConnectionInitiationSendRequest
            | ClientConnectorState::ConnectionInitiationWaitConfirm { .. } => Self::X224,
            ClientConnectorState::EnhancedSecurityUpgrade { .. } => Self::Tls,
            ClientConnectorState::Credssp { .. } => Self::Credssp,
            ClientConnectorState::LicensingExchange { .. } => Self::Licensing,
            // After the licences, waiting for the Demand Active.
            ClientConnectorState::MultitransportBootstrapping { .. }
            | ClientConnectorState::MultitransportPending { .. }
            | ClientConnectorState::CapabilitiesExchange { .. }
            | ClientConnectorState::ConnectionFinalization { .. }
            | ClientConnectorState::Connected { .. } => Self::Activation,
            _ => Self::Mcs,
        }
    }
}

/// Times the phases and counts their round trips.
struct Clock {
    origin: Instant,
    current: Phase,
    started: Instant,
    round_trips: u32,
    done: Vec<PhaseMeasure>,
}

impl Clock {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            origin: now,
            current: Phase::Tcp,
            started: now,
            round_trips: 0,
            done: Vec::new(),
        }
    }

    fn enter(&mut self, phase: Phase) {
        if phase == self.current {
            return;
        }
        let now = Instant::now();
        self.done.push(PhaseMeasure {
            phase: self.current.name(),
            millis: millis(now.duration_since(self.started)),
            round_trips: self.round_trips,
        });
        self.current = phase;
        self.started = now;
        self.round_trips = 0;
    }

    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_millis(millis(self.origin.elapsed()))
    }

    fn finish(mut self) -> Vec<PhaseMeasure> {
        let now = Instant::now();
        self.done.push(PhaseMeasure {
            phase: self.current.name(),
            millis: millis(now.duration_since(self.started)),
            round_trips: self.round_trips,
        });
        self.done
    }
}

fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The connector configuration: NLA only, no password (CredSSP carries the
/// credentials), no channel, no compression, no audio, no multitransport.
fn connector_config(params: &ConnectParams, licenses: Arc<Licenses>) -> Config {
    Config {
        desktop_size: params.desktop,
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls: false,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        // The password never goes to the connector: the Client Info PDU
        // carries none, CredSSP has already authenticated the session.
        credentials: Credentials::UsernamePassword {
            username: params.auth.username.clone(),
            password: String::new(),
        },
        domain: None,
        client_build: 0,
        client_name: params.client_name.clone(),
        keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        connection_type: gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        platform: MajorPlatformType::UNSPECIFIED,
        hardware_id: Some(params.hardware_id),
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
        license_cache: Some(licenses),
        timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
    }
}

/// Maps an error of the connector in `phase`.
fn connector_error(phase: Phase, e: &ConnectorError) -> RdpError {
    let text = e.report().to_string();
    match e.kind() {
        ConnectorErrorKind::AccessDenied => RdpError::AccessDenied,
        ConnectorErrorKind::Negotiation(_) => RdpError::NoNla,
        _ if phase == Phase::Licensing => RdpError::License(text),
        _ => RdpError::Protocol(text),
    }
}

/// Reads the next PDU the connector expects, skipping those that do not
/// match its hint; counts a round trip at each wait.
async fn read_hinted(
    transport: &mut Transport,
    hint: &dyn ironrdp_pdu::PduHint,
    clock: &mut Clock,
) -> Result<Vec<u8>, RdpError> {
    loop {
        match hint
            .find_size(transport.pending())
            .map_err(|e| RdpError::Protocol(format!("trame : {e}")))?
        {
            Some((_, 0)) => return Err(RdpError::Protocol("trame de taille nulle".into())),
            Some((_, size)) if size > MAX_PDU => {
                return Err(RdpError::Protocol(format!(
                    "taille de PDU {size} hors bornes"
                )));
            }
            Some((matched, size)) if transport.pending().len() >= size => {
                let pdu = transport.consume(size);
                if matched {
                    return Ok(pdu);
                }
                tracing::debug!(size, "PDU inattendue ignorée pendant la séquence");
            }
            _ => {
                if transport.pending().is_empty() {
                    clock.round_trips = clock.round_trips.saturating_add(1);
                }
                transport.fill().await?;
            }
        }
    }
}

/// Whether `pdu` is a licensing PDU: an indication whose data decodes as
/// one (`SEC_LICENSE_PKT` in its basic security header, [MS-RDPBCGR]
/// 2.2.8.1.1.2.1). The flag alone is not enough: with TLS, a Share Control
/// PDU starts with its length, whose bit 0x0080 may be set.
fn is_license_pdu(pdu: &[u8]) -> bool {
    ironrdp_pdu::mcs::decode_send_data_indication(pdu).is_ok_and(|data| {
        ironrdp_core::decode::<ironrdp_pdu::rdp::server_license::LicensePdu>(data.user_data).is_ok()
    })
}

/// What the sequence observed, for the profile.
#[derive(Default)]
struct Observed {
    confirmed: Option<Confirmed>,
    server: Option<ServerSettings>,
    removed: u32,
}

/// Runs the whole sequence towards `addr`.
///
/// # Errors
///
/// The [`RdpError`] of the step that failed; nothing is sent after a
/// refusal.
pub async fn establish(addr: SocketAddr, params: ConnectParams) -> Result<Established, RdpError> {
    let mut clock = Clock::new();
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| RdpError::Unreachable(e.kind().to_string()))?;
    clock.round_trips = 1;
    let mut transport = Transport::new(tcp);
    let client_addr = transport
        .local_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let (tls_config, check) =
        target_client_config(&params.trust).map_err(|e| RdpError::Tls(e.to_string()))?;
    let server_name = ServerName::try_from(params.server_name.clone())
        .map_err(|_| RdpError::Params("nom de la cible invalide pour TLS".into()))?;
    let licenses = Licenses::new(params.license.clone());
    let mut connector =
        ClientConnector::new(connector_config(&params, licenses.clone()), client_addr);
    let restricted_admin = params.auth.restricted_admin;
    let mut observed = Observed::default();
    let mut buf = WriteBuf::new();

    // X.224 request, rewritten by the guard.
    clock.enter(Phase::X224);
    connector
        .step_no_input(&mut buf)
        .map_err(|e| connector_error(Phase::X224, &e))?;
    let request = guard::rewrite_connection_request(buf.filled(), restricted_admin)?;
    transport.write_all(&request).await?;
    let hint = connector
        .next_pdu_hint()
        .ok_or_else(|| RdpError::Protocol("pas de confirmation X.224 attendue".into()))?;
    let confirm = read_hinted(&mut transport, hint, &mut clock).await?;
    let confirmed = guard::check_connection_confirm(&confirm, restricted_admin)?;
    observed.confirmed = Some(confirmed);
    buf.clear();
    connector
        .step(&confirm, Some(clock.now()), &mut buf)
        .map_err(|e| connector_error(Phase::X224, &e))?;
    if !connector.should_perform_security_upgrade() {
        return Err(RdpError::Protocol("TLS non demandée après X.224".into()));
    }

    // TLS: the certificate is checked before any credential.
    clock.enter(Phase::Tls);
    transport.start_tls(tls_config, server_name, &check).await?;
    clock.round_trips = clock.round_trips.saturating_add(2);
    connector.mark_security_upgrade_as_done();
    if !connector.should_perform_credssp() {
        return Err(RdpError::NoNla);
    }

    clock.enter(Phase::Credssp);
    let public_key = check
        .verified_public_key()
        .ok_or(RdpError::Certificate("non vérifié"))?;
    let outcome = credssp::authenticate(
        &mut transport,
        &params.auth,
        public_key,
        confirmed.protocol == SecurityProtocol::HYBRID_EX,
    )
    .await?;
    clock.round_trips = clock.round_trips.saturating_add(outcome.rounds);
    connector.mark_credssp_as_done();

    let result =
        run_to_connected(&mut connector, &mut transport, &mut clock, &mut observed).await?;

    let profile = observe(&observed, &check, &result);
    let profile_changed = params
        .profile
        .as_ref()
        .map(|old| old.differences(&profile))
        .unwrap_or_default();
    let report = ConnectReport {
        profile,
        profile_changed,
        license: licenses.issued(),
        phases: clock.finish(),
        ntlm_used: outcome.ntlm_used,
        kdc_exchanges: outcome.kdc_exchanges,
        early_capabilities_removed: observed.removed,
        sessions_logged_off: Vec::new(),
    };
    log_report(&params.label, &report);
    Ok(Established {
        transport,
        result,
        report,
    })
}

/// After CredSSP: MCS, channels, licences, capabilities, finalization.
async fn run_to_connected(
    connector: &mut ClientConnector,
    transport: &mut Transport,
    clock: &mut Clock,
    observed: &mut Observed,
) -> Result<ConnectionResult, RdpError> {
    let mut buf = WriteBuf::new();
    loop {
        if let Some(outcome) = connector.state.take_outcome() {
            match outcome {
                ConnectionOutcome::Connected(result) => return Ok(result),
                ConnectionOutcome::Redirected(_) => return Err(RdpError::Redirected),
            }
        }
        let phase = Phase::of(&connector.state);
        clock.enter(phase);
        buf.clear();
        if connector.should_perform_multitransport() {
            connector
                .skip_multitransport(&mut buf)
                .map_err(|e| connector_error(phase, &e))?;
        } else if let Some(hint) = connector.next_pdu_hint() {
            let waiting_response = matches!(
                connector.state,
                ClientConnectorState::BasicSettingsExchangeWaitResponse { .. }
            );
            let pdu = read_hinted(transport, hint, clock).await?;
            if waiting_response {
                observed.server = server_settings(&pdu);
            }
            // The first licence PDU may arrive while the connector still
            // waits for connect-time Auto-Detect: the phase is that of the PDU.
            // Licensing comes before the capabilities exchange: never after.
            let phase = if matches!(phase, Phase::Mcs | Phase::Licensing) && is_license_pdu(&pdu) {
                clock.enter(Phase::Licensing);
                Phase::Licensing
            } else {
                phase
            };
            connector
                .step(&pdu, Some(clock.now()), &mut buf)
                .map_err(|e| connector_error(phase, &e))?;
        } else {
            let initial = matches!(
                connector.state,
                ClientConnectorState::BasicSettingsExchangeSendInitial { .. }
            );
            connector
                .step_no_input(&mut buf)
                .map_err(|e| connector_error(phase, &e))?;
            if initial && !buf.filled().is_empty() {
                let (pdu, removed) = guard::rewrite_connect_initial(
                    buf.filled(),
                    guard::allowed_early_capabilities(),
                )?;
                observed.removed = u32::from(removed.bits());
                transport.write_all(&pdu).await?;
                continue;
            }
        }
        if !buf.filled().is_empty() {
            transport.write_all(buf.filled()).await?;
        }
    }
}

/// The profile of the target from what the sequence saw.
fn observe(
    observed: &Observed,
    check: &ostena_crypto::tls::target::TargetCheck,
    result: &ConnectionResult,
) -> TargetProfile {
    let server = observed.server.clone();
    let early = server.as_ref().map_or(0, |s| s.early_capabilities);
    let mut static_channels: Vec<(String, u16)> = result
        .static_channels
        .iter()
        .filter_map(|(_, channel)| {
            let name = channel.channel_name();
            let id = result
                .static_channels
                .get_channel_id_by_channel_name(&name)?;
            Some((name.as_str()?.to_owned(), id))
        })
        .collect();
    static_channels.sort_by_key(|(_, id)| *id);
    TargetProfile {
        rdp_version: server.as_ref().map_or(0, |s| s.rdp_version),
        security_protocol: observed.confirmed.map_or(0, |c| c.protocol.bits()),
        response_flags: observed.confirmed.map_or(0, |c| c.flags.bits()),
        server_early_capabilities: early,
        static_channels,
        skip_channel_join: ServerEarlyCapabilityFlags::from_bits_truncate(early)
            .contains(ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED),
        message_channel: server.as_ref().is_some_and(|s| s.message_channel),
        certificate: check
            .presented()
            .map(|p| to_hex(&p.fingerprint))
            .unwrap_or_default(),
    }
}

fn log_report(label: &str, report: &ConnectReport) {
    let phases: Vec<String> = report
        .phases
        .iter()
        .map(|p| format!("{}={}ms/{}", p.phase, p.millis, p.round_trips))
        .collect();
    tracing::info!(
        event = "rdp.connect_phases",
        target = label,
        phases = phases.join(" "),
        kdc_exchanges = report.kdc_exchanges,
        "séquence de connexion RDP établie"
    );
    if report.ntlm_used {
        tracing::warn!(
            event = "rdp.ntlm_used",
            target = label,
            "repli NTLM admis utilisé (Restricted Admin)"
        );
    }
    if !report.profile_changed.is_empty() {
        tracing::info!(
            event = "rdp.profile_changed",
            target = label,
            fields = report.profile_changed.join(","),
            "profil de la cible modifié : remplacé"
        );
    }
    if report.early_capabilities_removed != 0 {
        tracing::debug!(
            target = label,
            removed = format!("0x{:04x}", report.early_capabilities_removed),
            "drapeaux de capacité précoce retirés par la garde"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ironrdp_core::encode_vec;
    use ironrdp_pdu::mcs::{McsMessage, SendDataIndication};
    use ironrdp_pdu::x224::X224;

    use super::is_license_pdu;

    fn indication(data: &[u8]) -> Vec<u8> {
        encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
            initiator_id: 1002,
            channel_id: 1003,
            user_data: Cow::Borrowed(data),
        })))
        .unwrap()
    }

    /// A Share Control PDU of 0x01a0 bytes: its length has the bit of
    /// `SEC_LICENSE_PKT`, it is not a licence PDU (seen on Windows Server
    /// with a Demand Active).
    #[test]
    fn share_control_length_is_not_a_licence_flag() {
        let mut data = vec![0u8; 0x01a0];
        data[..6].copy_from_slice(&[0xa0, 0x01, 0x11, 0x00, 0xea, 0x03]);
        assert!(!is_license_pdu(&indication(&data)));
    }

    #[test]
    fn licence_pdu_is_recognised() {
        let seed = include_bytes!("../../../fuzz/corpus/rdp_license/seed-autodetect-07");
        assert!(is_license_pdu(seed));
    }
}
