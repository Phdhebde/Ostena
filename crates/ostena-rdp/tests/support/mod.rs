//! A small RDP target for the tests (ADR-0019 section 7), built on
//! `ironrdp-acceptor` of the same generation as the connector: X.224, TLS
//! (test certificate of `ostena-crypto`), CredSSP server by `sspi` (NTLM),
//! MCS, licences, capabilities, finalization, then a scripted session.
//!
//! It runs on a thread with blocking I/O, independent of the client
//! runtime, and can misbehave on demand ([`Misbehave`]). What it saw is
//! returned in a [`Seen`].

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test uses a part of the support"
)]
#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use ironrdp_acceptor::{Acceptor, DesktopSize};
use ironrdp_connector::Sequence as _;
use ironrdp_connector::sspi::credssp::EarlyUserAuthResult;
use ironrdp_connector::sspi::credssp::{
    CredSspServer, CredentialsProxy, ServerMode, ServerState, TsRequest,
};
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::sspi::ntlm::NtlmConfig;
use ironrdp_connector::sspi::{AuthIdentity, NegotiateConfig, Username};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc::ClientEarlyCapabilityFlags;
use ironrdp_pdu::mcs::{ConnectInitial, McsMessage, SendDataIndication};
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::autodetect::{
    AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu, BW_START_LOSSY_UDP,
    BW_START_RELIABLE_UDP, BW_STOP_RELIABLE_UDP, RTT_REQUEST_CONTINUOUS,
};
use ironrdp_pdu::rdp::capability_sets::{
    Bitmap, BitmapDrawingFlags, CapabilitySet, General, GeneralExtraFlags, Input, InputFlags,
    MultifragmentUpdate, Order, OrderFlags, OrderSupportExFlags, Pointer, VirtualChannel,
    VirtualChannelFlags,
};
use ironrdp_pdu::rdp::headers::{
    CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu,
    StreamPriority,
};
use ironrdp_pdu::rdp::server_error_info::{
    ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu,
};
use ironrdp_pdu::x224::{X224, X224Data};
use ostena_crypto::tls::ServerConnection;
use ostena_crypto::tls::target::testing::{
    KeyKind, TargetIdentity, Versions, self_signed, server_config,
};
use ostena_rdp::credssp::ts_request_size;

/// The account the target accepts.
pub const USER: &str = "admin";
/// Its password.
pub const PASSWORD: &str = "correct horse battery staple";

/// How the target misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehave {
    /// A conforming target.
    None,
    /// Offers TLS only, no NLA.
    NoNla,
    /// Refuses the user after CredSSP (early user authorization).
    AccessDenied,
    /// Announces CredSSP version `n` in its answers.
    CredSspVersion(u8),
    /// Answers the licensing with `ERR_INVALID_CLIENT`.
    LicenseError,
}

/// What the scripted session does once connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Error information `LogoffByUser`, then disconnection.
    Logoff,
    /// Auto-Detect requests (round trip, bandwidth, unknown), then logoff.
    AutoDetect,
    /// Error information with a failure code, then disconnection.
    ServerError,
    /// Waits for the client to disconnect.
    WaitClient,
}

/// Options of the target.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Misbehaviour.
    pub misbehave: Misbehave,
    /// Session script.
    pub script: Script,
    /// Announce `RESTRICTED_ADMIN_MODE_SUPPORTED`.
    pub restricted_admin: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            misbehave: Misbehave::None,
            script: Script::Logoff,
            restricted_admin: false,
        }
    }
}

/// What the target saw.
#[derive(Debug, Default)]
pub struct Seen {
    /// The X.224 Connection Request, raw.
    pub connection_request: Vec<u8>,
    /// The protocols requested.
    pub requested_protocols: u32,
    /// The early capability flags of the Connect Initial.
    pub early_capabilities: Option<ClientEarlyCapabilityFlags>,
    /// The client name in the Connect Initial.
    pub client_name: String,
    /// CredSSP finished.
    pub credssp_done: bool,
    /// Bytes received after TLS, before the end of CredSSP.
    pub credssp_bytes: usize,
    /// Reached the end of the sequence.
    pub accepted: bool,
    /// Auto-Detect responses received.
    pub autodetect_responses: Vec<AutoDetectResponse>,
    /// Why the target stopped, if early.
    pub error: Option<String>,
}

/// A running target.
pub struct Target {
    /// Its address.
    pub addr: SocketAddr,
    /// Its identity (certificate and key).
    pub identity: Arc<TargetIdentity>,
    handle: JoinHandle<Seen>,
}

impl Target {
    /// Starts a target with a fresh self-signed RSA 2048 certificate.
    pub fn start(options: Options) -> Self {
        let identity = Arc::new(self_signed(KeyKind::Rsa2048, "target.example.test").unwrap());
        Self::start_with(options, identity)
    }

    /// Starts a target presenting `identity`.
    pub fn start_with(options: Options, identity: Arc<TargetIdentity>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let id = identity.clone();
        let handle = std::thread::spawn(move || {
            let mut seen = Seen::default();
            let Ok((tcp, _)) = listener.accept() else {
                seen.error = Some("accept".into());
                return seen;
            };
            tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
            if let Err(e) = serve(tcp, options, &id, &mut seen) {
                seen.error = Some(e);
            }
            seen
        });
        Self {
            addr,
            identity,
            handle,
        }
    }

    /// Its certificate fingerprint.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }

    /// Waits for the target to stop.
    pub fn join(self) -> Seen {
        self.handle.join().unwrap()
    }
}

/// Blocking byte stream, TCP then TLS.
struct Stream {
    tcp: TcpStream,
    tls: Option<ServerConnection>,
    pending: Vec<u8>,
    received: usize,
}

impl Stream {
    fn fill(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 16 * 1024];
        match &mut self.tls {
            None => {
                let n = self.tcp.read(&mut buf)?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.received += n;
                self.pending.extend_from_slice(&buf[..n]);
            }
            Some(tls) => loop {
                match tls.reader().read(&mut buf) {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) => {
                        self.received += n;
                        self.pending.extend_from_slice(&buf[..n]);
                        return Ok(());
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                let (rd, _) = tls.complete_io(&mut self.tcp)?;
                if rd == 0 && !tls.wants_read() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            },
        }
        Ok(())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.tls {
            None => self.tcp.write_all(data),
            Some(tls) => {
                tls.writer().write_all(data)?;
                while tls.wants_write() {
                    tls.write_tls(&mut self.tcp)?;
                }
                Ok(())
            }
        }
    }

    /// Reads one PDU whose size `size` tells.
    fn read(&mut self, size: impl Fn(&[u8]) -> Option<usize>) -> io::Result<Vec<u8>> {
        loop {
            if let Some(n) = size(&self.pending)
                && self.pending.len() >= n
            {
                return Ok(self.pending.drain(..n).collect());
            }
            self.fill()?;
        }
    }

    fn read_hinted(&mut self, hint: &dyn ironrdp_pdu::PduHint) -> io::Result<Vec<u8>> {
        loop {
            match hint.find_size(&self.pending).map_err(io::Error::other)? {
                Some((matched, n)) if self.pending.len() >= n => {
                    let pdu: Vec<u8> = self.pending.drain(..n).collect();
                    if matched {
                        return Ok(pdu);
                    }
                }
                _ => self.fill()?,
            }
        }
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        self.read(|b| ironrdp_pdu::find_size(b).ok().flatten().map(|i| i.length))
    }
}

fn capabilities(size: DesktopSize) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(General {
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
            ..General::default()
        }),
        CapabilitySet::Bitmap(Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: size.width,
            desktop_height: size.height,
            desktop_resize_flag: true,
            drawing_flags: BitmapDrawingFlags::empty(),
        }),
        CapabilitySet::Order(Order::new(
            OrderFlags::empty(),
            OrderSupportExFlags::empty(),
            2048,
            224,
        )),
        CapabilitySet::Pointer(Pointer {
            color_pointer_cache_size: 2048,
            pointer_cache_size: 2048,
        }),
        CapabilitySet::Input(Input {
            input_flags: InputFlags::SCANCODES | InputFlags::FASTPATH_INPUT | InputFlags::UNICODE,
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            keyboard_ime_filename: String::new(),
        }),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: None,
        }),
        CapabilitySet::MultiFragmentUpdate(MultifragmentUpdate {
            max_request_size: 8 * 1024 * 1024,
        }),
    ]
}

/// The single account of the target.
struct Accounts;

impl CredentialsProxy for Accounts {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> io::Result<AuthIdentity> {
        if username.account_name() != USER {
            return Err(io::Error::other("unknown user"));
        }
        Ok(AuthIdentity {
            username: username.clone(),
            password: PASSWORD.to_owned().into(),
        })
    }

    fn auth_data(&mut self) -> io::Result<Vec<AuthIdentity>> {
        Ok(vec![AuthIdentity {
            username: Username::new(USER, None).map_err(io::Error::other)?,
            password: PASSWORD.to_owned().into(),
        }])
    }
}

fn err(context: &str, e: impl std::fmt::Display) -> String {
    format!("{context}: {e}")
}

/// Rewrites the server answers of CredSSP to announce `version`.
fn patch_version(bytes: &mut [u8], version: u8) {
    if let Some(i) = bytes.windows(4).position(|w| w == [0xa0, 0x03, 0x02, 0x01]) {
        bytes[i + 4] = version;
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one scripted target, read top to bottom"
)]
fn serve(
    tcp: TcpStream,
    options: Options,
    identity: &TargetIdentity,
    seen: &mut Seen,
) -> Result<(), String> {
    let mut stream = Stream {
        tcp,
        tls: None,
        pending: Vec::new(),
        received: 0,
    };
    let size = DesktopSize {
        width: 1280,
        height: 720,
    };
    let security = if options.misbehave == Misbehave::NoNla {
        SecurityProtocol::SSL
    } else {
        SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
    };
    let mut acceptor = Acceptor::new(security, size, capabilities(size), None);
    let mut buf = WriteBuf::new();

    // X.224.
    let request = stream
        .read_hinted(&ironrdp_pdu::X224_HINT)
        .map_err(|e| err("X.224", e))?;
    seen.connection_request.clone_from(&request);
    if let Ok(X224(r)) = decode::<X224<ConnectionRequest>>(&request) {
        seen.requested_protocols = r.protocol.bits();
    }
    acceptor
        .step(&request, None, &mut buf)
        .map_err(|e| err("X.224", e))?;
    buf.clear();
    let confirm = acceptor.step_no_input(&mut buf);
    let mut out = buf.filled().to_vec();
    if options.restricted_admin
        && let Ok(X224(ConnectionConfirm::Response { flags, protocol })) =
            decode::<X224<ConnectionConfirm>>(&out)
    {
        out = encode_vec(&X224(ConnectionConfirm::Response {
            flags: flags | ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED,
            protocol,
        }))
        .unwrap();
    }
    stream.write_all(&out).map_err(|e| err("X.224", e))?;
    let protocol = confirm.map_err(|e| err("confirmation", e)).and_then(|_| {
        acceptor
            .reached_security_upgrade()
            .ok_or_else(|| "pas de TLS".to_owned())
    })?;

    // TLS.
    let config = server_config(identity, Versions::Both).map_err(|e| err("TLS", e))?;
    let mut tls = ServerConnection::new(config).map_err(|e| err("TLS", e))?;
    while tls.is_handshaking() {
        tls.complete_io(&mut stream.tcp)
            .map_err(|e| err("TLS", e))?;
    }
    stream.tls = Some(tls);
    acceptor.mark_security_upgrade_as_done();
    let start = stream.received;

    // CredSSP, NTLM.
    let public_key = ostena_crypto::tls::target::subject_public_key(identity.certificate.as_ref())
        .unwrap()
        .to_vec();
    let mut server = CredSspServer::new(
        public_key,
        Accounts,
        ServerMode::Negotiate(NegotiateConfig {
            protocol_config: Box::new(NtlmConfig::new("TARGET".to_owned())),
            package_list: Some("!kerberos,ntlm".to_owned()),
            client_computer_name: "TARGET".to_owned(),
        }),
    )
    .map_err(|e| err("CredSSP", e))?;
    let mut failed = None;
    loop {
        let pdu = stream
            .read(|b| ts_request_size(b).ok().flatten())
            .map_err(|e| err("TSRequest", e))?;
        let request = TsRequest::from_buffer(&pdu).map_err(|e| err("TSRequest", e))?;
        let result = match server.process(request).start() {
            GeneratorState::Completed(r) => r,
            GeneratorState::Suspended(_) => {
                return Err("CredSSP serveur : requête réseau inattendue".into());
            }
        };
        let (answer, done) = match result {
            Ok(ServerState::ReplyNeeded(ts)) => (Some(ts), false),
            Ok(ServerState::Finished(_)) => (None, true),
            Err(e) => {
                failed = Some(format!("CredSSP: {:?}", e.error));
                (e.ts_request.map(|t| *t), true)
            }
        };
        if let Some(ts) = answer {
            let mut bytes = Vec::new();
            ts.encode_ts_request(&mut bytes)
                .map_err(|e| err("TSRequest", e))?;
            if let Misbehave::CredSspVersion(v) = options.misbehave {
                patch_version(&mut bytes, v);
            }
            stream.write_all(&bytes).map_err(|e| err("CredSSP", e))?;
        }
        if done {
            break;
        }
    }
    seen.credssp_bytes = stream.received - start;
    if protocol.contains(SecurityProtocol::HYBRID_EX) {
        let result = if failed.is_some() || options.misbehave == Misbehave::AccessDenied {
            EarlyUserAuthResult::AccessDenied
        } else {
            EarlyUserAuthResult::Success
        };
        buf.clear();
        result.to_buffer(&mut buf).unwrap();
        stream
            .write_all(&buf.filled()[..4])
            .map_err(|e| err("EUAR", e))?;
    }
    if let Some(e) = failed {
        return Err(e);
    }
    if options.misbehave == Misbehave::AccessDenied {
        return Err("accès refusé (scénario)".into());
    }
    seen.credssp_done = true;
    acceptor.mark_credssp_as_done();

    // MCS, licences, capabilities, finalization.
    let result = loop {
        if let Some(result) = acceptor.get_result() {
            break result;
        }
        buf.clear();
        let licensing = acceptor.state().name() == "LicensingExchange";
        let written = match acceptor.next_pdu_hint() {
            Some(hint) => {
                let pdu = stream.read_hinted(hint).map_err(|e| err("séquence", e))?;
                if seen.early_capabilities.is_none()
                    && let Ok(X224(data)) = decode::<X224<X224Data<'_>>>(&pdu)
                    && let Ok(initial) = decode::<ConnectInitial>(data.data.as_ref())
                {
                    let blocks = initial.conference_create_request.gcc_blocks();
                    seen.early_capabilities = blocks.core.optional_data.early_capability_flags;
                    seen.client_name.clone_from(&blocks.core.client_name);
                }
                acceptor.step(&pdu, None, &mut buf)
            }
            None => acceptor.step_no_input(&mut buf),
        }
        .map_err(|e| err("séquence", e))?;
        if let Some(n) = written.size() {
            let mut out = buf.filled()[..n].to_vec();
            if licensing && options.misbehave == Misbehave::LicenseError {
                // ERR_INVALID_CLIENT, ST_TOTAL_ABORT: the last fields of
                // the error message (code, transition, empty blob).
                let len = out.len();
                out[len - 12..len - 8].copy_from_slice(&8u32.to_le_bytes());
                out[len - 8..len - 4].copy_from_slice(&1u32.to_le_bytes());
                stream.write_all(&out).map_err(|e| err("licence", e))?;
                // The client stops here.
                let _ = stream.read_frame();
                return Err("licence refusée (scénario)".into());
            }
            stream.write_all(&out).map_err(|e| err("séquence", e))?;
        }
    };
    seen.accepted = true;
    let user = result.user_channel_id;
    let io = result.io_channel_id;
    let message = result.message_channel_id;

    let send = |stream: &mut Stream, channel: u16, data: Vec<u8>| -> Result<(), String> {
        let pdu = X224(McsMessage::SendDataIndication(SendDataIndication {
            initiator_id: user,
            channel_id: channel,
            user_data: Cow::Owned(data),
        }));
        stream
            .write_all(&encode_vec(&pdu).unwrap())
            .map_err(|e| err("envoi", e))
    };
    let error_info = |code: ProtocolIndependentCode| {
        encode_vec(&ShareControlHeader {
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                    ErrorInfo::ProtocolIndependentCode(code),
                )),
                stream_priority: StreamPriority::Undefined,
                compression_flags: CompressionFlags::empty(),
                compression_type: ironrdp_pdu::rdp::client_info::CompressionType::K8,
            }),
            pdu_source: user,
            share_id: 0,
        })
        .unwrap()
    };
    let ultimatum = || {
        encode_vec(&X224(McsMessage::DisconnectProviderUltimatum(
            ironrdp_pdu::mcs::DisconnectProviderUltimatum::from_reason(
                ironrdp_pdu::mcs::DisconnectReason::ProviderInitiated,
            ),
        )))
        .unwrap()
    };

    match options.script {
        Script::WaitClient => {
            while stream.read_frame().is_ok() {}
            return Ok(());
        }
        Script::AutoDetect => {
            let channel = message.ok_or("pas de canal de messages")?;
            let requests = [
                AutoDetectRequest::RttRequest {
                    sequence_number: 1,
                    request_type: RTT_REQUEST_CONTINUOUS,
                },
                AutoDetectRequest::BandwidthMeasureStart {
                    sequence_number: 2,
                    request_type: BW_START_RELIABLE_UDP,
                },
                AutoDetectRequest::BandwidthMeasureStop {
                    sequence_number: 3,
                    request_type: BW_STOP_RELIABLE_UDP,
                    payload: Some(vec![0x5a; 1024]),
                },
                // Lossy UDP: not on this transport, ignored by the client.
                AutoDetectRequest::BandwidthMeasureStart {
                    sequence_number: 4,
                    request_type: BW_START_LOSSY_UDP,
                },
                AutoDetectRequest::RttRequest {
                    sequence_number: 5,
                    request_type: RTT_REQUEST_CONTINUOUS,
                },
            ];
            for request in requests {
                send(
                    &mut stream,
                    channel,
                    encode_vec(&AutoDetectReqPdu::new(request)).unwrap(),
                )?;
            }
            // An undecodable request: ignored, never fatal.
            send(
                &mut stream,
                channel,
                vec![0x00, 0x10, 0x00, 0x00, 0x06, 0x00, 0x09, 0x00, 0xff, 0xff],
            )?;
            while seen.autodetect_responses.len() < 3 {
                let frame = stream.read_frame().map_err(|e| err("réponses", e))?;
                let Ok(X224(McsMessage::SendDataRequest(data))) =
                    decode::<X224<McsMessage<'_>>>(&frame)
                else {
                    continue;
                };
                if data.channel_id == channel
                    && let Ok(rsp) = decode::<AutoDetectRspPdu>(data.user_data.as_ref())
                {
                    seen.autodetect_responses.push(rsp.response);
                }
            }
            send(
                &mut stream,
                io,
                error_info(ProtocolIndependentCode::LogoffByUser),
            )?;
            stream.write_all(&ultimatum()).map_err(|e| err("fin", e))?;
        }
        Script::Logoff => {
            send(
                &mut stream,
                io,
                error_info(ProtocolIndependentCode::LogoffByUser),
            )?;
            stream.write_all(&ultimatum()).map_err(|e| err("fin", e))?;
        }
        Script::ServerError => {
            send(
                &mut stream,
                io,
                error_info(ProtocolIndependentCode::OutOfMemory),
            )?;
            stream.write_all(&ultimatum()).map_err(|e| err("fin", e))?;
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    Ok(())
}
