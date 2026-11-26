//! The active session loop, without image (ADR-0019 section 4): reads the
//! frames of the target, answers what must be answered without waiting for
//! a viewer, and tells why the session ends.
//!
//! - **Fast-path** output (image updates, pointer): counted and dropped at
//!   M2; the EGFX passthrough comes with PR 13.
//! - **Slow-path** on the I/O channel: error information
//!   (`SUPPORT_ERR_INFO_PDU`) kept as the reason of the end,
//!   deactivation-reactivation driven to its end, redirection refused.
//! - **Message channel**: continuous Auto-Detect answered at once (round
//!   trip, bandwidth start and stop, [MS-RDPBCGR] 2.2.14); an unknown
//!   request is ignored and counted, never fatal (REG-RDP-04).
//! - **Input** frames from the caller are written as they come, and touch
//!   the activity of the session (idle delay).

use std::time::Instant;

use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{ConnectionResult, MonotonicInstant, Sequence as _};
use ironrdp_core::{Decode as _, ReadCursor, WriteBuf, decode, encode_vec};
use ironrdp_pdu::mcs::{
    DisconnectProviderUltimatum, DisconnectReason, McsMessage, SendDataIndicationCtx,
};
use ironrdp_pdu::rdp::autodetect::{
    AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu,
    BW_RESULTS_CONTINUOUS, BW_START_RELIABLE_UDP, BW_STOP_RELIABLE_UDP,
};
use ironrdp_pdu::rdp::headers::{
    BasicSecurityHeader, BasicSecurityHeaderFlags, IoChannelPdu, ShareDataPdu,
};
use ironrdp_pdu::rdp::server_error_info::ServerSetErrorInfoPdu;
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, find_size};
use ostena_session::Activity;
use tokio::sync::{mpsc, watch};

use crate::error::RdpError;
use crate::transport::{MAX_PDU, Transport};

/// Error information codes that end a session normally ([MS-RDPBCGR]
/// 2.2.5.1.1): disconnection or logoff by an administrator tool, logoff by
/// the user, and the idle and logon limits of the target.
const NORMAL_END_CODES: &[u32] = &[0x0001, 0x0002, 0x0003, 0x0004, 0x000C];

/// How a session loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// The target closed the session normally (logoff, disconnection).
    Closed,
    /// The agent asked to stop.
    Stopped,
    /// The target or the transport failed.
    Failed(RdpError),
}

/// What the loop counted, for the report and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Frames received.
    pub frames: u64,
    /// Fast-path frames dropped (no image at M2).
    pub fast_path: u64,
    /// Auto-Detect requests answered or consumed.
    pub autodetect_served: u64,
    /// Auto-Detect requests not understood, ignored.
    pub autodetect_ignored: u64,
    /// Deactivation-reactivation sequences completed.
    pub reactivations: u64,
    /// Input frames written.
    pub inputs: u64,
}

/// Continuous Auto-Detect ([MS-RDPBCGR] 3.2.5.17).
#[derive(Debug, Default)]
pub struct AutoDetect {
    window: Option<(MonotonicInstant, u32)>,
}

impl AutoDetect {
    /// Counts bytes received while a bandwidth window is open.
    pub fn record(&mut self, bytes: usize) {
        if let Some((_, count)) = &mut self.window {
            *count = count.saturating_add(u32::try_from(bytes).unwrap_or(u32::MAX));
        }
    }

    /// The answer to `request`, received at `now`.
    pub fn respond(&mut self, request: &AutoDetectRequest, now: MonotonicInstant) -> Answer {
        match *request {
            AutoDetectRequest::RttRequest {
                sequence_number, ..
            } => Answer::Respond(AutoDetectResponse::RttResponse { sequence_number }),
            AutoDetectRequest::BandwidthMeasureStart {
                request_type: BW_START_RELIABLE_UDP,
                ..
            } => {
                self.window = Some((now, 0));
                Answer::Consumed
            }
            AutoDetectRequest::BandwidthMeasurePayload { .. }
            | AutoDetectRequest::NetworkCharacteristicsResult { .. } => Answer::Consumed,
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number,
                request_type: BW_STOP_RELIABLE_UDP,
                ..
            } => {
                let (delta, bytes) = self.window.take().map_or((1, 0), |(start, bytes)| {
                    let ms = now.as_millis().saturating_sub(start.as_millis());
                    (u32::try_from(ms).unwrap_or(u32::MAX).max(1), bytes)
                });
                Answer::Respond(AutoDetectResponse::BandwidthMeasureResults {
                    sequence_number,
                    response_type: BW_RESULTS_CONTINUOUS,
                    time_delta_ms: delta,
                    byte_count: bytes,
                })
            }
            _ => Answer::Unknown,
        }
    }
}

/// What [`AutoDetect::respond`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Send this response.
    Respond(AutoDetectResponse),
    /// Taken into account, nothing to send.
    Consumed,
    /// Not understood: ignored and counted.
    Unknown,
}

/// The session loop of one connection.
pub struct SessionLoop {
    transport: Transport,
    result: ConnectionResult,
    autodetect: AutoDetect,
    counters: Counters,
    origin: Instant,
    last_error: Option<u32>,
    responses: Vec<Vec<u8>>,
}

impl std::fmt::Debug for SessionLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLoop")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// What one frame asks of the loop.
enum Step {
    Continue,
    End(SessionEnd),
    Reactivate,
}

impl SessionLoop {
    /// A loop over an established connection.
    pub fn new(transport: Transport, result: ConnectionResult) -> Self {
        Self {
            transport,
            result,
            autodetect: AutoDetect::default(),
            counters: Counters::default(),
            origin: Instant::now(),
            last_error: None,
            responses: Vec::new(),
        }
    }

    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_millis(
            u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }

    /// Runs until the target ends the session, `stop` turns true, or an
    /// error. Input frames from `inputs` are written to the target.
    pub async fn run(
        mut self,
        mut inputs: mpsc::Receiver<Vec<u8>>,
        mut stop: watch::Receiver<bool>,
        activity: Option<Activity>,
    ) -> (SessionEnd, Counters) {
        let end = loop {
            match self.drain().await {
                Ok(None) => {}
                Ok(Some(end)) => break end,
                Err(e) => break SessionEnd::Failed(e),
            }
            if *stop.borrow() {
                break SessionEnd::Stopped;
            }
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break SessionEnd::Stopped;
                    }
                }
                input = inputs.recv(), if !inputs.is_closed() => {
                    if let Some(frame) = input {
                        if let Err(e) = self.transport.write_all(&frame).await {
                            break SessionEnd::Failed(e);
                        }
                        self.counters.inputs += 1;
                        if let Some(a) = &activity {
                            a.touch();
                        }
                    }
                }
                filled = self.transport.fill() => {
                    if let Err(e) = filled {
                        break match (e, self.last_error) {
                            (RdpError::Unreachable(_), None) => SessionEnd::Closed,
                            (_, Some(code)) => end_of(code),
                            (e, None) => SessionEnd::Failed(e),
                        };
                    }
                }
            }
        };
        if end == SessionEnd::Stopped {
            self.disconnect().await;
        } else {
            self.transport.close().await;
        }
        (end, self.counters)
    }

    /// Sends the MCS disconnection and closes the transport.
    async fn disconnect(&mut self) {
        let ultimatum = McsMessage::DisconnectProviderUltimatum(
            DisconnectProviderUltimatum::from_reason(DisconnectReason::UserRequested),
        );
        if let Ok(bytes) = encode_vec(&X224(ultimatum)) {
            let _ = self.transport.write_all(&bytes).await;
        }
        self.transport.close().await;
    }

    /// Handles every complete frame pending.
    async fn drain(&mut self) -> Result<Option<SessionEnd>, RdpError> {
        while let Some(frame) = self.next_frame()? {
            match self.process(&frame)? {
                Step::Continue => {}
                Step::End(end) => return Ok(Some(end)),
                Step::Reactivate => self.reactivate().await?,
            }
            for response in std::mem::take(&mut self.responses) {
                self.transport.write_all(&response).await?;
            }
        }
        Ok(None)
    }

    /// The next complete slow-path frame; fast-path frames are counted and
    /// dropped on the way.
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, RdpError> {
        loop {
            let Some(info) = find_size(self.transport.pending())
                .map_err(|e| RdpError::Protocol(format!("trame : {e}")))?
            else {
                return Ok(None);
            };
            if info.length == 0 || info.length > MAX_PDU {
                return Err(RdpError::Protocol(format!(
                    "taille de trame {} hors bornes",
                    info.length
                )));
            }
            if self.transport.pending().len() < info.length {
                return Ok(None);
            }
            let frame = self.transport.consume(info.length);
            self.counters.frames += 1;
            self.autodetect.record(frame.len());
            if info.action == Action::X224 {
                return Ok(Some(frame));
            }
            self.counters.fast_path += 1;
        }
    }

    /// Handles one slow-path frame; answers go to `self.responses`.
    fn process(&mut self, frame: &[u8]) -> Result<Step, RdpError> {
        let data = match ironrdp_pdu::mcs::decode_send_data_indication(frame) {
            Ok(data) => data,
            Err(error) => {
                return match decode::<X224<McsMessage<'_>>>(frame) {
                    Ok(X224(McsMessage::DisconnectProviderUltimatum(_))) => Ok(Step::End(
                        self.last_error.map_or(SessionEnd::Closed, end_of),
                    )),
                    _ => Err(RdpError::Protocol(format!("trame X.224 : {error}"))),
                };
            }
        };
        if data.channel_id == self.result.io_channel_id {
            self.process_io(data)
        } else if Some(data.channel_id) == self.result.message_channel_id {
            self.process_message(data)?;
            Ok(Step::Continue)
        } else {
            // No static channel is joined at M2.
            tracing::debug!(
                channel = data.channel_id,
                "données d'un canal non joint ignorées"
            );
            Ok(Step::Continue)
        }
    }

    fn process_io(&mut self, data: SendDataIndicationCtx<'_>) -> Result<Step, RdpError> {
        for part in share_control_parts(data.user_data)? {
            let ctx = SendDataIndicationCtx {
                initiator_id: data.initiator_id,
                channel_id: data.channel_id,
                user_data: part,
            };
            let pdu = ironrdp_pdu::rdp::headers::decode_io_channel(ctx)
                .map_err(|e| RdpError::Protocol(format!("canal d'E/S : {e}")))?;
            match pdu {
                IoChannelPdu::Data(share) => match share.pdu {
                    ShareDataPdu::ServerSetErrorInfo(info) => {
                        let code = error_code(&info);
                        if code != 0 {
                            self.last_error = Some(code);
                        }
                    }
                    ShareDataPdu::ShutdownDenied => return Ok(Step::End(SessionEnd::Closed)),
                    _ => {}
                },
                IoChannelPdu::DeactivateAll(_) => return Ok(Step::Reactivate),
                IoChannelPdu::ServerRedirection(r) if !r.is_informational() => {
                    return Ok(Step::End(SessionEnd::Failed(RdpError::Redirected)));
                }
                IoChannelPdu::ServerRedirection(_) | IoChannelPdu::MultitransportRequest(_) => {}
            }
        }
        Ok(Step::Continue)
    }

    fn process_message(&mut self, data: SendDataIndicationCtx<'_>) -> Result<(), RdpError> {
        let mut peek = ReadCursor::new(data.user_data);
        let header = BasicSecurityHeader::decode(&mut peek)
            .map_err(|e| RdpError::Protocol(format!("canal de messages : {e}")))?;
        let flags = header.flags.difference(
            BasicSecurityHeaderFlags::RESET_SEQNO | BasicSecurityHeaderFlags::IGNORE_SEQNO,
        );
        if flags != BasicSecurityHeaderFlags::AUTODETECT_REQ {
            // Heartbeat (not announced), multitransport (declined): ignored.
            return Ok(());
        }
        let Ok(request) = decode::<AutoDetectReqPdu>(data.user_data) else {
            self.counters.autodetect_ignored += 1;
            return Ok(());
        };
        let now = self.now();
        match self.autodetect.respond(&request.request, now) {
            Answer::Unknown => {
                self.counters.autodetect_ignored += 1;
                tracing::debug!("demande Auto-Detect inconnue ignorée");
            }
            Answer::Consumed => self.counters.autodetect_served += 1,
            Answer::Respond(response) => {
                self.counters.autodetect_served += 1;
                let Some(channel) = self.result.message_channel_id else {
                    return Ok(());
                };
                let mut out = WriteBuf::new();
                ironrdp_pdu::mcs::encode_send_data_request(
                    self.result.user_channel_id,
                    channel,
                    &AutoDetectRspPdu::new(response),
                    &mut out,
                )
                .map_err(|e| RdpError::Protocol(format!("réponse Auto-Detect : {e}")))?;
                self.responses.push(out.into_inner());
            }
        }
        Ok(())
    }

    /// Reads the next PDU matching `hint` (reactivation).
    async fn read_hinted(&mut self, hint: &dyn ironrdp_pdu::PduHint) -> Result<Vec<u8>, RdpError> {
        loop {
            match hint
                .find_size(self.transport.pending())
                .map_err(|e| RdpError::Protocol(format!("trame : {e}")))?
            {
                Some((_, 0)) => return Err(RdpError::Protocol("trame de taille nulle".into())),
                Some((_, n)) if n > MAX_PDU => {
                    return Err(RdpError::Protocol("trame hors bornes".into()));
                }
                Some((matched, n)) if self.transport.pending().len() >= n => {
                    let pdu = self.transport.consume(n);
                    if matched {
                        return Ok(pdu);
                    }
                }
                _ => self.transport.fill().await?,
            }
        }
    }

    /// Drives a deactivation-reactivation sequence to its end.
    async fn reactivate(&mut self) -> Result<(), RdpError> {
        let mut sequence = self.result.activation_factory.create();
        let mut out = WriteBuf::new();
        for _ in 0..64 {
            if let ConnectionActivationState::Finalized {
                desktop_size,
                share_id,
                ..
            } = sequence.connection_activation_state()
            {
                self.result.desktop_size = desktop_size;
                self.result.share_id = share_id;
                self.counters.reactivations += 1;
                return Ok(());
            }
            out.clear();
            let written = if let Some(hint) = sequence.next_pdu_hint() {
                let pdu = self.read_hinted(hint).await?;
                sequence.step(&pdu, Some(self.now()), &mut out)
            } else {
                sequence.step_no_input(&mut out)
            }
            .map_err(|e| RdpError::Protocol(format!("réactivation : {}", e.report())))?;
            if written.size().is_some() {
                self.transport.write_all(out.filled()).await?;
            }
        }
        Err(RdpError::Protocol("réactivation sans fin".into()))
    }
}

/// Share Control PDUs may be concatenated in one indication ([MS-RDPBCGR]
/// 2.2.8.1.1.1.1): splits them by their total length, unless the first one
/// is not a Share Control PDU (basic security header).
fn share_control_parts(bytes: &[u8]) -> Result<Vec<&[u8]>, RdpError> {
    let mut parts = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let length = bytes
            .get(offset..offset + 2)
            .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])));
        if length == 0 || offset + length > bytes.len() {
            if offset == 0 {
                parts.push(bytes);
                break;
            }
            return Err(RdpError::Protocol(
                "PDU de contrôle concaténées invalides".into(),
            ));
        }
        parts.push(&bytes[offset..offset + length]);
        offset += length;
    }
    Ok(parts)
}

/// The raw code of an error information PDU.
fn error_code(info: &ServerSetErrorInfoPdu) -> u32 {
    encode_vec(info)
        .ok()
        .and_then(|b| {
            b.get(..4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        })
        .unwrap_or(u32::MAX)
}

/// The end of a session whose target sent error information `code`.
fn end_of(code: u32) -> SessionEnd {
    if NORMAL_END_CODES.contains(&code) {
        SessionEnd::Closed
    } else {
        SessionEnd::Failed(RdpError::ServerError(code))
    }
}
