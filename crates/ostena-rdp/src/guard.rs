//! The sequence guard (ADR-0019 section 4): checks, and rewrites where the
//! connector gives no setting, the PDUs of the connection sequence that
//! carry security decisions.
//!
//! - **X.224 Connection Request** (sent): only `PROTOCOL_HYBRID` and
//!   `PROTOCOL_HYBRID_EX` (no standard RDP security, no TLS alone), no
//!   `mstshash` cookie (the account never travels in clear), and the
//!   `RESTRICTED_ADMIN_MODE_REQUIRED` flag in Restricted Admin.
//! - **X.224 Connection Confirm** (received): the target selected NLA, and
//!   announces `RESTRICTED_ADMIN_MODE_SUPPORTED` when it is required;
//!   otherwise the connection stops before CredSSP, with no fallback to a
//!   delegation of the password.
//! - **MCS Connect Initial** (sent): the `earlyCapabilityFlags` of the
//!   `TS_UD_CS_CORE` block are compared with a closed table « flag →
//!   module that handles it »; any other flag is removed before sending.

use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::gcc::{ClientEarlyCapabilityFlags, ConferenceCreateRequest};
use ironrdp_pdu::mcs::ConnectInitial;
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, FailureCode, RequestFlags, ResponseFlags,
    SecurityProtocol,
};
use ironrdp_pdu::x224::{X224, X224Data};

use crate::error::RdpError;

/// The `earlyCapabilityFlags` the agent may announce, each with the module
/// that honours it (REG-RDP-03: a flag announced without its module makes
/// the target wait for an answer that never comes).
pub const EARLY_CAPABILITIES: &[(ClientEarlyCapabilityFlags, &str)] = &[
    (
        ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU,
        "session::error_info",
    ),
    (
        ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE,
        "connect::config (LAN)",
    ),
    (
        ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT,
        "session::autodetect",
    ),
    (
        ClientEarlyCapabilityFlags::STRONG_ASYMMETRIC_KEYS,
        "ironrdp-pdu (licences)",
    ),
    (
        ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
        "ironrdp-connector (channel join)",
    ),
    (
        ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU,
        "session::monitor_layout",
    ),
];

/// The flags of [`EARLY_CAPABILITIES`].
pub fn allowed_early_capabilities() -> ClientEarlyCapabilityFlags {
    EARLY_CAPABILITIES
        .iter()
        .fold(ClientEarlyCapabilityFlags::empty(), |acc, (flag, _)| {
            acc | *flag
        })
}

/// The only security protocols the agent offers.
pub fn nla_protocols() -> SecurityProtocol {
    SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
}

fn protocol(context: &str, e: impl std::fmt::Display) -> RdpError {
    RdpError::Protocol(format!("{context} : {e}"))
}

/// Rewrites the X.224 Connection Request built by the connector.
///
/// # Errors
///
/// [`RdpError::Protocol`] if the bytes are not a Connection Request (a bug
/// of the connector, never data from the target).
pub fn rewrite_connection_request(
    sent: &[u8],
    restricted_admin: bool,
) -> Result<Vec<u8>, RdpError> {
    let X224(mut request) = decode::<X224<ConnectionRequest>>(sent)
        .map_err(|e| protocol("requête X.224 du connecteur", e))?;
    request.nego_data = None;
    request.correlation_info = None;
    request.protocol = nla_protocols();
    request.flags = if restricted_admin {
        RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED
    } else {
        RequestFlags::empty()
    };
    encode_vec(&X224(request)).map_err(|e| protocol("requête X.224", e))
}

/// What the target confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmed {
    /// The selected security protocol (`HYBRID` or `HYBRID_EX`).
    pub protocol: SecurityProtocol,
    /// The response flags.
    pub flags: ResponseFlags,
}

/// Checks the X.224 Connection Confirm of the target.
///
/// # Errors
///
/// [`RdpError::NoNla`] if the target refuses NLA or selects another
/// protocol, [`RdpError::RestrictedAdminUnsupported`] if Restricted Admin is
/// required and not announced, [`RdpError::Protocol`] if malformed.
pub fn check_connection_confirm(
    received: &[u8],
    restricted_admin: bool,
) -> Result<Confirmed, RdpError> {
    let X224(confirm) = decode::<X224<ConnectionConfirm>>(received)
        .map_err(|e| protocol("confirmation X.224", e))?;
    match confirm {
        ConnectionConfirm::Failure { code } => Err(
            if code == FailureCode::SSL_NOT_ALLOWED_BY_SERVER
                || code == FailureCode::SSL_REQUIRED_BY_SERVER
                || code == FailureCode::SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
            {
                RdpError::NoNla
            } else {
                RdpError::Protocol(format!(
                    "négociation refusée par la cible (code {})",
                    u32::from(code)
                ))
            },
        ),
        ConnectionConfirm::Response { flags, protocol } => {
            // Exactly one of the offered protocols.
            if !(protocol == SecurityProtocol::HYBRID || protocol == SecurityProtocol::HYBRID_EX) {
                return Err(RdpError::NoNla);
            }
            if restricted_admin && !flags.contains(ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED) {
                return Err(RdpError::RestrictedAdminUnsupported);
            }
            Ok(Confirmed { protocol, flags })
        }
    }
}

/// Removes from the MCS Connect Initial built by the connector every
/// `earlyCapabilityFlags` bit outside `allowed`; returns the PDU to send and
/// the bits removed.
///
/// # Errors
///
/// [`RdpError::Protocol`] if the bytes are not a Connect Initial.
pub fn rewrite_connect_initial(
    sent: &[u8],
    allowed: ClientEarlyCapabilityFlags,
) -> Result<(Vec<u8>, ClientEarlyCapabilityFlags), RdpError> {
    let X224(data) =
        decode::<X224<X224Data<'_>>>(sent).map_err(|e| protocol("MCS du connecteur", e))?;
    let mut initial = decode::<ConnectInitial>(data.data.as_ref())
        .map_err(|e| protocol("MCS Connect Initial du connecteur", e))?;
    let mut blocks = initial.conference_create_request.into_gcc_blocks();
    let flags = blocks
        .core
        .optional_data
        .early_capability_flags
        .unwrap_or_else(ClientEarlyCapabilityFlags::empty);
    let removed = flags.difference(allowed);
    blocks.core.optional_data.early_capability_flags = Some(flags.intersection(allowed));
    initial.conference_create_request =
        ConferenceCreateRequest::new(blocks).map_err(|e| protocol("blocs GCC", e))?;
    let inner = encode_vec(&initial).map_err(|e| protocol("MCS Connect Initial", e))?;
    let pdu = X224(X224Data {
        data: std::borrow::Cow::Owned(inner),
    });
    let out = encode_vec(&pdu).map_err(|e| protocol("MCS Connect Initial", e))?;
    Ok((out, removed))
}

/// The `earlyCapabilityFlags` of a Connect Initial, for the tests and the
/// test target.
pub fn early_capabilities_of(sent: &[u8]) -> Option<ClientEarlyCapabilityFlags> {
    let X224(data) = decode::<X224<X224Data<'_>>>(sent).ok()?;
    let initial = decode::<ConnectInitial>(data.data.as_ref()).ok()?;
    initial
        .conference_create_request
        .gcc_blocks()
        .core
        .optional_data
        .early_capability_flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(flags: RequestFlags, protocol: SecurityProtocol, cookie: bool) -> Vec<u8> {
        encode_vec(&X224(ConnectionRequest {
            nego_data: cookie
                .then(|| ironrdp_pdu::nego::NegoRequestData::cookie("admin".to_owned())),
            flags,
            protocol,
            correlation_info: None,
        }))
        .unwrap()
    }

    #[test]
    fn connection_request_is_nla_only_without_cookie() {
        let sent = request(
            RequestFlags::empty(),
            SecurityProtocol::SSL | SecurityProtocol::HYBRID,
            true,
        );
        for restricted in [false, true] {
            let out = rewrite_connection_request(&sent, restricted).unwrap();
            let X224(r) = decode::<X224<ConnectionRequest>>(&out).unwrap();
            assert_eq!(r.protocol, nla_protocols());
            assert_eq!(r.nego_data, None);
            assert_eq!(
                r.flags
                    .contains(RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED),
                restricted
            );
            // The account never travels in clear.
            assert!(!out.windows(5).any(|w| w == b"admin"));
        }
    }

    fn confirm(c: ConnectionConfirm) -> Vec<u8> {
        encode_vec(&X224(c)).unwrap()
    }

    #[test]
    fn confirm_requires_nla_and_restricted_admin_when_asked() {
        let hybrid = confirm(ConnectionConfirm::Response {
            flags: ResponseFlags::EXTENDED_CLIENT_DATA_SUPPORTED,
            protocol: SecurityProtocol::HYBRID_EX,
        });
        assert!(check_connection_confirm(&hybrid, false).is_ok());
        assert_eq!(
            check_connection_confirm(&hybrid, true),
            Err(RdpError::RestrictedAdminUnsupported)
        );
        let restricted = confirm(ConnectionConfirm::Response {
            flags: ResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED,
            protocol: SecurityProtocol::HYBRID,
        });
        assert!(check_connection_confirm(&restricted, true).is_ok());
        for protocol in [SecurityProtocol::SSL, SecurityProtocol::empty()] {
            let tls = confirm(ConnectionConfirm::Response {
                flags: ResponseFlags::all(),
                protocol,
            });
            assert_eq!(check_connection_confirm(&tls, false), Err(RdpError::NoNla));
        }
        let refused = confirm(ConnectionConfirm::Failure {
            code: FailureCode::SSL_NOT_ALLOWED_BY_SERVER,
        });
        assert_eq!(
            check_connection_confirm(&refused, false),
            Err(RdpError::NoNla)
        );
        assert!(matches!(
            check_connection_confirm(b"\x03\x00", false),
            Err(RdpError::Protocol(_))
        ));
    }

    #[test]
    fn the_table_has_one_module_per_flag() {
        let mut seen = ClientEarlyCapabilityFlags::empty();
        for (flag, module) in EARLY_CAPABILITIES {
            assert_eq!(flag.bits().count_ones(), 1);
            assert!(!seen.intersects(*flag));
            assert_ne!(*module, "");
            seen |= *flag;
        }
        // Never announced at M2 (ADR-0019).
        for never in [
            ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION,
            ClientEarlyCapabilityFlags::SUPPORT_STATUS_INFO_PDU,
            ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU,
            ClientEarlyCapabilityFlags::RELATIVE_MOUSE_INPUT,
            ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL,
            ClientEarlyCapabilityFlags::SUPPORT_DYNAMIC_TIME_ZONE,
        ] {
            assert!(!allowed_early_capabilities().intersects(never));
        }
    }
}
