//! The target profile (REG-PERF-01, ADR-0019 section 4) and the RDS
//! licence cache (REG-RDP-06).
//!
//! After each successful session the agent returns a **profile** of the
//! target in its report to the core, which keeps it in the inventory and
//! sends it back in `session_params`. At the next session the agent asks
//! only for the channels the grant allows and the target accepted, and
//! compares what it sees with the profile: a difference (an updated target)
//! is logged (`rdp.profile_changed`) and replaces the old profile, never an
//! error. The profile is an optimisation: absent or wrong, it slows the
//! connection, it never authorises anything.
//!
//! The **licence** issued by the target is kept by the core, per agent and
//! target, and presented at the next session, with a client name and a
//! hardware identifier derived from the agent and the target (HMAC under a
//! key of the agent), so that a per-device licence is not consumed at each
//! session and the identifier of the agent is not revealed.

use std::sync::{Arc, Mutex, PoisonError};

use ironrdp_connector::{ConnectorResult, LicenseCache};
use ironrdp_core::decode;
use ironrdp_pdu::mcs::ConnectResponse;
use ironrdp_pdu::rdp::server_license::LicenseInformation;
use ironrdp_pdu::x224::{X224, X224Data};
use serde::{Deserialize, Serialize};

/// What the agent remembers of a target between sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    /// RDP version of the server core data.
    pub rdp_version: u32,
    /// Security protocol selected (X.224 confirm).
    pub security_protocol: u32,
    /// Response flags of the X.224 confirm.
    pub response_flags: u8,
    /// Early capability flags of the server.
    pub server_early_capabilities: u32,
    /// Static channels accepted, with their MCS identifiers, in order.
    pub static_channels: Vec<(String, u16)>,
    /// The server can skip the channel join.
    pub skip_channel_join: bool,
    /// MCS message channel offered (Auto-Detect, heartbeat).
    pub message_channel: bool,
    /// SHA-256 of the target certificate seen, in hexadecimal.
    pub certificate: String,
}

impl TargetProfile {
    /// The fields that differ from `other`, for `rdp.profile_changed`.
    pub fn differences(&self, other: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.rdp_version != other.rdp_version {
            out.push("rdp_version");
        }
        if self.security_protocol != other.security_protocol {
            out.push("security_protocol");
        }
        if self.response_flags != other.response_flags {
            out.push("response_flags");
        }
        if self.server_early_capabilities != other.server_early_capabilities {
            out.push("server_early_capabilities");
        }
        if self.static_channels != other.static_channels {
            out.push("static_channels");
        }
        if self.skip_channel_join != other.skip_channel_join {
            out.push("skip_channel_join");
        }
        if self.message_channel != other.message_channel {
            out.push("message_channel");
        }
        if self.certificate != other.certificate {
            out.push("certificate");
        }
        out
    }

    /// Of the channels `wanted` (allowed by the grant), those to request:
    /// all of them without a profile, else those the target accepted.
    pub fn channels_to_request<'a>(profile: Option<&Self>, wanted: &[&'a str]) -> Vec<&'a str> {
        match profile {
            None => wanted.to_vec(),
            Some(p) => wanted
                .iter()
                .copied()
                .filter(|w| p.static_channels.iter().any(|(name, _)| name == w))
                .collect(),
        }
    }
}

/// What the MCS Connect Response of the server tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettings {
    /// RDP version.
    pub rdp_version: u32,
    /// Early capability flags.
    pub early_capabilities: u32,
    /// Static channel identifiers, in the order requested.
    pub channel_ids: Vec<u16>,
    /// Message channel offered.
    pub message_channel: bool,
}

/// Decodes an MCS Connect Response (an X.224 data PDU), if it is one.
pub fn server_settings(pdu: &[u8]) -> Option<ServerSettings> {
    let X224(data) = decode::<X224<X224Data<'_>>>(pdu).ok()?;
    let response = decode::<ConnectResponse>(data.data.as_ref()).ok()?;
    let blocks = response.conference_create_response.into_gcc_blocks();
    Some(ServerSettings {
        rdp_version: u32::from(blocks.core.version),
        early_capabilities: blocks
            .core
            .optional_data
            .early_capability_flags
            .map_or(0, |f| f.bits()),
        channel_ids: blocks.network.channel_ids,
        message_channel: blocks.message_channel.is_some(),
    })
}

/// An RDS licence kept by the core for one agent and target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredLicense {
    /// Licence version.
    pub version: u32,
    /// Scope (licence server).
    pub scope: String,
    /// Company name.
    pub company_name: String,
    /// Product identifier.
    pub product_id: String,
    /// The licence blob, hexadecimal.
    pub license: String,
}

/// The licence cache of one connection: presents the stored licence,
/// captures a new one for the report.
#[derive(Debug, Default)]
pub struct Licenses {
    stored: Option<StoredLicense>,
    issued: Mutex<Option<StoredLicense>>,
}

impl Licenses {
    /// A cache presenting `stored`.
    pub fn new(stored: Option<StoredLicense>) -> Arc<Self> {
        Arc::new(Self {
            stored,
            issued: Mutex::new(None),
        })
    }

    /// The licence issued by the target during this connection, if any.
    pub fn issued(&self) -> Option<StoredLicense> {
        self.issued
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether a stored licence was offered.
    pub fn has_stored(&self) -> bool {
        self.stored.is_some()
    }
}

impl std::panic::RefUnwindSafe for Licenses {}

impl LicenseCache for Licenses {
    fn get_license(&self, info: LicenseInformation) -> ConnectorResult<Option<Vec<u8>>> {
        Ok(self.stored.as_ref().and_then(|s| {
            (s.scope == info.scope
                && s.company_name == info.company_name
                && s.product_id == info.product_id)
                .then(|| from_hex(&s.license))
                .flatten()
        }))
    }

    fn store_license(&self, info: LicenseInformation) -> ConnectorResult<()> {
        *self.issued.lock().unwrap_or_else(PoisonError::into_inner) = Some(StoredLicense {
            version: info.version,
            scope: info.scope,
            company_name: info.company_name,
            product_id: info.product_id,
            license: to_hex(&info.license_info),
        });
        Ok(())
    }
}

/// Lower-case hexadecimal.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Parses hexadecimal; `None` if invalid.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The client name and hardware identifier presented to `target`: stable
/// for one agent and one target, revealing neither (HMAC-SHA-256 under the
/// key of the agent; ADR-0019).
pub fn client_identity(key: &ostena_crypto::hmac::HmacKey, target: &str) -> (String, [u32; 4]) {
    let mac = key.tag(&[b"ostena-rdp-client\0", target.as_bytes()]);
    let name = format!("OST-{}", to_hex(&mac[..5]).to_uppercase());
    let word = |i: usize| u32::from_le_bytes([mac[i], mac[i + 1], mac[i + 2], mac[i + 3]]);
    (name, [word(8), word(12), word(16), word(20)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(blob: &[u8]) -> LicenseInformation {
        LicenseInformation {
            version: 0x0006_0000,
            scope: "srv".into(),
            company_name: "co".into(),
            product_id: "A02".into(),
            license_info: blob.to_vec(),
        }
    }

    #[test]
    fn issued_licence_is_captured_then_presented() {
        let first = Licenses::new(None);
        assert_eq!(first.get_license(info(b"")).unwrap(), None);
        first.store_license(info(b"\x01\x02licence")).unwrap();
        let stored = first.issued().unwrap();
        let second = Licenses::new(Some(stored));
        assert_eq!(
            second.get_license(info(b"")).unwrap().unwrap(),
            b"\x01\x02licence"
        );
        // Another licence server: not presented.
        let mut other = info(b"");
        other.scope = "other".into();
        assert_eq!(second.get_license(other).unwrap(), None);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(from_hex(&to_hex(b"\x00\xffab")).unwrap(), b"\x00\xffab");
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn client_identity_is_stable_per_target_and_hides_the_agent() {
        let key =
            ostena_crypto::hmac::HmacKey::new(&ostena_crypto::hmac::HmacKey::generate().unwrap())
                .unwrap();
        let a = client_identity(&key, "srv01.example.test");
        assert_eq!(a, client_identity(&key, "srv01.example.test"));
        assert_ne!(a, client_identity(&key, "srv02.example.test"));
        assert!(a.0.len() <= 15, "NetBIOS name limit");
        let other =
            ostena_crypto::hmac::HmacKey::new(&ostena_crypto::hmac::HmacKey::generate().unwrap())
                .unwrap();
        assert_ne!(a, client_identity(&other, "srv01.example.test"));
    }

    #[test]
    fn profile_differences_and_channels() {
        let p = TargetProfile {
            rdp_version: 0x0008_0004,
            static_channels: vec![("drdynvc".into(), 1004)],
            ..TargetProfile::default()
        };
        let mut q = p.clone();
        assert_eq!(p.differences(&q), Vec::<&str>::new());
        q.rdp_version = 0x0008_0010;
        q.certificate = "ab".into();
        assert_eq!(p.differences(&q), ["rdp_version", "certificate"]);
        assert_eq!(
            TargetProfile::channels_to_request(Some(&p), &["drdynvc", "cliprdr"]),
            ["drdynvc"]
        );
        assert_eq!(
            TargetProfile::channels_to_request(None, &["drdynvc", "cliprdr"]),
            ["drdynvc", "cliprdr"]
        );
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<TargetProfile>(&json).unwrap(), p);
    }
}
