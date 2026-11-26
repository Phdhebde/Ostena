//! CredSSP driven by the agent (ADR-0019 section 2), on
//! `sspi::credssp::CredSspClient` rather than the sequence of the connector,
//! which lets SPNEGO fall back to NTLM and cannot ask for Restricted Admin.
//!
//! - **Kerberos is the rule**: SPNEGO with `kerberos,!ntlm`, the KDC always
//!   given (never discovered), reached over TCP at its pinned addresses only.
//! - **NTLM** only when the policy admits it (Restricted Admin with
//!   `ntlm_fallback`, ADR-0009): every outgoing token is inspected, and an
//!   NTLM message where NTLM is not admitted stops the exchange before it is
//!   sent (`RDP-E011`), whatever SPNEGO decided.
//! - **CredSSP version 6** required from the target (`RDP-E007`).
//! - **Early User Authorization Result** read in `HYBRID_EX` (`RDP-E009`).

use std::time::Duration;

use ostena_scope::PinnedTarget;
use sspi::credssp::{
    ClientMode, ClientState, CredSspClient, CredSspMode, EarlyUserAuthResult, TsRequest,
};
use sspi::generator::GeneratorState;
use sspi::{AuthIdentity, Credentials, KerberosConfig, NegotiateConfig, NetworkRequest, Username};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::error::RdpError;
use crate::transport::{Transport, read_pdu};

/// Largest `TSRequest` accepted from the target.
pub const MAX_TS_REQUEST: usize = 64 * 1024;
/// Largest answer accepted from a KDC.
pub const MAX_KDC_ANSWER: usize = 64 * 1024;
/// Delay of one KDC exchange.
pub const KDC_TIMEOUT: Duration = Duration::from_secs(5);
/// CredSSP version required from the target ([MS-CSSP], CVE-2018-0886).
pub const MIN_CREDSSP_VERSION: u32 = 6;
/// Rounds of the exchange before giving up (Kerberos takes 2, NTLM 3).
const MAX_ROUNDS: usize = 8;

/// The signature of every NTLM message ([MS-NLMP] 2.2.1).
const NTLMSSP: &[u8] = b"NTLMSSP\0";

/// The KDCs of the realm of the account, configured and pinned by the scope
/// control (ADR-0005): never discovered.
#[derive(Debug, Clone)]
pub struct Kdcs {
    /// Realm, in upper case.
    pub realm: String,
    /// `(name, pinned addresses)`, in order of preference.
    pub servers: Vec<(String, PinnedTarget)>,
}

/// What may authenticate the account.
#[derive(Debug, Clone)]
pub enum Mechanism {
    /// Kerberos only (`kerberos,!ntlm`).
    Kerberos(Kdcs),
    /// Kerberos, then NTLM if the target cannot do Kerberos (Restricted
    /// Admin with `ntlm_fallback` only).
    KerberosThenNtlm(Kdcs),
    /// NTLM only: a target known by its address, Restricted Admin with
    /// `ntlm_fallback` only.
    Ntlm,
}

impl Mechanism {
    fn ntlm_admitted(&self) -> bool {
        !matches!(self, Self::Kerberos(_))
    }

    fn kdcs(&self) -> Option<&Kdcs> {
        match self {
            Self::Kerberos(k) | Self::KerberosThenNtlm(k) => Some(k),
            Self::Ntlm => None,
        }
    }
}

/// One CredSSP authentication.
pub struct Authentication {
    /// `user`, `DOMAIN\user` or `user@realm`.
    pub username: String,
    /// The password, read from the agent store, wiped with this value.
    pub password: ostena_common::secret::SecretString,
    /// `TERMSRV/<DNS name of the target>`.
    pub spn: String,
    /// What may authenticate.
    pub mechanism: Mechanism,
    /// Restricted Admin (`CredentialLess`) or delegation (`WithCredentials`).
    pub restricted_admin: bool,
    /// Name of the agent as a workstation.
    pub workstation: String,
}

impl std::fmt::Debug for Authentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authentication")
            .field("username", &self.username)
            .field("spn", &self.spn)
            .field("mechanism", &self.mechanism)
            .field("restricted_admin", &self.restricted_admin)
            .finish_non_exhaustive()
    }
}

/// How the exchange went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outcome {
    /// NTLM was used (event `rdp.ntlm_used`).
    pub ntlm_used: bool,
    /// Round trips with the target.
    pub rounds: u32,
    /// Exchanges with a KDC.
    pub kdc_exchanges: u32,
}

/// Whether a token carries an NTLM message (raw or inside SPNEGO).
pub fn carries_ntlm(token: &[u8]) -> bool {
    token.windows(NTLMSSP.len()).any(|w| w == NTLMSSP)
}

fn auth_error(e: &sspi::Error) -> RdpError {
    use sspi::ErrorKind as K;
    match e.error_type {
        K::NoAuthenticatingAuthority
        | K::TimeSkew
        | K::KdcInvalidRequest
        | K::UnknownCredentials => RdpError::Kerberos(e.description.clone()),
        _ => RdpError::Authentication(e.description.clone()),
    }
}

fn credentials(auth: &Authentication) -> Result<Credentials, RdpError> {
    let username = Username::parse(&auth.username)
        .map_err(|e| RdpError::Params(format!("nom de compte : {e}")))?;
    // SECRET-EXPOSURE: the password goes to sspi only, in its own Secret.
    #[expect(clippy::disallowed_methods)]
    let password = auth.password.expose_secret().to_owned();
    Ok(Credentials::AuthIdentity(AuthIdentity {
        username,
        password: sspi::Secret::new(password),
    }))
}

fn client_mode(auth: &Authentication) -> Result<ClientMode, RdpError> {
    let (protocol_config, packages): (Box<dyn sspi::negotiate::ProtocolConfig>, &str) =
        match &auth.mechanism {
            Mechanism::Kerberos(kdcs) => (Box::new(kerberos_config(kdcs, auth)?), "kerberos,!ntlm"),
            Mechanism::KerberosThenNtlm(kdcs) => {
                (Box::new(kerberos_config(kdcs, auth)?), "kerberos,ntlm")
            }
            Mechanism::Ntlm => (
                Box::new(sspi::ntlm::NtlmConfig {
                    client_computer_name: Some(auth.workstation.clone()),
                }),
                "!kerberos,ntlm",
            ),
        };
    Ok(ClientMode::Negotiate(NegotiateConfig {
        protocol_config,
        package_list: Some(packages.to_owned()),
        client_computer_name: auth.workstation.clone(),
    }))
}

fn kerberos_config(kdcs: &Kdcs, auth: &Authentication) -> Result<KerberosConfig, RdpError> {
    let (name, _) = kdcs
        .servers
        .first()
        .ok_or_else(|| RdpError::Kerberos(format!("aucun KDC configuré pour {}", kdcs.realm)))?;
    let url = url::Url::parse(&format!("tcp://{name}:88"))
        .map_err(|e| RdpError::Params(format!("nom de KDC « {name} » : {e}")))?;
    Ok(KerberosConfig {
        kdc_url: Some(url),
        client_computer_name: auth.workstation.clone(),
    })
}

/// Runs CredSSP over the TLS of `transport`, binding the verified
/// `public_key` of the target (`subjectPublicKey`).
///
/// # Errors
///
/// The `RDP-E0xx` of the failure: `RDP-E005` refused, `RDP-E006` Kerberos,
/// `RDP-E007` version, `RDP-E009` early refusal, `RDP-E011` NTLM refused,
/// `RDP-E012` malformed exchange.
pub async fn authenticate(
    transport: &mut Transport,
    auth: &Authentication,
    public_key: Vec<u8>,
    early_user_auth: bool,
) -> Result<Outcome, RdpError> {
    let mode = if auth.restricted_admin {
        CredSspMode::CredentialLess
    } else {
        CredSspMode::WithCredentials
    };
    let mut client = CredSspClient::new(
        public_key,
        credentials(auth)?,
        mode,
        client_mode(auth)?,
        auth.spn.clone(),
    )
    .map_err(|e| auth_error(&e))?;
    let mut outcome = Outcome::default();
    let mut request = TsRequest::default();
    for _ in 0..MAX_ROUNDS {
        let state = drive(&mut client, request, &auth.mechanism, &mut outcome).await?;
        let (to_send, last) = match state {
            ClientState::ReplyNeeded(r) => (r, false),
            ClientState::FinalMessage(r) => (r, true),
        };
        if let Some(token) = &to_send.nego_tokens
            && carries_ntlm(token)
        {
            if !auth.mechanism.ntlm_admitted() {
                return Err(RdpError::NtlmRefused(
                    "jeton NTLM produit alors que seul Kerberos est admis",
                ));
            }
            outcome.ntlm_used = true;
        }
        let mut bytes = Vec::new();
        to_send
            .encode_ts_request(&mut bytes)
            .map_err(|e| RdpError::Protocol(format!("TSRequest : {e}")))?;
        transport.write_all(&bytes).await?;
        outcome.rounds += 1;
        if last {
            if early_user_auth {
                let result = read_pdu(transport, 4, |b| Ok((b.len() >= 4).then_some(4))).await?;
                match EarlyUserAuthResult::from_buffer(result.as_slice()) {
                    Ok(EarlyUserAuthResult::Success) => {}
                    Ok(EarlyUserAuthResult::AccessDenied) => return Err(RdpError::AccessDenied),
                    Err(e) => {
                        return Err(RdpError::Protocol(format!("résultat d'autorisation : {e}")));
                    }
                }
            }
            return Ok(outcome);
        }
        request = read_ts_request(transport).await?;
    }
    Err(RdpError::Protocol("échange CredSSP sans fin".into()))
}

/// Reads and checks one `TSRequest` of the target.
async fn read_ts_request(transport: &mut Transport) -> Result<TsRequest, RdpError> {
    let bytes = read_pdu(transport, MAX_TS_REQUEST, ts_request_size).await?;
    let request = TsRequest::from_buffer(&bytes)
        .map_err(|e| RdpError::Protocol(format!("TSRequest de la cible : {e}")))?;
    if request.version < MIN_CREDSSP_VERSION {
        return Err(RdpError::CredSspVersion(request.version));
    }
    if let Some(token) = &request.nego_tokens
        && carries_ntlm(token)
    {
        // The target speaks NTLM: the checks on the next outgoing token
        // decide, this only records it.
        tracing::debug!(event = "rdp.credssp_ntlm_offered", "la cible propose NTLM");
    }
    request
        .check_error()
        .map_err(|e| RdpError::Authentication(e.description))?;
    Ok(request)
}

/// The size of the `TSRequest` at the start of `bytes`, if known.
///
/// # Errors
///
/// [`RdpError::Protocol`] if the DER header is invalid.
pub fn ts_request_size(bytes: &[u8]) -> Result<Option<usize>, RdpError> {
    match TsRequest::read_length(bytes) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(RdpError::Protocol(format!("TSRequest : {e}"))),
    }
}

/// Runs one step of the client, serving its requests to the KDC.
async fn drive(
    client: &mut CredSspClient,
    request: TsRequest,
    mechanism: &Mechanism,
    outcome: &mut Outcome,
) -> Result<ClientState, RdpError> {
    let mut generator = client.process(request);
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Completed(result) => return result.map_err(|e| auth_error(&e)),
            GeneratorState::Suspended(request) => {
                let answer = match mechanism.kdcs() {
                    Some(kdcs) => {
                        outcome.kdc_exchanges += 1;
                        exchange_with_kdc(kdcs, &request).await
                    }
                    None => Err(RdpError::Kerberos("aucun KDC pour cette cible".into())),
                };
                let answer = answer.map_err(|e| {
                    sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, e.to_string())
                });
                state = generator.resume(answer);
            }
        }
    }
}

/// Carries one Kerberos request to a configured KDC, over TCP only, at its
/// pinned addresses (RFC 4120 section 7.2.2: four-byte length, then the
/// message; the request already starts with its length).
///
/// # Errors
///
/// [`RdpError::Kerberos`]: the KDC named is not configured, the transport is
/// not TCP, no address answers in time, or the answer is out of bounds.
pub async fn exchange_with_kdc(kdcs: &Kdcs, request: &NetworkRequest) -> Result<Vec<u8>, RdpError> {
    if request.protocol != sspi::NetworkProtocol::Tcp {
        return Err(RdpError::Kerberos(
            "transport KDC autre que TCP refusé".into(),
        ));
    }
    let host = request.url.host_str().unwrap_or_default();
    let Some((_, pinned)) = kdcs
        .servers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(host))
    else {
        // A referral to another realm, or a discovered KDC: refused.
        return Err(RdpError::Kerberos(format!("KDC « {host} » non configuré")));
    };
    let mut last = RdpError::Kerberos("KDC injoignable".into());
    for addr in pinned.addrs() {
        match tokio::time::timeout(KDC_TIMEOUT, kdc_round_trip(*addr, &request.data)).await {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(e)) => last = e,
            Err(_) => last = RdpError::Kerberos(format!("KDC {addr} : délai dépassé")),
        }
    }
    Err(last)
}

async fn kdc_round_trip(addr: std::net::SocketAddr, data: &[u8]) -> Result<Vec<u8>, RdpError> {
    let e =
        |what: &str, e: std::io::Error| RdpError::Kerberos(format!("KDC {addr} : {what} : {e}"));
    let mut tcp = TcpStream::connect(addr)
        .await
        .map_err(|x| e("connexion", x))?;
    tcp.write_all(data).await.map_err(|x| e("envoi", x))?;
    let mut len = [0u8; 4];
    tcp.read_exact(&mut len)
        .await
        .map_err(|x| e("réponse", x))?;
    let n = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if n == 0 || n > MAX_KDC_ANSWER {
        return Err(RdpError::Kerberos(format!(
            "KDC {addr} : réponse de {n} octets hors bornes"
        )));
    }
    let mut answer = vec![0u8; 4 + n];
    answer[..4].copy_from_slice(&len);
    tcp.read_exact(&mut answer[4..])
        .await
        .map_err(|x| e("réponse", x))?;
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlm_messages_are_seen_raw_and_wrapped() {
        assert!(carries_ntlm(b"NTLMSSP\0\x01\x00\x00\x00"));
        let mut spnego = vec![0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        spnego.extend_from_slice(b"\xa0\x3e\x30\x3c\xa2\x3a\x04\x38NTLMSSP\0\x01");
        assert!(carries_ntlm(&spnego));
        assert!(!carries_ntlm(b"\x60\x82\x01\x00kerberos"));
        assert!(!carries_ntlm(b""));
    }

    #[test]
    fn ts_request_size_needs_the_header() {
        assert_eq!(ts_request_size(&[]).unwrap(), None);
        assert_eq!(ts_request_size(&[0x30]).unwrap(), None);
        assert_eq!(ts_request_size(&[0x30, 0x03, 1, 2, 3]).unwrap(), Some(5));
    }
}
