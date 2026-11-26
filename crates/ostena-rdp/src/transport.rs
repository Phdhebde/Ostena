//! The byte transport to the target: TCP, then the TLS built by
//! `ostena-crypto` (never by IronRDP), and the framing of RDP PDUs.

use std::io::{self, Read as _, Write as _};
use std::sync::Arc;

use ostena_crypto::tls::target::{TargetCheck, is_pin_mismatch};
use ostena_crypto::tls::{ClientConfig, ClientConnection, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::error::RdpError;

/// Largest PDU accepted from the target (a TPKT or fast-path length fits in
/// 16 bits; a TSRequest or a KDC answer is bounded separately).
pub const MAX_PDU: usize = 64 * 1024;

/// Read chunk.
const CHUNK: usize = 16 * 1024;

/// TCP before TLS, then TLS.
pub struct Transport {
    tcp: TcpStream,
    tls: Option<ClientConnection>,
    /// Plain bytes received and not consumed yet.
    pending: Vec<u8>,
    /// Bytes received from the target since the last [`Transport::take_received`].
    received: u64,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("tls", &self.tls.is_some())
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

fn io_error(e: &io::Error) -> RdpError {
    RdpError::Unreachable(e.kind().to_string())
}

impl Transport {
    /// Wraps a connected TCP stream.
    pub fn new(tcp: TcpStream) -> Self {
        let _ = tcp.set_nodelay(true);
        Self {
            tcp,
            tls: None,
            pending: Vec::new(),
            received: 0,
        }
    }

    /// Bytes received since the last call (Auto-Detect bandwidth).
    pub fn take_received(&mut self) -> u64 {
        std::mem::take(&mut self.received)
    }

    /// Writes `data` (through TLS once it is up).
    ///
    /// # Errors
    ///
    /// [`RdpError::Unreachable`] on an I/O error.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), RdpError> {
        match &mut self.tls {
            None => self.tcp.write_all(data).await.map_err(|e| io_error(&e)),
            Some(tls) => {
                tls.writer().write_all(data).map_err(|e| io_error(&e))?;
                self.flush_tls().await
            }
        }
    }

    async fn flush_tls(&mut self) -> Result<(), RdpError> {
        let Some(tls) = &mut self.tls else {
            return Ok(());
        };
        while tls.wants_write() {
            let mut out = Vec::with_capacity(CHUNK);
            tls.write_tls(&mut out).map_err(|e| io_error(&e))?;
            self.tcp.write_all(&out).await.map_err(|e| io_error(&e))?;
        }
        Ok(())
    }

    /// Reads once from TCP and feeds what came to TLS or to the pending
    /// bytes. Cancel safe: nothing is lost if the future is dropped before
    /// the read completes.
    ///
    /// # Errors
    ///
    /// [`RdpError::Unreachable`] when the target closed, [`RdpError::Tls`]
    /// on a TLS error.
    pub async fn fill(&mut self) -> Result<(), RdpError> {
        let mut buf = vec![0u8; CHUNK];
        let n = self.tcp.read(&mut buf).await.map_err(|e| io_error(&e))?;
        self.absorb(&buf[..n])
    }

    /// Feeds bytes read from TCP (what [`Transport::fill`] does after its
    /// read).
    ///
    /// # Errors
    ///
    /// As [`Transport::fill`].
    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), RdpError> {
        if bytes.is_empty() {
            return Err(RdpError::Unreachable(
                "connexion fermée par la cible".into(),
            ));
        }
        self.received = self.received.saturating_add(bytes.len() as u64);
        let Some(tls) = &mut self.tls else {
            self.pending.extend_from_slice(bytes);
            return self.check_pending();
        };
        let mut slice = bytes;
        while !slice.is_empty() {
            tls.read_tls(&mut slice).map_err(|e| io_error(&e))?;
            tls.process_new_packets()
                .map_err(|e| RdpError::Tls(e.to_string()))?;
        }
        let mut chunk = [0u8; CHUNK];
        loop {
            match tls.reader().read(&mut chunk) {
                Ok(0) => {
                    return Err(RdpError::Unreachable("TLS fermée par la cible".into()));
                }
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(io_error(&e)),
            }
        }
        self.check_pending()
    }

    fn check_pending(&self) -> Result<(), RdpError> {
        // A PDU is at most MAX_PDU; more pending bytes than a few PDUs
        // means the reader is not consuming: refuse rather than grow.
        if self.pending.len() > 4 * MAX_PDU {
            return Err(RdpError::Protocol("données en attente hors bornes".into()));
        }
        Ok(())
    }

    /// The plain bytes received and not consumed.
    pub fn pending(&self) -> &[u8] {
        &self.pending
    }

    /// Consumes the first `n` pending bytes.
    pub fn consume(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.pending.len());
        self.pending.drain(..n).collect()
    }

    /// Runs the TLS handshake towards `name` with `config`; the certificate
    /// is verified by `ostena-crypto` (`check`) before anything is sent.
    ///
    /// # Errors
    ///
    /// [`RdpError::Certificate`] if the certificate is refused,
    /// [`RdpError::Tls`] for any other handshake failure.
    pub async fn start_tls(
        &mut self,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        check: &TargetCheck,
    ) -> Result<(), RdpError> {
        if !self.pending.is_empty() {
            return Err(RdpError::Protocol(
                "données avant la négociation TLS".into(),
            ));
        }
        let mut tls =
            ClientConnection::new(config, name).map_err(|e| RdpError::Tls(e.to_string()))?;
        let result = loop {
            while tls.wants_write() {
                let mut out = Vec::with_capacity(CHUNK);
                tls.write_tls(&mut out).map_err(|e| io_error(&e))?;
                self.tcp.write_all(&out).await.map_err(|e| io_error(&e))?;
            }
            if !tls.is_handshaking() {
                break Ok(());
            }
            let mut buf = vec![0u8; CHUNK];
            let n = self.tcp.read(&mut buf).await.map_err(|e| io_error(&e))?;
            if n == 0 {
                break Err(RdpError::Tls(
                    "connexion fermée pendant la négociation".into(),
                ));
            }
            let mut slice = &buf[..n];
            let mut failed = None;
            while !slice.is_empty() {
                if let Err(e) = tls.read_tls(&mut slice) {
                    failed = Some(io_error(&e));
                    break;
                }
                if let Err(e) = tls.process_new_packets() {
                    failed = Some(classify(&e, check));
                    break;
                }
            }
            if let Some(error) = failed {
                // Best effort: tell the target why.
                while tls.wants_write() {
                    let mut out = Vec::new();
                    if tls.write_tls(&mut out).is_err() || self.tcp.write_all(&out).await.is_err() {
                        break;
                    }
                }
                break Err(error);
            }
        };
        result?;
        if check.verified_public_key().is_none() {
            return Err(RdpError::Certificate("non vérifié"));
        }
        self.tls = Some(tls);
        Ok(())
    }

    /// Sends the TLS close notification and shuts the socket down.
    pub async fn close(&mut self) {
        if let Some(tls) = &mut self.tls {
            tls.send_close_notify();
        }
        let _ = self.flush_tls().await;
        let _ = self.tcp.shutdown().await;
    }
}

fn classify(error: &ostena_crypto::tls::TlsHandshakeError, check: &TargetCheck) -> RdpError {
    if is_pin_mismatch(error) {
        return RdpError::Certificate("empreinte différente de l'empreinte épinglée");
    }
    match check.presented() {
        Some(p) if !p.verified => RdpError::Certificate("hors de la PKI des cibles"),
        _ => RdpError::Tls(error.to_string()),
    }
}

/// Reads one PDU whose size `size_of` tells from its first bytes (`None`:
/// not enough bytes yet).
///
/// # Errors
///
/// [`RdpError::Protocol`] if the size is invalid or above `max`, and the
/// errors of [`Transport::fill`].
pub async fn read_pdu(
    transport: &mut Transport,
    max: usize,
    size_of: impl Fn(&[u8]) -> Result<Option<usize>, RdpError>,
) -> Result<Vec<u8>, RdpError> {
    loop {
        if let Some(size) = size_of(transport.pending())? {
            if size == 0 || size > max {
                return Err(RdpError::Protocol(format!(
                    "taille de PDU {size} hors bornes"
                )));
            }
            if transport.pending().len() >= size {
                return Ok(transport.consume(size));
            }
        }
        transport.fill().await?;
    }
}
