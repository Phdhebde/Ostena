//! RFC 3161 time-stamps (ADR-0012, « Horodatage RFC 3161 des têtes »):
//! requests, responses and tokens, with a strict DER parser and a fixed
//! profile.
//!
//! - The imprint is SHA-256; the token is a CMS `SignedData` (RFC 5652)
//!   with exactly one signer, signed attributes, ECDSA P-256 / SHA-256
//!   (ADR-0009): any other algorithm is refused, never negotiated.
//! - The signer certificate is named by a `signingCertificateV2` attribute
//!   (RFC 5816) with a SHA-256 hash (the SHA-1 `signingCertificate` is
//!   refused); it must chain to a trusted anchor at the time of the
//!   stamp, and carry the critical extended key usage `timeStamping`
//!   alone (RFC 3161 section 2.3).
//! - Everything is bounded: a response of at most [`MAX_RESPONSE`] bytes.
//!
//! The token is a hostile input (a TSA response, or an export written by
//! anyone): every element is checked before it is used, and the parser
//! refuses every encoding that is not DER. Fuzzed by `tsp_response`.

pub(crate) mod der;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

use ::aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, UnixTime};

use self::der::{Reader, tag, write};

/// Largest response accepted from a time-stamping authority.
pub const MAX_RESPONSE: usize = 16 * 1024;
/// Largest token kept (in the audit chain, ADR-0012).
pub const MAX_TOKEN: usize = 6 * 1024;
/// Most trusted certificates of an authority.
pub const MAX_ANCHORS: usize = 16;

/// OID contents (DER, without tag and length).
pub(crate) mod oid {
    pub(crate) const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    pub(crate) const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    pub(crate) const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    pub(crate) const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    pub(crate) const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    pub(crate) const TST_INFO: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
    ];
    pub(crate) const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    pub(crate) const MESSAGE_DIGEST: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    pub(crate) const SIGNING_CERTIFICATE_V2: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
    ];
    pub(crate) const SIGNING_CERTIFICATE: &[u8] = &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c,
    ];
    pub(crate) const TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
    pub(crate) const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    pub(crate) const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
}

/// Time-stamp errors, each with a stable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TspError {
    /// Not DER, or not the structure RFC 3161 and RFC 5652 define.
    #[error("[TSP-E001] jeton ou réponse d'horodatage mal formé : {0}")]
    Malformed(&'static str),
    /// The authority refused the request.
    #[error("[TSP-E002] horodatage refusé par l'autorité (statut {status}{text})")]
    Refused {
        /// `PKIStatus`.
        status: u64,
        /// The status string of the authority, if any, prefixed.
        text: String,
    },
    /// Another algorithm than SHA-256 and ECDSA P-256 / SHA-256.
    #[error("[TSP-E003] algorithme non admis : {0} (seuls SHA-256 et ECDSA P-256 / SHA-256)")]
    Algorithm(&'static str),
    /// The signature of the token does not verify.
    #[error("[TSP-E004] signature du jeton d'horodatage invalide")]
    Signature,
    /// The signer certificate is absent, untrusted, or not a time-stamping
    /// certificate.
    #[error("[TSP-E005] certificat de l'autorité d'horodatage refusé : {0}")]
    Certificate(String),
    /// The token does not stamp what was asked (imprint, nonce).
    #[error("[TSP-E006] jeton d'horodatage étranger à la demande : {0}")]
    Mismatch(&'static str),
}

impl TspError {
    /// The stable code, e.g. `TSP-E004`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "TSP-E001",
            Self::Refused { .. } => "TSP-E002",
            Self::Algorithm(_) => "TSP-E003",
            Self::Signature => "TSP-E004",
            Self::Certificate(_) => "TSP-E005",
            Self::Mismatch(_) => "TSP-E006",
        }
    }
}

/// A time-stamp request (`TimeStampReq`) for a SHA-256 digest, with a
/// random nonce, asking the authority for its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    der: Vec<u8>,
    digest: [u8; 32],
    nonce: Vec<u8>,
}

impl Request {
    /// A request stamping `digest`.
    ///
    /// # Errors
    ///
    /// [`TspError::Malformed`] if no random nonce can be drawn.
    pub fn new(digest: [u8; 32]) -> Result<Self, TspError> {
        let random = crate::rand::array::<8>().map_err(|_| TspError::Malformed("aléa"))?;
        Ok(Self::with_nonce(digest, &random))
    }

    /// The same, with a given nonce (tests).
    pub fn with_nonce(digest: [u8; 32], nonce: &[u8]) -> Self {
        let nonce_der = write::unsigned(nonce);
        let imprint = message_imprint(&digest);
        let der = write::sequence(&[
            &write::unsigned(&[1]),
            &imprint,
            &nonce_der,
            &write::element(tag::BOOLEAN, &[0xff]),
        ]);
        // The INTEGER content, as the authority must echo it.
        let nonce = nonce_der[2..].to_vec();
        Self { der, digest, nonce }
    }

    /// The DER encoding, sent as `application/timestamp-query`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The digest stamped.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Checks the response of the authority: granted, a token for this
    /// digest and this nonce, signed and trusted per `trust`. Returns the
    /// token (DER) and what it says.
    ///
    /// # Errors
    ///
    /// Any [`TspError`]; a token above [`MAX_TOKEN`] is malformed.
    pub fn check(
        &self,
        response: &[u8],
        trust: &TsaTrust,
    ) -> Result<(Vec<u8>, TimeStamp), TspError> {
        let token = token_of_response(response)?;
        let stamp = verify(token, &self.digest, trust)?;
        if stamp.nonce.as_deref() != Some(self.nonce.as_slice()) {
            return Err(TspError::Mismatch("nonce"));
        }
        Ok((token.to_vec(), stamp))
    }
}

fn message_imprint(digest: &[u8; 32]) -> Vec<u8> {
    write::sequence(&[
        &write::sequence(&[&write::oid(oid::SHA256)]),
        &write::octets(digest),
    ])
}

/// The token of a `TimeStampResp`, if the status grants it.
///
/// # Errors
///
/// [`TspError::Refused`] for a status other than granted (0) or granted
/// with modifications (1); [`TspError::Malformed`] otherwise, including a
/// response above [`MAX_RESPONSE`] or a token above [`MAX_TOKEN`].
pub fn token_of_response(response: &[u8]) -> Result<&[u8], TspError> {
    if response.len() > MAX_RESPONSE {
        return Err(TspError::Malformed("réponse trop grande"));
    }
    let mut outer = Reader::new(response);
    let mut resp = outer.nested(tag::SEQUENCE, "TimeStampResp")?;
    outer.finish("octets après la réponse")?;
    let mut info = resp.nested(tag::SEQUENCE, "PKIStatusInfo")?;
    let status = info.small("statut")?;
    let mut text = String::new();
    if let Some(strings) = info.optional(tag::SEQUENCE)? {
        let mut strings = Reader::new(strings);
        while !strings.is_empty() {
            let s = strings.expect(tag::UTF8_STRING, "statusString")?;
            let s = std::str::from_utf8(s).map_err(|_| TspError::Malformed("statusString"))?;
            text.push_str(" : ");
            text.extend(s.chars().filter(|c| !c.is_control()).take(200));
        }
    }
    let _fail_info = info.optional(tag::BIT_STRING)?;
    info.finish("PKIStatusInfo")?;
    if status > 1 {
        return Err(TspError::Refused { status, text });
    }
    let (_, token) = resp.expect_whole(tag::SEQUENCE, "jeton absent")?;
    resp.finish("octets après le jeton")?;
    if token.len() > MAX_TOKEN {
        return Err(TspError::Malformed("jeton trop grand"));
    }
    Ok(token)
}

/// The trusted certificates of time-stamping authorities: roots or
/// intermediates, each a trust anchor (at most [`MAX_ANCHORS`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TsaTrust {
    anchors: Vec<CertificateDer<'static>>,
}

impl TsaTrust {
    /// Trust in `anchors` (DER).
    ///
    /// # Errors
    ///
    /// [`TspError::Certificate`] for none, more than [`MAX_ANCHORS`], or a
    /// certificate that cannot be an anchor.
    pub fn new(anchors: Vec<CertificateDer<'static>>) -> Result<Self, TspError> {
        if anchors.is_empty() || anchors.len() > MAX_ANCHORS {
            return Err(TspError::Certificate(format!(
                "de 1 à {MAX_ANCHORS} certificats de confiance attendus"
            )));
        }
        for anchor in &anchors {
            webpki::anchor_from_trusted_cert(anchor)
                .map_err(|e| TspError::Certificate(format!("ancre illisible : {e}")))?;
        }
        Ok(Self { anchors })
    }

    /// Trust in every certificate of a PEM text.
    ///
    /// # Errors
    ///
    /// As [`TsaTrust::new`], or a PEM text without certificate.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TspError> {
        use rustls::pki_types::pem::PemObject;
        let certs = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TspError::Certificate("PEM illisible".into()))?;
        Self::new(certs)
    }

    /// Adds the certificates of another trust.
    ///
    /// # Errors
    ///
    /// More than [`MAX_ANCHORS`] in all.
    pub fn extend(&mut self, other: Self) -> Result<(), TspError> {
        if self.anchors.len() + other.anchors.len() > MAX_ANCHORS {
            return Err(TspError::Certificate(format!(
                "plus de {MAX_ANCHORS} certificats de confiance"
            )));
        }
        self.anchors.extend(other.anchors);
        Ok(())
    }

    /// The trusted certificates.
    pub fn anchors(&self) -> &[CertificateDer<'static>] {
        &self.anchors
    }
}

/// What a verified token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStamp {
    /// `genTime`, Unix milliseconds.
    pub gen_time_ms: u64,
    /// The accuracy announced, in milliseconds (rounded up), if any.
    pub accuracy_ms: Option<u64>,
    /// The serial number of the token (INTEGER content).
    pub serial: Vec<u8>,
    /// The policy of the authority, dotted.
    pub policy: String,
    /// The nonce echoed (INTEGER content), if any.
    pub nonce: Option<Vec<u8>>,
    /// SHA-256 of the signer certificate.
    pub signer_sha256: [u8; 32],
}

/// A token parsed, nothing verified yet.
#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    /// The `TSTInfo` (DER), signed.
    tst_info: &'a [u8],
    /// Its fields.
    pub info: TstInfo,
    /// The certificates of the token.
    certificates: Vec<&'a [u8]>,
    signer: Signer<'a>,
}

/// The fields of a `TSTInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo {
    /// The policy, dotted.
    pub policy: String,
    /// The SHA-256 digest stamped.
    pub digest: [u8; 32],
    /// Serial number (INTEGER content).
    pub serial: Vec<u8>,
    /// `genTime`, Unix milliseconds.
    pub gen_time_ms: u64,
    /// Accuracy, milliseconds rounded up.
    pub accuracy_ms: Option<u64>,
    /// Nonce (INTEGER content).
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyId(&'a [u8]),
}

#[derive(Debug, Clone)]
struct Signer<'a> {
    id: SignerId<'a>,
    /// The signed attributes, as encoded (`[0]` tag).
    signed_attrs: &'a [u8],
    message_digest: [u8; 32],
    cert_hash: [u8; 32],
    signature: &'a [u8],
}

/// Parses a token (a CMS `ContentInfo`): structure and profile, no
/// signature or trust check.
///
/// # Errors
///
/// [`TspError::Malformed`] or [`TspError::Algorithm`].
pub fn parse(token: &[u8]) -> Result<Parsed<'_>, TspError> {
    if token.len() > MAX_TOKEN {
        return Err(TspError::Malformed("jeton trop grand"));
    }
    let mut outer = Reader::new(token);
    let mut content_info = outer.nested(tag::SEQUENCE, "ContentInfo")?;
    outer.finish("octets après le jeton")?;
    if content_info.expect(tag::OID, "contentType")? != oid::SIGNED_DATA {
        return Err(TspError::Malformed("pas un SignedData"));
    }
    let mut explicit = content_info.nested(tag::context(0), "SignedData")?;
    content_info.finish("ContentInfo")?;
    let mut sd = explicit.nested(tag::SEQUENCE, "SignedData")?;
    explicit.finish("SignedData")?;
    if sd.small("version de SignedData")? != 3 {
        return Err(TspError::Malformed("version de SignedData"));
    }
    let mut digests = sd.nested(tag::SET, "digestAlgorithms")?;
    sha256_algorithm(&mut digests)?;
    digests.finish("un seul digestAlgorithm attendu")?;
    let mut encap = sd.nested(tag::SEQUENCE, "encapContentInfo")?;
    if encap.expect(tag::OID, "eContentType")? != oid::TST_INFO {
        return Err(TspError::Malformed("pas un TSTInfo"));
    }
    let mut e_content = encap.nested(tag::context(0), "eContent")?;
    encap.finish("encapContentInfo")?;
    let tst_info = e_content.expect(tag::OCTET_STRING, "eContent")?;
    e_content.finish("eContent")?;
    let mut certificates = Vec::new();
    if let Some(certs) = sd.optional(tag::context(0))? {
        let mut certs = Reader::new(certs);
        while !certs.is_empty() {
            let (cert_tag, _, whole) = certs.any()?;
            if cert_tag != tag::SEQUENCE {
                return Err(TspError::Malformed("certificat d'un autre type"));
            }
            certificates.push(whole);
        }
    }
    if sd.peek() == Some(tag::context(1)) {
        return Err(TspError::Malformed("listes de révocation dans le jeton"));
    }
    let mut signers = sd.nested(tag::SET, "signerInfos")?;
    sd.finish("SignedData")?;
    let signer = signer_info(&mut signers.nested(tag::SEQUENCE, "SignerInfo")?)?;
    signers.finish("un seul signataire attendu")?;
    let info = tst_info_of(tst_info)?;
    Ok(Parsed {
        tst_info,
        info,
        certificates,
        signer,
    })
}

/// An `AlgorithmIdentifier` that must be SHA-256 (parameters absent or NULL).
fn sha256_algorithm(r: &mut Reader<'_>) -> Result<(), TspError> {
    let mut alg = r.nested(tag::SEQUENCE, "AlgorithmIdentifier")?;
    if alg.expect(tag::OID, "algorithme")? != oid::SHA256 {
        return Err(TspError::Algorithm("empreinte"));
    }
    if let Some(null) = alg.optional(tag::NULL)?
        && !null.is_empty()
    {
        return Err(TspError::Malformed("paramètres de SHA-256"));
    }
    alg.finish("paramètres de SHA-256")
}

fn signer_info<'a>(si: &mut Reader<'a>) -> Result<Signer<'a>, TspError> {
    let version = si.small("version de SignerInfo")?;
    let id = match (version, si.peek()) {
        (1, Some(tag::SEQUENCE)) => {
            let mut ias = si.nested(tag::SEQUENCE, "issuerAndSerialNumber")?;
            let (_, issuer) = ias.expect_whole(tag::SEQUENCE, "issuer")?;
            let serial = ias.integer("serialNumber")?;
            ias.finish("issuerAndSerialNumber")?;
            SignerId::IssuerSerial { issuer, serial }
        }
        (3, Some(t)) if t == tag::context_primitive(0) => SignerId::KeyId(si.any()?.1),
        _ => return Err(TspError::Malformed("identifiant du signataire")),
    };
    sha256_algorithm(si)?;
    let (attrs, signed_attrs) = si.expect_whole(tag::context(0), "attributs signés absents")?;
    let mut alg = si.nested(tag::SEQUENCE, "signatureAlgorithm")?;
    if alg.expect(tag::OID, "signatureAlgorithm")? != oid::ECDSA_SHA256 {
        return Err(TspError::Algorithm("signature"));
    }
    alg.finish("paramètres de la signature")?;
    let signature = si.expect(tag::OCTET_STRING, "signature")?;
    if si.peek() == Some(tag::context(1)) {
        si.any()?;
    }
    si.finish("SignerInfo")?;

    let (mut content_type, mut message_digest, mut cert_hash) = (false, None, None);
    let mut attrs = Reader::new(attrs);
    while !attrs.is_empty() {
        let mut attr = attrs.nested(tag::SEQUENCE, "Attribute")?;
        let attr_oid = attr.expect(tag::OID, "type d'attribut")?;
        let mut values = attr.nested(tag::SET, "valeurs d'attribut")?;
        attr.finish("Attribute")?;
        let seen = match attr_oid {
            oid::CONTENT_TYPE => {
                if values.expect(tag::OID, "contentType")? != oid::TST_INFO {
                    return Err(TspError::Malformed("contentType signé"));
                }
                std::mem::replace(&mut content_type, true)
            }
            oid::MESSAGE_DIGEST => {
                let d = values.expect(tag::OCTET_STRING, "messageDigest")?;
                let d =
                    <[u8; 32]>::try_from(d).map_err(|_| TspError::Malformed("messageDigest"))?;
                message_digest.replace(d).is_some()
            }
            oid::SIGNING_CERTIFICATE_V2 => {
                let h = ess_cert_hash(&mut values)?;
                cert_hash.replace(h).is_some()
            }
            oid::SIGNING_CERTIFICATE => {
                return Err(TspError::Algorithm("signingCertificate (SHA-1)"));
            }
            _ => {
                values.any()?;
                false
            }
        };
        if seen {
            return Err(TspError::Malformed("attribut signé en double"));
        }
        values.finish("un seul attribut par type attendu")?;
    }
    if !content_type {
        return Err(TspError::Malformed("contentType signé absent"));
    }
    Ok(Signer {
        id,
        signed_attrs,
        message_digest: message_digest.ok_or(TspError::Malformed("messageDigest absent"))?,
        cert_hash: cert_hash.ok_or(TspError::Malformed("signingCertificateV2 absent"))?,
        signature,
    })
}

/// The hash of the first `ESSCertIDv2` of a `SigningCertificateV2`.
fn ess_cert_hash(values: &mut Reader<'_>) -> Result<[u8; 32], TspError> {
    let mut sc = values.nested(tag::SEQUENCE, "SigningCertificateV2")?;
    let mut certs = sc.nested(tag::SEQUENCE, "ESSCertIDv2")?;
    let mut first = certs.nested(tag::SEQUENCE, "ESSCertIDv2")?;
    if first.peek() == Some(tag::SEQUENCE) {
        sha256_algorithm(&mut first)?;
    }
    let hash = first.expect(tag::OCTET_STRING, "certHash")?;
    let hash = <[u8; 32]>::try_from(hash).map_err(|_| TspError::Malformed("certHash"))?;
    let _issuer_serial = first.optional(tag::SEQUENCE)?;
    first.finish("ESSCertIDv2")?;
    Ok(hash)
}

fn tst_info_of(der: &[u8]) -> Result<TstInfo, TspError> {
    let mut outer = Reader::new(der);
    let mut info = outer.nested(tag::SEQUENCE, "TSTInfo")?;
    outer.finish("octets après TSTInfo")?;
    if info.small("version de TSTInfo")? != 1 {
        return Err(TspError::Malformed("version de TSTInfo"));
    }
    let policy = oid_text(info.expect(tag::OID, "policy")?)?;
    let mut imprint = info.nested(tag::SEQUENCE, "messageImprint")?;
    sha256_algorithm(&mut imprint)?;
    let digest = imprint.expect(tag::OCTET_STRING, "hashedMessage")?;
    let digest = <[u8; 32]>::try_from(digest).map_err(|_| TspError::Malformed("hashedMessage"))?;
    imprint.finish("messageImprint")?;
    let serial = info.integer("serialNumber")?.to_vec();
    let gen_time_ms = der::generalized_time(info.expect(tag::GENERALIZED_TIME, "genTime")?)?;
    let accuracy_ms = match info.optional(tag::SEQUENCE)? {
        None => None,
        Some(acc) => Some(accuracy(acc)?),
    };
    if info.peek() == Some(tag::BOOLEAN) {
        // DER: DEFAULT FALSE is absent, so only TRUE may be present.
        if !info.boolean("ordering")? {
            return Err(TspError::Malformed("ordering"));
        }
    }
    let nonce = match info.peek() {
        Some(tag::INTEGER) => Some(info.integer("nonce")?.to_vec()),
        _ => None,
    };
    let _tsa = info.optional(tag::context(0))?;
    let _extensions = info.optional(tag::context(1))?;
    info.finish("TSTInfo")?;
    Ok(TstInfo {
        policy,
        digest,
        serial,
        gen_time_ms,
        accuracy_ms,
        nonce,
    })
}

fn accuracy(der: &[u8]) -> Result<u64, TspError> {
    let mut acc = Reader::new(der);
    let seconds = match acc.peek() {
        Some(tag::INTEGER) => acc.small("accuracy")?,
        _ => 0,
    };
    let small = |r: &mut Reader<'_>, t: u8| -> Result<u64, TspError> {
        match r.optional(t)? {
            None => Ok(0),
            Some(bytes) => {
                der::check_integer(bytes, "accuracy")?;
                if bytes[0] & 0x80 != 0 || bytes.len() > 2 {
                    return Err(TspError::Malformed("accuracy"));
                }
                let v = bytes.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
                if v == 0 || v > 999 {
                    return Err(TspError::Malformed("accuracy"));
                }
                Ok(v)
            }
        }
    };
    let millis = small(&mut acc, tag::context_primitive(0))?;
    let micros = small(&mut acc, tag::context_primitive(1))?;
    acc.finish("accuracy")?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(millis)
        .saturating_add(u64::from(micros > 0)))
}

/// Dotted text of an OID content.
fn oid_text(content: &[u8]) -> Result<String, TspError> {
    use std::fmt::Write as _;
    let bad = || TspError::Malformed("OID");
    if content.is_empty() || content.len() > 64 || content.last().is_some_and(|b| b & 0x80 != 0) {
        return Err(bad());
    }
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    let mut start = true;
    for &b in content {
        if start && b == 0x80 {
            return Err(bad());
        }
        value = value.checked_mul(128).ok_or_else(bad)? | u64::from(b & 0x7f);
        start = b & 0x80 == 0;
        if start {
            arcs.push(value);
            value = 0;
        }
    }
    let first = arcs[0];
    let (a, b) = match first {
        0..40 => (0, first),
        40..80 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut text = format!("{a}.{b}");
    for arc in &arcs[1..] {
        let _ = write!(text, ".{arc}");
    }
    Ok(text)
}

/// What a certificate tells the verifier.
struct CertView<'a> {
    issuer: &'a [u8],
    serial: &'a [u8],
    /// Uncompressed SEC1 point of a P-256 key.
    p256_point: Option<&'a [u8]>,
    key_id: Option<&'a [u8]>,
    /// The extended key usage: present and critical, with its purposes.
    eku: Option<(bool, Vec<&'a [u8]>)>,
}

fn cert_view(der: &[u8]) -> Result<CertView<'_>, TspError> {
    let mut outer = Reader::new(der);
    let mut cert = outer.nested(tag::SEQUENCE, "Certificate")?;
    let mut tbs = cert.nested(tag::SEQUENCE, "TBSCertificate")?;
    let _version = tbs.optional(tag::context(0))?;
    let serial = tbs.integer("numéro de série")?;
    tbs.expect(tag::SEQUENCE, "algorithme du certificat")?;
    let (_, issuer) = tbs.expect_whole(tag::SEQUENCE, "issuer")?;
    tbs.expect(tag::SEQUENCE, "validity")?;
    tbs.expect(tag::SEQUENCE, "subject")?;
    let mut spki = tbs.nested(tag::SEQUENCE, "subjectPublicKeyInfo")?;
    let mut alg = spki.nested(tag::SEQUENCE, "algorithme de la clé")?;
    let is_p256 = alg.expect(tag::OID, "algorithme de la clé")? == oid::EC_PUBLIC_KEY
        && alg.optional(tag::OID)? == Some(oid::P256);
    let bits = spki.expect(tag::BIT_STRING, "clé publique")?;
    let p256_point = match bits {
        [0, point @ ..] if is_p256 && point.len() == 65 && point[0] == 0x04 => Some(point),
        _ => None,
    };
    let _issuer_uid = tbs.optional(tag::context_primitive(1))?;
    let _subject_uid = tbs.optional(tag::context_primitive(2))?;
    let (mut key_id, mut eku) = (None, None);
    if let Some(exts) = tbs.optional(tag::context(3))? {
        let mut exts = Reader::new(exts);
        let mut exts = exts.nested(tag::SEQUENCE, "extensions")?;
        while !exts.is_empty() {
            let mut ext = exts.nested(tag::SEQUENCE, "extension")?;
            let ext_oid = ext.expect(tag::OID, "extension")?;
            let critical = if ext.peek() == Some(tag::BOOLEAN) {
                ext.boolean("critical")?
            } else {
                false
            };
            let value = ext.expect(tag::OCTET_STRING, "extnValue")?;
            match ext_oid {
                oid::EXT_KEY_USAGE => {
                    let mut seq = Reader::new(value);
                    let mut purposes = seq.nested(tag::SEQUENCE, "extKeyUsage")?;
                    let mut list = Vec::new();
                    while !purposes.is_empty() {
                        list.push(purposes.expect(tag::OID, "extKeyUsage")?);
                    }
                    eku = Some((critical, list));
                }
                oid::SUBJECT_KEY_ID => {
                    key_id =
                        Some(Reader::new(value).expect(tag::OCTET_STRING, "subjectKeyIdentifier")?);
                }
                _ => {}
            }
        }
    }
    Ok(CertView {
        issuer,
        serial,
        p256_point,
        key_id,
        eku,
    })
}

/// Verifies `token` as a time-stamp of `digest` trusted per `trust`: the
/// imprint, the signed attributes, the ECDSA signature, the signer
/// certificate (named by `signingCertificateV2`, matching the signer
/// identifier, critical `timeStamping` usage alone) and its chain to an
/// anchor at `genTime`.
///
/// # Errors
///
/// Any [`TspError`].
pub fn verify(token: &[u8], digest: &[u8; 32], trust: &TsaTrust) -> Result<TimeStamp, TspError> {
    let parsed = parse(token)?;
    if !crate::constant_time_eq(&parsed.info.digest, digest) {
        return Err(TspError::Mismatch("empreinte horodatée"));
    }
    if crate::sha256::digest(parsed.tst_info) != parsed.signer.message_digest {
        return Err(TspError::Signature);
    }
    let signer = parsed
        .certificates
        .iter()
        .copied()
        .chain(trust.anchors.iter().map(AsRef::as_ref))
        .find(|c| crate::sha256::digest(c) == parsed.signer.cert_hash)
        .ok_or_else(|| TspError::Certificate("certificat du signataire absent".into()))?;
    let view = cert_view(signer)?;
    let named = match &parsed.signer.id {
        SignerId::IssuerSerial { issuer, serial } => {
            *issuer == view.issuer && *serial == view.serial
        }
        SignerId::KeyId(id) => view.key_id == Some(*id),
    };
    if !named {
        return Err(TspError::Certificate(
            "identifiant du signataire différent du certificat désigné".into(),
        ));
    }
    match &view.eku {
        Some((true, purposes)) if purposes.as_slice() == [oid::TIME_STAMPING] => {}
        _ => {
            return Err(TspError::Certificate(
                "usage étendu timeStamping critique et seul exigé".into(),
            ));
        }
    }
    let point = view
        .p256_point
        .ok_or(TspError::Algorithm("clé du signataire"))?;
    // The signature covers the DER of the attributes as a SET (RFC 5652
    // section 5.4), not their implicit [0] tag.
    let mut attrs_as_set = parsed.signer.signed_attrs.to_vec();
    attrs_as_set[0] = tag::SET;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&attrs_as_set, parsed.signer.signature)
        .map_err(|_| TspError::Signature)?;

    let anchors = trust
        .anchors
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TspError::Certificate(format!("ancre illisible : {e}")))?;
    let intermediates: Vec<CertificateDer<'_>> = parsed
        .certificates
        .iter()
        .filter(|c| **c != signer)
        .map(|c| CertificateDer::from(*c))
        .collect();
    let end_entity = CertificateDer::from(signer);
    let cert = webpki::EndEntityCert::try_from(&end_entity)
        .map_err(|e| TspError::Certificate(e.to_string()))?;
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_millis(parsed.info.gen_time_ms));
    cert.verify_for_usage(
        crate::tls::SIGNATURE_ALGORITHMS.all,
        &anchors,
        &intermediates,
        at,
        webpki::KeyUsage::required(oid::TIME_STAMPING),
        None,
        None,
    )
    .map_err(|e| TspError::Certificate(e.to_string()))?;
    Ok(TimeStamp {
        gen_time_ms: parsed.info.gen_time_ms,
        accuracy_ms: parsed.info.accuracy_ms,
        serial: parsed.info.serial,
        policy: parsed.info.policy,
        nonce: parsed.info.nonce,
        signer_sha256: parsed.signer.cert_hash,
    })
}

/// Entry point of the cargo-fuzz target `tsp_response` and of the stable
/// test that replays its corpus. Not part of the API.
#[doc(hidden)]
pub mod fuzz {
    use rustls::pki_types::CertificateDer;

    use super::{TsaTrust, der, parse, token_of_response, verify};

    /// Runs the parsers on untrusted input, a response or a token; must
    /// never panic. A token that parses is verified against its own
    /// certificates as anchors and its own imprint, to reach the signature
    /// and certificate checks.
    pub fn response(data: &[u8]) {
        let token = token_of_response(data).unwrap_or(data);
        if let Ok(parsed) = parse(token) {
            let digest = parsed.info.digest;
            let anchors = parsed
                .certificates
                .iter()
                .take(super::MAX_ANCHORS)
                .map(|c| CertificateDer::from(c.to_vec()))
                .collect();
            if let Ok(trust) = TsaTrust::new(anchors) {
                let _ = verify(token, &digest, &trust);
            }
        }
        if let Ok(ms) = der::generalized_time(data) {
            assert!(ms < 253_402_300_800_000, "année à quatre chiffres");
        }
    }
}
