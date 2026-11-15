//! OpenSSH certificates of the frozen list only:
//! `ecdsa-sha2-nistp256-cert-v01@openssh.com` (PROTOCOL.certkeys), signed by
//! an ECDSA P-256 authority (ADR-0010).
//!
//! The codec is strict and canonical: [`parse`] refuses anything
//! [`Certificate::encode`] would not write back byte for byte (another key
//! type or curve, an authority or a signature of another algorithm, a
//! non-minimal `mpint`, trailing bytes, a non-empty reserved field, options
//! or extensions out of order or repeated), a certificate of more than
//! [`MAX_CERTIFICATE`] bytes and more than [`MAX_PRINCIPALS`] principals.
//!
//! Signatures are made and checked by `ostena-crypto` (aws-lc): low-S form
//! on issue, strict verification. It is the second check of a user
//! certificate: the SSH library verifies the dates and the signature with
//! its own cryptography, but not the authority, the type, the principals,
//! the options nor the extensions, which [`check_user`] does.
//!
//! Pure and bounded, without the SSH library: fuzzed alone
//! (`ssh_certificate`).

use std::fmt::Write as _;

use ostena_crypto::p256::{self, Signature, SigningKey, VerifyingKey};
use ostena_grant::Kid;

use crate::algorithms;

/// Certificate type name.
pub const CERT_TYPE: &str = algorithms::HOST_KEY_CERTIFICATE;
/// Key and signature algorithm of the subject and the authority.
const KEY_TYPE: &str = algorithms::HOST_KEY;
/// Curve name.
const CURVE: &str = "nistp256";
/// Largest certificate accepted, in bytes.
pub const MAX_CERTIFICATE: usize = 4096;
/// Most principals accepted.
pub const MAX_PRINCIPALS: usize = 16;
/// Bounds of the nonce (`ssh-keygen` draws 32 bytes, so does [`issue`]).
pub const NONCE_LEN: std::ops::RangeInclusive<usize> = 16..=64;
/// Longest key identifier, principal or option name.
const MAX_TEXT: usize = 256;
/// Clock skew tolerated on the start of validity of a user certificate.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// Longest validity of a user certificate: the 8 hours of a login session,
/// plus a margin.
pub const MAX_USER_VALIDITY_SECS: u64 = 8 * 3600 + 5 * 60;
/// The only extension a user certificate may carry.
pub const PERMIT_PTY: &str = "permit-pty";

/// User or host certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `SSH2_CERT_TYPE_USER`.
    User,
    /// `SSH2_CERT_TYPE_HOST`.
    Host,
}

impl Kind {
    const fn code(self) -> u32 {
        match self {
            Self::User => 1,
            Self::Host => 2,
        }
    }
}

/// Why a certificate is refused. Deliberately without a code: the caller
/// gives it (`SSH-E011` for a user, `SSH-E018` for the agent identity).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// More than [`MAX_CERTIFICATE`] bytes.
    #[error("certificat de plus de {MAX_CERTIFICATE} octets")]
    TooLarge,
    /// Not a certificate of the frozen list.
    #[error("type de certificat hors de la liste figée ({CERT_TYPE} seul)")]
    UnsupportedType,
    /// Malformed or not canonical.
    #[error("certificat mal formé : {0}")]
    Malformed(&'static str),
    /// Signed by an authority that is not trusted.
    #[error("autorité de certification inconnue")]
    UnknownAuthority,
    /// The signature does not verify (or is not in its low-S form).
    #[error("signature du certificat invalide")]
    BadSignature,
    /// Well formed and signed, but not acceptable here.
    #[error("certificat refusé : {0}")]
    Refused(&'static str),
    /// Issue failed (random generator, signature).
    #[error("émission du certificat impossible : {0}")]
    Issue(&'static str),
}

/// A parsed certificate, borrowing its blob. Its signature is not checked
/// until [`Certificate::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<'a> {
    raw: &'a [u8],
    signed_len: usize,
    /// Nonce chosen by the authority.
    pub nonce: &'a [u8],
    /// The certified key.
    pub public: VerifyingKey,
    /// Serial number.
    pub serial: u64,
    /// User or host.
    pub kind: Kind,
    /// Key identifier.
    pub key_id: &'a str,
    /// Principals (empty: any, which [`check_user`] refuses).
    pub principals: Vec<&'a str>,
    /// Start of validity, Unix seconds.
    pub valid_after: u64,
    /// End of validity, Unix seconds (exclusive).
    pub valid_before: u64,
    /// Critical options, sorted, each name once: (name, data).
    pub critical_options: Vec<(&'a str, &'a [u8])>,
    /// Extensions, sorted, each name once: (name, data).
    pub extensions: Vec<(&'a str, &'a [u8])>,
    /// The signing authority.
    pub authority: VerifyingKey,
    /// The signature, `r ‖ s`.
    pub signature: Signature,
}

/// What [`issue`] certifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// User or host.
    pub kind: Kind,
    /// The certified key.
    pub public: VerifyingKey,
    /// Serial number.
    pub serial: u64,
    /// Key identifier.
    pub key_id: String,
    /// Principals.
    pub principals: Vec<String>,
    /// Start of validity, Unix seconds.
    pub valid_after: u64,
    /// End of validity, Unix seconds (exclusive).
    pub valid_before: u64,
    /// Critical options (name, data); sorted by [`issue`].
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Extensions (name, data); sorted by [`issue`].
    pub extensions: Vec<(String, Vec<u8>)>,
}

/// Who a user certificate names, after [`check_user`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIdentity {
    /// The user (principal), UUID bytes.
    pub subject: [u8; 16],
    /// The `ostena login` session (key identifier), UUID bytes.
    pub login_session: [u8; 16],
    /// The certificate allows a terminal (`permit-pty`).
    pub allow_pty: bool,
    /// SHA-256 of the certificate blob.
    pub certificate_sha256: [u8; 32],
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CertError> {
        if self.0.len() < n {
            return Err(CertError::Malformed("tronqué"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, CertError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, CertError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn string(&mut self) -> Result<&'a [u8], CertError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn end(&self) -> Result<(), CertError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(CertError::Malformed("octets en trop"))
        }
    }
}

/// Text without control characters, at most [`MAX_TEXT`] bytes.
fn text<'a>(bytes: &'a [u8], what: &'static str) -> Result<&'a str, CertError> {
    let s = std::str::from_utf8(bytes).map_err(|_| CertError::Malformed(what))?;
    if s.len() > MAX_TEXT || s.chars().any(char::is_control) {
        return Err(CertError::Malformed(what));
    }
    Ok(s)
}

fn point(bytes: &[u8], what: &'static str) -> Result<VerifyingKey, CertError> {
    let bytes: &[u8; p256::PUBLIC_KEY_LEN] =
        bytes.try_into().map_err(|_| CertError::Malformed(what))?;
    VerifyingKey::from_bytes(bytes).map_err(|_| CertError::Malformed(what))
}

/// Options or extensions: name and data strings, names strictly increasing.
fn options(bytes: &[u8]) -> Result<Vec<(&str, &[u8])>, CertError> {
    let mut r = Reader(bytes);
    let mut out: Vec<(&str, &[u8])> = Vec::new();
    while !r.0.is_empty() {
        let name = r.string()?;
        let name = text(name, "nom d'option invalide")?;
        if name.is_empty() || !name.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(CertError::Malformed("nom d'option invalide"));
        }
        let data = r.string()?;
        if let Some((last, _)) = out.last()
            && last.as_bytes() >= name.as_bytes()
        {
            return Err(CertError::Malformed("options non triées ou répétées"));
        }
        out.push((name, data));
        if out.len() > MAX_PRINCIPALS * 2 {
            return Err(CertError::Malformed("trop d'options"));
        }
    }
    Ok(out)
}

/// A minimal positive `mpint` of at most 32 significant bytes, left-padded.
fn mpint(bytes: &[u8]) -> Result<[u8; 32], CertError> {
    let bad = CertError::Malformed("entier de la signature non canonique");
    let digits = match bytes {
        [] => return Err(CertError::BadSignature),
        [first, ..] if first & 0x80 != 0 => return Err(bad),
        [0, second, ..] if second & 0x80 != 0 => &bytes[1..],
        [0, ..] => return Err(bad),
        _ => bytes,
    };
    if digits.len() > 32 {
        return Err(bad);
    }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(digits);
    Ok(out)
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u32::try_from(value).unwrap_or(u32::MAX).to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_mpint(out: &mut Vec<u8>, value: &[u8; 32]) {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let digits = &value[start..];
    let pad = digits.first().is_some_and(|b| b & 0x80 != 0);
    put_u32(out, digits.len() + usize::from(pad));
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

fn key_blob(key: &VerifyingKey) -> Vec<u8> {
    let mut blob = Vec::with_capacity(104);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, CURVE.as_bytes());
    put_string(&mut blob, &key.to_bytes());
    blob
}

fn signature_blob(signature: &Signature) -> Vec<u8> {
    let bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    let mut inner = Vec::with_capacity(70);
    put_mpint(&mut inner, &r);
    put_mpint(&mut inner, &s);
    let mut blob = Vec::with_capacity(100);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, &inner);
    blob
}

fn packed<'a>(items: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in items {
        put_string(&mut out, name);
        if let Some(data) = data {
            put_string(&mut out, data);
        }
    }
    out
}

/// The signed part: every field up to and including the authority.
#[allow(clippy::too_many_arguments)]
fn signed_part(
    nonce: &[u8],
    public: &VerifyingKey,
    serial: u64,
    kind: Kind,
    key_id: &str,
    principals: &[&str],
    valid_after: u64,
    valid_before: u64,
    critical_options: &[(&str, &[u8])],
    extensions: &[(&str, &[u8])],
    authority: &VerifyingKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    put_string(&mut out, CERT_TYPE.as_bytes());
    put_string(&mut out, nonce);
    put_string(&mut out, CURVE.as_bytes());
    put_string(&mut out, &public.to_bytes());
    out.extend_from_slice(&serial.to_be_bytes());
    out.extend_from_slice(&kind.code().to_be_bytes());
    put_string(&mut out, key_id.as_bytes());
    put_string(
        &mut out,
        &packed(principals.iter().map(|p| (p.as_bytes(), None))),
    );
    out.extend_from_slice(&valid_after.to_be_bytes());
    out.extend_from_slice(&valid_before.to_be_bytes());
    put_string(
        &mut out,
        &packed(
            critical_options
                .iter()
                .map(|(n, d)| (n.as_bytes(), Some(*d))),
        ),
    );
    put_string(
        &mut out,
        &packed(extensions.iter().map(|(n, d)| (n.as_bytes(), Some(*d)))),
    );
    put_string(&mut out, b"");
    put_string(&mut out, &key_blob(authority));
    out
}

/// Parses a certificate blob (the binary form, not the base64 line).
///
/// # Errors
///
/// [`CertError`] for anything outside the frozen list or not canonical.
pub fn parse(blob: &[u8]) -> Result<Certificate<'_>, CertError> {
    if blob.len() > MAX_CERTIFICATE {
        return Err(CertError::TooLarge);
    }
    let mut r = Reader(blob);
    if r.string()? != CERT_TYPE.as_bytes() {
        return Err(CertError::UnsupportedType);
    }
    let nonce = r.string()?;
    if !NONCE_LEN.contains(&nonce.len()) {
        return Err(CertError::Malformed("nonce de longueur invalide"));
    }
    if r.string()? != CURVE.as_bytes() {
        return Err(CertError::UnsupportedType);
    }
    let public = point(r.string()?, "clé certifiée invalide")?;
    let serial = r.u64()?;
    let kind = match r.u32()? {
        1 => Kind::User,
        2 => Kind::Host,
        _ => return Err(CertError::Malformed("type inconnu")),
    };
    let key_id = text(r.string()?, "identifiant de clé invalide")?;
    let mut list = Reader(r.string()?);
    let mut principals = Vec::new();
    while !list.0.is_empty() {
        let p = text(list.string()?, "principal invalide")?;
        if p.is_empty() {
            return Err(CertError::Malformed("principal vide"));
        }
        principals.push(p);
        if principals.len() > MAX_PRINCIPALS {
            return Err(CertError::Malformed("trop de principaux"));
        }
    }
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let critical_options = options(r.string()?)?;
    let extensions = options(r.string()?)?;
    if !r.string()?.is_empty() {
        return Err(CertError::Malformed("champ réservé non vide"));
    }
    let mut ca = Reader(r.string()?);
    if ca.string()? != KEY_TYPE.as_bytes() || ca.string()? != CURVE.as_bytes() {
        return Err(CertError::UnsupportedType);
    }
    let authority = point(ca.string()?, "clé de l'autorité invalide")?;
    ca.end()?;
    let signed_len = blob.len() - r.0.len();
    let mut sig = Reader(r.string()?);
    r.end()?;
    if sig.string()? != KEY_TYPE.as_bytes() {
        return Err(CertError::UnsupportedType);
    }
    let mut parts = Reader(sig.string()?);
    sig.end()?;
    let rr = mpint(parts.string()?)?;
    let ss = mpint(parts.string()?)?;
    parts.end()?;
    let mut bytes = [0u8; p256::SIGNATURE_LEN];
    bytes[..32].copy_from_slice(&rr);
    bytes[32..].copy_from_slice(&ss);
    Ok(Certificate {
        raw: blob,
        signed_len,
        nonce,
        public,
        serial,
        kind,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        authority,
        signature: Signature::from_bytes(&bytes),
    })
}

impl Certificate<'_> {
    /// The blob it was parsed from.
    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    /// SHA-256 of the blob.
    pub fn sha256(&self) -> [u8; 32] {
        ostena_crypto::sha256::digest(self.raw)
    }

    /// Writes the certificate from its fields; equal to the parsed blob.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = signed_part(
            self.nonce,
            &self.public,
            self.serial,
            self.kind,
            self.key_id,
            &self.principals,
            self.valid_after,
            self.valid_before,
            &self.critical_options,
            &self.extensions,
            &self.authority,
        );
        put_string(&mut out, &signature_blob(&self.signature));
        out
    }

    /// Checks that the authority is one of `authorities` and that its
    /// signature verifies (`ostena-crypto`: strict, low-S); returns the
    /// authority kid.
    ///
    /// # Errors
    ///
    /// [`CertError::UnknownAuthority`], [`CertError::BadSignature`].
    pub fn verify(&self, authorities: &[VerifyingKey]) -> Result<Kid, CertError> {
        let authority = authorities
            .iter()
            .find(|a| **a == self.authority)
            .ok_or(CertError::UnknownAuthority)?;
        authority
            .verify(&self.raw[..self.signed_len], &self.signature)
            .map_err(|_| CertError::BadSignature)?;
        Ok(Kid::of(authority))
    }
}

/// Issues a certificate for `template`, signed by `authority` with
/// `ostena-crypto` (low-S), with a 32-byte nonce from the system generator.
///
/// # Errors
///
/// [`CertError::Refused`] for a template the parser would refuse (too many
/// principals, repeated option, invalid text), [`CertError::Issue`] if the
/// random generator or the signature fails.
pub fn issue(template: &Template, authority: &SigningKey) -> Result<Vec<u8>, CertError> {
    let nonce = ostena_crypto::rand::array::<32>().map_err(|_| CertError::Issue("aléa"))?;
    let sorted = |list: &[(String, Vec<u8>)]| -> Result<Vec<(String, Vec<u8>)>, CertError> {
        let mut list = list.to_vec();
        list.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if list.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(CertError::Refused("option répétée"));
        }
        Ok(list)
    };
    let critical = sorted(&template.critical_options)?;
    let extensions = sorted(&template.extensions)?;
    let principals: Vec<&str> = template.principals.iter().map(String::as_str).collect();
    let authority_key = authority.verifying_key();
    let mut out = signed_part(
        &nonce,
        &template.public,
        template.serial,
        template.kind,
        &template.key_id,
        &principals,
        template.valid_after,
        template.valid_before,
        &borrow(&critical),
        &borrow(&extensions),
        &authority_key,
    );
    let signature = authority
        .sign(&out)
        .map_err(|_| CertError::Issue("signature"))?;
    put_string(&mut out, &signature_blob(&signature));
    // What we issue must be what we accept.
    parse(&out).map_err(|_| CertError::Refused("modèle hors des bornes du format"))?;
    Ok(out)
}

fn borrow(list: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    list.iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect()
}

/// A canonical lowercase UUID, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let b = text.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut nibbles = b
        .iter()
        .enumerate()
        .filter(|(i, _)| !matches!(i, 8 | 13 | 18 | 23));
    if [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    for byte in &mut out {
        let mut value = 0u8;
        for _ in 0..2 {
            let (_, &c) = nibbles.next()?;
            let n = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => return None,
            };
            value = value << 4 | n;
        }
        *byte = value;
    }
    Some(out)
}

/// Canonical text of 16 UUID bytes.
pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Applies the policy of a user certificate, at `now` (Unix seconds),
/// after [`Certificate::verify`]: type user, exactly one principal (the
/// subject UUID), key identifier the login session UUID, no critical option
/// at all, no extension but `permit-pty` (any forwarding or `permit-user-rc`
/// refuses), valid now (start up to [`CLOCK_SKEW_SECS`] ahead), validity at
/// most [`MAX_USER_VALIDITY_SECS`].
///
/// # Errors
///
/// [`CertError::Refused`].
pub fn check_user(cert: &Certificate<'_>, now: u64) -> Result<UserIdentity, CertError> {
    if cert.kind != Kind::User {
        return Err(CertError::Refused(
            "certificat d'hôte présenté par un client",
        ));
    }
    let [principal] = cert.principals.as_slice() else {
        return Err(CertError::Refused("un et un seul principal attendu"));
    };
    let subject =
        parse_uuid(principal).ok_or(CertError::Refused("le principal n'est pas un UUID"))?;
    let login_session = parse_uuid(cert.key_id)
        .ok_or(CertError::Refused("l'identifiant de clé n'est pas un UUID"))?;
    if !cert.critical_options.is_empty() {
        return Err(CertError::Refused("option critique présente"));
    }
    let mut allow_pty = false;
    for (name, data) in &cert.extensions {
        if *name == PERMIT_PTY && data.is_empty() {
            allow_pty = true;
        } else {
            return Err(CertError::Refused(
                "extension interdite (redirection ou permit-user-rc)",
            ));
        }
    }
    check_dates(cert, now)?;
    if cert.valid_before - cert.valid_after > MAX_USER_VALIDITY_SECS {
        return Err(CertError::Refused("validité de plus de 8 heures"));
    }
    Ok(UserIdentity {
        subject,
        login_session,
        allow_pty,
        certificate_sha256: cert.sha256(),
    })
}

fn check_dates(cert: &Certificate<'_>, now: u64) -> Result<(), CertError> {
    if cert.valid_after >= cert.valid_before {
        return Err(CertError::Refused("période de validité vide"));
    }
    if cert.valid_after > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(CertError::Refused("pas encore valide"));
    }
    if now >= cert.valid_before {
        return Err(CertError::Refused("expiré"));
    }
    Ok(())
}

/// Applies the policy of the agent host certificate at `now`: type host,
/// for `host_key`, at least one principal, no critical option nor
/// extension, valid now.
///
/// # Errors
///
/// [`CertError::Refused`].
pub fn check_host(
    cert: &Certificate<'_>,
    host_key: &VerifyingKey,
    now: u64,
) -> Result<(), CertError> {
    if cert.kind != Kind::Host {
        return Err(CertError::Refused(
            "certificat d'utilisateur au lieu d'hôte",
        ));
    }
    if cert.public != *host_key {
        return Err(CertError::Refused("certificat d'une autre clé d'hôte"));
    }
    if cert.principals.is_empty() {
        return Err(CertError::Refused("aucun nom d'hôte"));
    }
    if !cert.critical_options.is_empty() || !cert.extensions.is_empty() {
        return Err(CertError::Refused(
            "option ou extension sur un certificat d'hôte",
        ));
    }
    check_dates(cert, now)
}

#[cfg(test)]
mod tests;
