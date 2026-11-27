//! A local time-stamping authority (tests and feature `testing` only): a
//! root and a time-stamping certificate made at once, and tokens built by
//! the RFC 3161 rules, so that everything is tested offline, in CI too.

use ::aws_lc_rs::rand::SystemRandom;
use ::aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::CertificateDer;

use super::der::{Reader, tag, write};
use super::{TsaTrust, oid};

/// Policy OID of the test authority: 1.3.6.1.4.1.99999.3161.
pub const POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x98, 0x59];

/// What to change in a token, to test refusals.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools, reason = "independent test switches")]
pub struct TokenOptions {
    /// Leave the certificates out of the token.
    pub omit_certificates: bool,
    /// Leave the `signingCertificateV2` attribute out.
    pub omit_signing_certificate: bool,
    /// Put a SHA-1 `signingCertificate` attribute instead.
    pub sha1_signing_certificate: bool,
    /// Another digest algorithm OID in the imprint and the signer.
    pub digest_algorithm: Option<Vec<u8>>,
    /// Sign another `TSTInfo` than the one carried.
    pub sign_other_content: bool,
    /// An accuracy of this many seconds.
    pub accuracy_secs: Option<u8>,
}

/// The test authority. No `Debug`.
pub struct TestTsa {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: EcdsaKeyPair,
    serial: std::sync::atomic::AtomicU64,
}

fn named(cn: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl TestTsa {
    /// A new authority whose certificates are valid from yesterday for 30
    /// days; its time-stamping certificate has the critical extended key
    /// usage `timeStamping` alone.
    ///
    /// # Panics
    ///
    /// If a certificate cannot be made (test only).
    pub fn new() -> Self {
        Self::with_eku(true)
    }

    /// The same, the extended key usage critical or not.
    ///
    /// # Panics
    ///
    /// If a certificate cannot be made (test only).
    #[allow(clippy::unwrap_used, reason = "test authority")]
    pub fn with_eku(critical: bool) -> Self {
        let validity = |params: &mut CertificateParams| {
            params.not_before = time::OffsetDateTime::from_unix_timestamp(
                i64::try_from(now()).unwrap_or(0) - 86_400,
            )
            .unwrap();
            params.not_after = time::OffsetDateTime::from_unix_timestamp(
                i64::try_from(now()).unwrap_or(0) + 30 * 86_400,
            )
            .unwrap();
        };
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = named("Ostena test TSA root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        validity(&mut root_params);
        let root = root_params.self_signed(&root_key).unwrap().der().clone();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = named("Ostena test TSA");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // extKeyUsage = SEQUENCE { id-kp-timeStamping }
        let mut eku = CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            write::sequence(&[&write::oid(oid::TIME_STAMPING)]),
        );
        eku.set_criticality(critical);
        leaf_params.custom_extensions = vec![eku];
        validity(&mut leaf_params);
        let issuer = Issuer::from_params(&root_params, &root_key);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .clone();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &leaf_key.serialize_der())
                .unwrap();
        Self {
            root,
            leaf,
            key,
            serial: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Trust in the root of this authority.
    ///
    /// # Panics
    ///
    /// Never for a test authority.
    #[allow(clippy::unwrap_used, reason = "test authority")]
    pub fn trust(&self) -> TsaTrust {
        TsaTrust::new(vec![self.root.clone()]).unwrap()
    }

    /// The root certificate, PEM.
    pub fn root_pem(&self) -> String {
        crate::pki::pem_certificate(&self.root)
    }

    /// The time-stamping certificate (DER).
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.leaf
    }

    /// The granted response to a `TimeStampReq` (DER), stamped at
    /// `gen_time_ms`, or a refusal (status 2) for a request it cannot read.
    pub fn respond(&self, request: &[u8], gen_time_ms: u64) -> Vec<u8> {
        match read_request(request) {
            Some((digest, nonce)) => {
                let token = self.token(
                    &digest,
                    nonce.as_deref(),
                    gen_time_ms,
                    &TokenOptions::default(),
                );
                granted(&token)
            }
            None => refusal(2),
        }
    }

    /// A token for `digest`, with `nonce` (INTEGER content) if any.
    ///
    /// # Panics
    ///
    /// If signing fails (test only).
    #[allow(clippy::unwrap_used, reason = "test authority")]
    pub fn token(
        &self,
        digest: &[u8; 32],
        nonce: Option<&[u8]>,
        gen_time_ms: u64,
        options: &TokenOptions,
    ) -> Vec<u8> {
        let digest_oid = options.digest_algorithm.as_deref().unwrap_or(oid::SHA256);
        let algorithm = write::sequence(&[&write::oid(digest_oid)]);
        let serial = self
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes();
        let imprint = write::sequence(&[&algorithm, &write::octets(digest)]);
        let accuracy = options
            .accuracy_secs
            .map(|s| write::sequence(&[&write::unsigned(&[s])]))
            .unwrap_or_default();
        let nonce = nonce
            .map(|n| write::element(tag::INTEGER, n))
            .unwrap_or_default();
        let tst_info = write::sequence(&[
            &write::unsigned(&[1]),
            &write::oid(POLICY),
            &imprint,
            &write::unsigned(&serial),
            &write::element(
                tag::GENERALIZED_TIME,
                generalized_time(gen_time_ms).as_bytes(),
            ),
            &accuracy,
            &nonce,
        ]);
        let signed_content = if options.sign_other_content {
            let mut other = tst_info.clone();
            if let Some(last) = other.last_mut() {
                *last ^= 1;
            }
            other
        } else {
            tst_info.clone()
        };
        let attribute = |id: &[u8], value: &[u8]| {
            write::sequence(&[&write::oid(id), &write::element(tag::SET, value)])
        };
        let mut attrs = vec![
            attribute(oid::CONTENT_TYPE, &write::oid(oid::TST_INFO)),
            attribute(
                oid::MESSAGE_DIGEST,
                &write::octets(&crate::sha256::digest(&signed_content)),
            ),
        ];
        let cert_hash = crate::sha256::digest(&self.leaf);
        if options.sha1_signing_certificate {
            attrs.push(attribute(
                oid::SIGNING_CERTIFICATE,
                &write::sequence(&[&write::sequence(&[&write::sequence(&[&write::octets(
                    &cert_hash[..20],
                )])])]),
            ));
        } else if !options.omit_signing_certificate {
            attrs.push(attribute(
                oid::SIGNING_CERTIFICATE_V2,
                &write::sequence(&[&write::sequence(&[&write::sequence(&[&write::octets(
                    &cert_hash,
                )])])]),
            ));
        }
        // DER: the elements of a SET OF in increasing order.
        attrs.sort();
        let attrs = attrs.concat();
        let signature = self
            .key
            .sign(&SystemRandom::new(), &write::element(tag::SET, &attrs))
            .unwrap();
        let (issuer, leaf_serial) = issuer_and_serial(&self.leaf);
        let signer_info = write::sequence(&[
            &write::unsigned(&[1]),
            &write::sequence(&[issuer, &write::element(tag::INTEGER, leaf_serial)]),
            &algorithm,
            &write::element(tag::context(0), &attrs),
            &write::sequence(&[&write::oid(oid::ECDSA_SHA256)]),
            &write::octets(signature.as_ref()),
        ]);
        let certificates = if options.omit_certificates {
            Vec::new()
        } else {
            write::element(tag::context(0), &self.leaf)
        };
        let signed_data = write::sequence(&[
            &write::unsigned(&[3]),
            &write::element(tag::SET, &algorithm),
            &write::sequence(&[
                &write::oid(oid::TST_INFO),
                &write::element(tag::context(0), &write::octets(&tst_info)),
            ]),
            &certificates,
            &write::element(tag::SET, &signer_info),
        ]);
        write::sequence(&[
            &write::oid(oid::SIGNED_DATA),
            &write::element(tag::context(0), &signed_data),
        ])
    }
}

impl Default for TestTsa {
    fn default() -> Self {
        Self::new()
    }
}

/// A granted `TimeStampResp` around `token`.
pub fn granted(token: &[u8]) -> Vec<u8> {
    write::sequence(&[&write::sequence(&[&write::unsigned(&[0])]), token])
}

/// A refused `TimeStampResp` with `status`.
pub fn refusal(status: u8) -> Vec<u8> {
    write::sequence(&[&write::sequence(&[
        &write::unsigned(&[status]),
        &write::sequence(&[&write::element(tag::UTF8_STRING, b"refus de test")]),
    ])])
}

/// The digest and the nonce (INTEGER content) of a `TimeStampReq`.
fn read_request(request: &[u8]) -> Option<([u8; 32], Option<Vec<u8>>)> {
    let mut outer = Reader::new(request);
    let mut req = outer.nested(tag::SEQUENCE, "req").ok()?;
    req.small("version").ok()?;
    let mut imprint = req.nested(tag::SEQUENCE, "imprint").ok()?;
    imprint.expect(tag::SEQUENCE, "alg").ok()?;
    let digest = <[u8; 32]>::try_from(imprint.expect(tag::OCTET_STRING, "hash").ok()?).ok()?;
    let _policy = req.optional(tag::OID).ok()?;
    let nonce = req.optional(tag::INTEGER).ok()?.map(<[u8]>::to_vec);
    Some((digest, nonce))
}

/// The issuer (whole) and serial number (content) of a certificate.
fn issuer_and_serial(cert: &[u8]) -> (&[u8], &[u8]) {
    let parsed = (|| {
        let mut outer = Reader::new(cert);
        let mut c = outer.nested(tag::SEQUENCE, "c").ok()?;
        let mut tbs = c.nested(tag::SEQUENCE, "tbs").ok()?;
        tbs.optional(tag::context(0)).ok()?;
        let serial = tbs.integer("serial").ok()?;
        tbs.expect(tag::SEQUENCE, "alg").ok()?;
        let (_, issuer) = tbs.expect_whole(tag::SEQUENCE, "issuer").ok()?;
        Some((issuer, serial))
    })();
    parsed.unwrap_or((&[], &[]))
}

/// `YYYYMMDDHHMMSS[.fff]Z`, without trailing zeros in the fraction.
pub fn generalized_time(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let mut text = format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    let frac = ms % 1000;
    if frac != 0 {
        let f = format!("{frac:03}");
        text.push('.');
        text.push_str(f.trim_end_matches('0'));
    }
    text.push('Z');
    text
}

fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
