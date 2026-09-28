//! Certificate authority: CA generation and CSR signing.
//!
//! Implements the server side of the enrollment flow described in
//! `docs/TEST-PLAN.md` §4 — a client submits a CSR, this module signs it
//! against MicroTAK's own CA. Does not implement the Marti
//! `/Marti/api/tls/*` HTTP contract itself (Content-Type strictness,
//! per-client response shaping, etc. — see TC-ENROLL-02/03/07) — that's a
//! thin HTTP layer on top of [`CertificateAuthority::sign_csr`], not yet
//! built.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, DnValue, ExtendedKeyUsagePurpose, Issuer, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("failed to generate key pair: {0}")]
    KeyGeneration(rcgen::Error),
    #[error("failed to build certificate parameters: {0}")]
    Params(rcgen::Error),
    #[error("failed to self-sign CA certificate: {0}")]
    SelfSign(rcgen::Error),
    #[error("failed to load CA key or certificate: {0}")]
    Load(rcgen::Error),
    #[error("failed to parse CSR: {0}")]
    CsrParse(rcgen::Error),
    #[error("CSR has no usable Common Name in its subject")]
    MissingCommonName,
    #[error("failed to sign certificate: {0}")]
    Signing(rcgen::Error),
    #[error("failed to parse PEM: {0}")]
    Pem(#[from] pem::PemError),
}

/// A self-signed certificate authority: holds its own key pair and can sign
/// incoming CSRs.
pub struct CertificateAuthority {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    /// Generate a brand-new, self-signed CA with the given Common Name.
    pub fn generate(common_name: &str) -> Result<Self, PkiError> {
        let key = KeyPair::generate().map_err(PkiError::KeyGeneration)?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);

        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(PkiError::Params)?;
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);

        let cert = params.self_signed(&key).map_err(PkiError::SelfSign)?;
        let cert_pem = cert.pem();
        let issuer = Issuer::new(params, key);

        Ok(Self { cert_pem, issuer })
    }

    /// Load an existing CA from its PEM-encoded certificate and private key
    /// (e.g. persisted from a previous run).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(key_pem).map_err(PkiError::Load)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key).map_err(PkiError::Load)?;
        Ok(Self {
            cert_pem: cert_pem.to_string(),
            issuer,
        })
    }

    /// The CA's own certificate, PEM-encoded. Serve this at the enrollment
    /// config endpoint (TC-ENROLL-01) and as the client truststore.
    pub fn ca_cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// The CA's private key, PEM-encoded. Never serve this over the
    /// network — persist it locally only.
    pub fn ca_key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// Sign a PEM-encoded PKCS#10 certificate signing request from an
    /// enrolling *client*, issuing a leaf certificate valid for `validity`
    /// from now.
    ///
    /// Only two things are taken from the CSR: its public key (whose
    /// possession the CSR's own signature proves -- `rcgen` verifies it
    /// while parsing) and its subject Common Name, which becomes the
    /// device's identity. **Everything else the CSR requests is ignored**
    /// -- the issued cert always carries the fixed client profile below,
    /// never a CA flag, certificate-signing key usage, server-auth EKU, or
    /// SANs. Signing requested extensions as-is (the previous behaviour)
    /// let any enrolling client obtain a subordinate CA and forge any
    /// identity, the admin's included (TC-ENROLL-11/12).
    ///
    /// Returns [`PkiError::CsrParse`] for a malformed/non-CSR payload
    /// (TC-ENROLL-06) and [`PkiError::MissingCommonName`] if the CSR's
    /// subject has no CN to bind an identity to.
    pub fn sign_csr(
        &self,
        csr_pem: &str,
        validity: Duration,
    ) -> Result<SignedCertificate, PkiError> {
        self.sign_with_profile(csr_pem, validity, CertProfile::Client)
    }

    /// Like [`Self::sign_csr`], but issuing a *server* certificate: EKU
    /// `serverAuth`, with exactly the given names as SANs (taken from the
    /// server's own configuration, never from the CSR) -- each an IP
    /// address SAN if it parses as one, a DNS SAN otherwise. Only for
    /// MicroTAK's own listener certificates -- never reachable from
    /// enrollment.
    pub fn sign_server_csr(
        &self,
        csr_pem: &str,
        dns_names: &[String],
        validity: Duration,
    ) -> Result<SignedCertificate, PkiError> {
        self.sign_with_profile(csr_pem, validity, CertProfile::Server(dns_names))
    }

    fn sign_with_profile(
        &self,
        csr_pem: &str,
        validity: Duration,
        profile: CertProfile<'_>,
    ) -> Result<SignedCertificate, PkiError> {
        let requested =
            CertificateSigningRequestParams::from_pem(csr_pem).map_err(PkiError::CsrParse)?;

        let common_name = common_name_of(&requested.params.distinguished_name)
            .ok_or(PkiError::MissingCommonName)?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.as_str());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial_number());
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + validity;
        match profile {
            CertProfile::Client => {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            }
            CertProfile::Server(dns_names) => {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
                params.subject_alt_names = dns_names
                    .iter()
                    .map(|name| match name.parse::<std::net::IpAddr>() {
                        Ok(ip) => Ok(SanType::IpAddress(ip)),
                        Err(_) => name
                            .clone()
                            .try_into()
                            .map(SanType::DnsName)
                            .map_err(PkiError::Params),
                    })
                    .collect::<Result<_, _>>()?;
            }
        }

        let issued = CertificateSigningRequestParams {
            params,
            public_key: requested.public_key,
        };
        let cert = issued.signed_by(&self.issuer).map_err(PkiError::Signing)?;

        Ok(SignedCertificate {
            cert_pem: cert.pem(),
            common_name,
        })
    }
}

enum CertProfile<'a> {
    Client,
    Server(&'a [String]),
}

/// A random, positive 128-bit serial number (RFC 5280 allows up to 20
/// octets; the top bit is cleared so the DER INTEGER stays positive).
/// Without this, `rcgen` derives the serial from the public key, so a
/// device re-enrolling with the same key would get a duplicate serial.
fn random_serial_number() -> SerialNumber {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes[0] &= 0x7f;
    SerialNumber::from_slice(&bytes)
}

/// The result of a successful CSR signing.
#[derive(Debug, Clone)]
pub struct SignedCertificate {
    pub cert_pem: String,
    /// The Common Name from the CSR's subject, carried forward for
    /// convenience (e.g. to bind connection identity later — see
    /// `docs/TEST-PLAN.md` TC-TLS-04, not yet implemented).
    pub common_name: String,
}

fn common_name_of(dn: &DistinguishedName) -> Option<String> {
    match dn.get(&DnType::CommonName)? {
        DnValue::Utf8String(s) => Some(s.clone()),
        DnValue::PrintableString(s) => Some(s.as_str().to_string()),
        DnValue::Ia5String(s) => Some(s.as_str().to_string()),
        DnValue::TeletexString(s) => Some(s.as_str().to_string()),
        _ => None,
    }
}

/// Decode a PEM-encoded certificate (CA or leaf) to DER, for handing to
/// `rustls`.
pub fn cert_pem_to_der(pem_str: &str) -> Result<CertificateDer<'static>, PkiError> {
    let parsed = pem::parse(pem_str)?;
    Ok(CertificateDer::from(parsed.contents().to_vec()))
}

/// The SHA-256 fingerprint of a PEM-encoded certificate's DER bytes,
/// formatted as uppercase colon-separated hex (`AA:BB:CC:...`) — matching
/// Node's `crypto.X509Certificate.fingerprint256`, since that's what a real
/// `node-tak` client computes locally and sends us for a
/// `GET /Marti/api/certadmin/cert/:hash` lookup (see `marti::admin`).
pub fn fingerprint_sha256_colon_hex(cert_pem: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let der = cert_pem_to_der(cert_pem).ok()?;
    let digest = Sha256::digest(der.as_ref());
    let hex_pairs: Vec<String> = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    Some(hex_pairs.join(":"))
}

/// Extract the Common Name from a DER-encoded certificate, e.g. an mTLS
/// peer certificate presented during a handshake. Shared by
/// `transport::tls` and `marti::MtlsHttpServer` — one identity-extraction
/// implementation, not two.
pub fn common_name_from_cert_der(der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

/// Build a PEM-encoded CSR for the given Common Name, for use in tests and
/// as a reference client-side implementation.
pub fn build_csr(common_name: &str) -> Result<(String, KeyPair), PkiError> {
    build_csr_with_san(common_name, Vec::new())
}

/// Like [`build_csr`], but also requesting the given DNS Subject
/// Alternative Names — needed for a *server* cert, since TLS clients verify
/// server identity against SAN, not CN (RFC 6125). A client-auth cert
/// doesn't need this (client-cert verification doesn't check hostname).
pub fn build_csr_with_san(
    common_name: &str,
    dns_names: Vec<String>,
) -> Result<(String, KeyPair), PkiError> {
    let key = KeyPair::generate().map_err(PkiError::KeyGeneration)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    let mut params = CertificateParams::new(dns_names).map_err(PkiError::Params)?;
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key).map_err(PkiError::Signing)?;
    let pem = csr.pem().map_err(PkiError::Signing)?;
    Ok((pem, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_self_signed_ca() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn signs_a_valid_csr() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr_pem, _key) = build_csr("device-alpha").unwrap();

        let signed = ca.sign_csr(&csr_pem, Duration::days(365)).unwrap();
        assert_eq!(signed.common_name, "device-alpha");
        assert!(signed.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn tc_enroll_06_rejects_malformed_csr() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let result = ca.sign_csr("not a csr at all", Duration::days(365));
        assert!(matches!(result, Err(PkiError::CsrParse(_))));
    }

    #[test]
    fn signing_two_csrs_produces_different_certificates() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr_a, _key_a) = build_csr("device-a").unwrap();
        let (csr_b, _key_b) = build_csr("device-b").unwrap();

        let signed_a = ca.sign_csr(&csr_a, Duration::days(365)).unwrap();
        let signed_b = ca.sign_csr(&csr_b, Duration::days(365)).unwrap();

        assert_ne!(signed_a.cert_pem, signed_b.cert_pem);
        assert_eq!(signed_a.common_name, "device-a");
        assert_eq!(signed_b.common_name, "device-b");
    }

    #[test]
    fn ca_survives_a_reload_round_trip_and_can_still_sign() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let cert_pem = ca.ca_cert_pem();
        let key_pem = ca.ca_key_pem();

        let reloaded = CertificateAuthority::from_pem(&cert_pem, &key_pem).unwrap();
        assert_eq!(reloaded.ca_cert_pem(), cert_pem);

        let (csr_pem, _key) = build_csr("device-after-reload").unwrap();
        let signed = reloaded
            .sign_csr(&csr_pem, Duration::days(365))
            .expect("reloaded CA should still be able to sign");
        assert_eq!(signed.common_name, "device-after-reload");
    }

    /// Strongest possible test here: actually cryptographically verify the
    /// signed leaf certificate's signature against the CA's public key, and
    /// confirm the issuer/subject chain is correct -- not just "no error
    /// was thrown."
    #[test]
    fn signed_certificate_is_cryptographically_verifiable_against_the_ca() {
        use x509_parser::prelude::{FromDer, X509Certificate};

        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr_pem, _key) = build_csr("device-verify").unwrap();
        let signed = ca.sign_csr(&csr_pem, Duration::days(365)).unwrap();

        let ca_der = pem::parse(ca.ca_cert_pem()).unwrap();
        let (_, ca_x509) = X509Certificate::from_der(ca_der.contents()).unwrap();

        let leaf_der = pem::parse(&signed.cert_pem).unwrap();
        let (_, leaf_x509) = X509Certificate::from_der(leaf_der.contents()).unwrap();

        assert_eq!(leaf_x509.issuer(), ca_x509.subject());
        assert!(
            leaf_x509
                .verify_signature(Some(ca_x509.public_key()))
                .is_ok(),
            "leaf certificate's signature must verify against the CA's public key"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_distinguishes_different_certs() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr_a, _key_a) = build_csr("device-a").unwrap();
        let (csr_b, _key_b) = build_csr("device-b").unwrap();
        let signed_a = ca.sign_csr(&csr_a, Duration::days(365)).unwrap();
        let signed_b = ca.sign_csr(&csr_b, Duration::days(365)).unwrap();

        let fp_a1 = fingerprint_sha256_colon_hex(&signed_a.cert_pem).unwrap();
        let fp_a2 = fingerprint_sha256_colon_hex(&signed_a.cert_pem).unwrap();
        let fp_b = fingerprint_sha256_colon_hex(&signed_b.cert_pem).unwrap();

        assert_eq!(fp_a1, fp_a2, "the same cert must always fingerprint the same");
        assert_ne!(fp_a1, fp_b);
        assert_eq!(fp_a1.len(), 32 * 3 - 1, "32 hex-pair groups joined by colons");
        assert!(fp_a1.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
        assert_eq!(fp_a1, fp_a1.to_uppercase());
    }

    /// A CSR asking for everything a client cert must never carry: CA
    /// status, certificate-signing key usage, server-auth EKU, and SANs.
    fn malicious_csr(common_name: &str) -> String {
        use rcgen::{ExtendedKeyUsagePurpose, SanType};
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params
            .subject_alt_names
            .push(SanType::IpAddress("10.0.0.1".parse().unwrap()));
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    fn parse_leaf(cert_pem: &str) -> Vec<u8> {
        pem::parse(cert_pem).unwrap().contents().to_vec()
    }

    /// TC-ENROLL-11/12: whatever a CSR requests, the issued client cert
    /// carries only the fixed client profile -- a CSR asking for CA status
    /// must never produce a subordinate CA (which could then mint a cert
    /// for any identity, the admin included, or a server cert every
    /// CA-pinned client would accept).
    #[test]
    fn tc_enroll_11_12_issued_client_cert_ignores_requested_extensions() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::prelude::{FromDer, X509Certificate};

        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let signed = ca
            .sign_csr(&malicious_csr("device-evil"), Duration::days(365))
            .unwrap();
        assert_eq!(signed.common_name, "device-evil");

        let der = parse_leaf(&signed.cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        let basic_constraints = cert.basic_constraints().unwrap().map(|bc| bc.value.ca);
        assert_ne!(basic_constraints, Some(true), "a client cert must never be a CA");

        let key_usage = cert.key_usage().unwrap().expect("client certs carry an explicit KeyUsage");
        assert!(key_usage.value.digital_signature());
        assert!(!key_usage.value.key_cert_sign(), "no certificate signing");
        assert!(!key_usage.value.crl_sign());

        let eku = cert
            .extended_key_usage()
            .unwrap()
            .expect("client certs carry an explicit EKU");
        assert!(eku.value.client_auth);
        assert!(!eku.value.server_auth, "a client cert must not be usable as a server cert");
        assert!(!eku.value.any);

        let has_san = cert
            .extensions()
            .iter()
            .any(|ext| matches!(ext.parsed_extension(), ParsedExtension::SubjectAlternativeName(_)));
        assert!(!has_san, "client certs carry no SANs, whatever the CSR asked for");
    }

    /// Two certs issued for the same public key (e.g. a device re-enrolling
    /// with its existing key) must still get distinct serial numbers.
    #[test]
    fn issued_certs_get_distinct_random_serials_even_for_the_same_key() {
        use x509_parser::prelude::{FromDer, X509Certificate};

        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr_pem, _key) = build_csr("device-same-key").unwrap();
        let first = ca.sign_csr(&csr_pem, Duration::days(365)).unwrap();
        let second = ca.sign_csr(&csr_pem, Duration::days(365)).unwrap();

        let first_der = parse_leaf(&first.cert_pem);
        let second_der = parse_leaf(&second.cert_pem);
        let (_, a) = X509Certificate::from_der(&first_der).unwrap();
        let (_, b) = X509Certificate::from_der(&second_der).unwrap();
        assert_ne!(a.raw_serial(), b.raw_serial());
    }

    /// The server profile carries `serverAuth` and exactly the configured
    /// DNS names -- not SANs the CSR asked for, and never CA status.
    #[test]
    fn server_cert_carries_server_auth_and_only_the_configured_names() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        use x509_parser::prelude::{FromDer, X509Certificate};

        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let signed = ca
            .sign_server_csr(
                &malicious_csr("microtak-server"),
                &["microtak-server".to_string()],
                Duration::days(365),
            )
            .unwrap();
        let der = parse_leaf(&signed.cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        assert_ne!(cert.basic_constraints().unwrap().map(|bc| bc.value.ca), Some(true));
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth);
        assert!(!eku.value.client_auth);

        let names: Vec<String> = cert
            .extensions()
            .iter()
            .filter_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .flat_map(|san| san.general_names.iter())
            .map(|name| match name {
                GeneralName::DNSName(dns) => dns.to_string(),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["microtak-server".to_string()]);
    }

    /// TC-TLS-09: configured names that are IP addresses become IP SANs
    /// (what a client connecting to a bare LAN IP checks against), the
    /// rest DNS SANs.
    #[test]
    fn server_cert_names_become_ip_or_dns_sans() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        use x509_parser::prelude::{FromDer, X509Certificate};

        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let (csr, _key) = build_csr("microtak-server").unwrap();
        let signed = ca
            .sign_server_csr(
                &csr,
                &["microtak-server".to_string(), "192.168.1.10".to_string(), "fd00::1".to_string()],
                Duration::days(1),
            )
            .unwrap();
        let der = parse_leaf(&signed.cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let sans: Vec<String> = cert
            .extensions()
            .iter()
            .filter_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .flat_map(|san| san.general_names.iter())
            .map(|name| match name {
                GeneralName::DNSName(dns) => format!("dns:{dns}"),
                GeneralName::IPAddress(bytes) => format!("ip:{}", bytes.len()),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(sans, vec!["dns:microtak-server", "ip:4", "ip:16"]);
    }

    #[test]
    fn rejects_csr_with_no_common_name() {
        let ca = CertificateAuthority::generate("MicroTAK Test CA").unwrap();
        let key = KeyPair::generate().unwrap();
        // `CertificateParams::new` defaults to a placeholder CN -- remove it
        // to exercise a CSR whose subject genuinely has none.
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.remove(DnType::CommonName);
        let csr = params.serialize_request(&key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let result = ca.sign_csr(&csr_pem, Duration::days(365));
        assert!(matches!(result, Err(PkiError::MissingCommonName)));
    }
}
