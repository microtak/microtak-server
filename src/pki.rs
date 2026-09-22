//! Certificate authority: CA generation and CSR signing.
//!
//! Implements the server side of the enrollment flow described in
//! `docs/TEST-PLAN.md` §4 — a client submits a CSR, this module signs it
//! against EdgeTAK's own CA. Does not implement the Marti
//! `/Marti/api/tls/*` HTTP contract itself (Content-Type strictness,
//! per-client response shaping, etc. — see TC-ENROLL-02/03/07) — that's a
//! thin HTTP layer on top of [`CertificateAuthority::sign_csr`], not yet
//! built.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, DnValue, Issuer, IsCa, KeyPair, KeyUsagePurpose,
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

    /// Sign a PEM-encoded PKCS#10 certificate signing request, issuing a
    /// leaf certificate valid for `validity` from now.
    ///
    /// Returns [`PkiError::CsrParse`] for a malformed/non-CSR payload
    /// (TC-ENROLL-06) and [`PkiError::MissingCommonName`] if the CSR's
    /// subject has no CN to bind an identity to.
    pub fn sign_csr(
        &self,
        csr_pem: &str,
        validity: Duration,
    ) -> Result<SignedCertificate, PkiError> {
        let mut csr_params =
            CertificateSigningRequestParams::from_pem(csr_pem).map_err(PkiError::CsrParse)?;

        let common_name = common_name_of(&csr_params.params.distinguished_name)
            .ok_or(PkiError::MissingCommonName)?;

        csr_params.params.not_before = OffsetDateTime::now_utc();
        csr_params.params.not_after = OffsetDateTime::now_utc() + validity;

        let cert = csr_params
            .signed_by(&self.issuer)
            .map_err(PkiError::Signing)?;

        Ok(SignedCertificate {
            cert_pem: cert.pem(),
            common_name,
        })
    }
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
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn signs_a_valid_csr() {
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
        let (csr_pem, _key) = build_csr("device-alpha").unwrap();

        let signed = ca.sign_csr(&csr_pem, Duration::days(365)).unwrap();
        assert_eq!(signed.common_name, "device-alpha");
        assert!(signed.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn tc_enroll_06_rejects_malformed_csr() {
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
        let result = ca.sign_csr("not a csr at all", Duration::days(365));
        assert!(matches!(result, Err(PkiError::CsrParse(_))));
    }

    #[test]
    fn signing_two_csrs_produces_different_certificates() {
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
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
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
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

        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
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
    fn rejects_csr_with_no_common_name() {
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
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
