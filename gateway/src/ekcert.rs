//! TPM endorsement-key certificates (roadmap 4.2): just enough X.509 to
//! check that an EK certificate chains to a TPM manufacturer's CA.
//!
//! * A minimal DER reader (definite lengths only, every length bounded).
//! * [`Certificate::parse`]: the to-be-signed bytes, signature algorithm and
//!   value, issuer/subject names (compared as raw DER), public key, and the
//!   basicConstraints / extendedKeyUsage extensions.
//! * [`TrustStore::verify`]: walk issuer links through the store's
//!   certificates to a self-signed root, checking each signature (RSA
//!   PKCS#1 v1.5 or ECDSA, SHA-256/384/512, verified by `ring`) and that
//!   every issuer is a CA. Validity dates and revocation are not checked:
//!   TPMs routinely outlive their EK certificates, and vendors do not publish
//!   revocation for them.

use std::path::Path;

use base64::Engine as _;

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_RSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_RSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// tcg-kp-EKCertificate (2.23.133.8.1).
const OID_TCG_EK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const CONTEXT_0: u8 = 0xA0;
const CONTEXT_3: u8 = 0xA3;

/// One DER element: tag, contents, and the whole encoding.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

/// Read one element from the front of `b`; returns it and the rest.
fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    if tag & 0x1F == 0x1F {
        return None; // high tag numbers do not occur in certificates
    }
    let first = *b.get(1)?;
    let (len, hdr) = match first {
        0..=0x7F => (first as usize, 2),
        0x81..=0x83 => {
            let n = (first & 0x7F) as usize;
            let mut len = 0usize;
            for &x in b.get(2..2 + n)? {
                len = (len << 8) | x as usize;
            }
            (len, 2 + n)
        }
        _ => return None, // indefinite or absurd lengths
    };
    let end = hdr.checked_add(len)?;
    let value = b.get(hdr..end)?;
    Some((
        Tlv {
            tag,
            value,
            raw: &b[..end],
        },
        &b[end..],
    ))
}

/// Read an element that must have `tag`.
fn expect(b: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (t, rest) = tlv(b)?;
    (t.tag == tag).then_some((t, rest))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// Uncompressed point (`04 ‖ x ‖ y`).
    P256(Vec<u8>),
    P384(Vec<u8>),
    /// `RSAPublicKey` DER.
    Rsa(Vec<u8>),
    Other,
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub der: Vec<u8>,
    tbs: (usize, usize),
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub key: PublicKey,
    pub is_ca: bool,
    /// Carries the TCG EK-certificate extended key usage.
    pub ek_usage: bool,
}

impl Certificate {
    pub fn parse(der: &[u8]) -> Option<Certificate> {
        let (cert, rest) = expect(der, SEQUENCE)?;
        if !rest.is_empty() {
            return None;
        }
        let (tbs, r) = expect(cert.value, SEQUENCE)?;
        let (alg, r) = expect(r, SEQUENCE)?;
        let (sig, r) = expect(r, BIT_STRING)?;
        if !r.is_empty() || sig.value.first() != Some(&0) {
            return None;
        }
        let sig_alg = expect(alg.value, OID)?.0.value.to_vec();

        // TBSCertificate
        let mut r = tbs.value;
        if r.first() == Some(&CONTEXT_0) {
            r = tlv(r)?.1; // version
        }
        let (_, r) = expect(r, INTEGER)?; // serial
        let (inner_alg, r) = expect(r, SEQUENCE)?;
        if expect(inner_alg.value, OID)?.0.value != sig_alg.as_slice() {
            return None;
        }
        let (issuer, r) = expect(r, SEQUENCE)?;
        let (_, r) = expect(r, SEQUENCE)?; // validity
        let (subject, r) = expect(r, SEQUENCE)?;
        let (spki, mut r) = expect(r, SEQUENCE)?;
        let key = parse_spki(spki.value)?;
        let (mut is_ca, mut ek_usage) = (false, false);
        while let Some((t, rest)) = tlv(r) {
            if t.tag == CONTEXT_3 {
                let (exts, _) = expect(t.value, SEQUENCE)?;
                let mut e = exts.value;
                while !e.is_empty() {
                    let (ext, rest) = expect(e, SEQUENCE)?;
                    e = rest;
                    let (oid, mut x) = expect(ext.value, OID)?;
                    if x.first() == Some(&BOOLEAN) {
                        x = tlv(x)?.1; // critical
                    }
                    let (val, _) = expect(x, OCTET_STRING)?;
                    if oid.value == OID_BASIC_CONSTRAINTS {
                        let (bc, _) = expect(val.value, SEQUENCE)?;
                        is_ca = matches!(tlv(bc.value), Some((t, _)) if t.tag == BOOLEAN && t.value == [0xFF]);
                    } else if oid.value == OID_EXT_KEY_USAGE {
                        let (eku, _) = expect(val.value, SEQUENCE)?;
                        let mut u = eku.value;
                        while let Some((o, rest)) = expect(u, OID) {
                            ek_usage |= o.value == OID_TCG_EK_CERTIFICATE;
                            u = rest;
                        }
                    }
                }
            }
            r = rest;
        }
        let start = tbs.raw.as_ptr() as usize - der.as_ptr() as usize;
        Some(Certificate {
            der: der.to_vec(),
            tbs: (start, start + tbs.raw.len()),
            sig_alg,
            signature: sig.value[1..].to_vec(),
            issuer: issuer.raw.to_vec(),
            subject: subject.raw.to_vec(),
            key,
            is_ca,
            ek_usage,
        })
    }

    fn tbs(&self) -> &[u8] {
        &self.der[self.tbs.0..self.tbs.1]
    }

    /// Whether `issuer`'s key signed this certificate.
    pub fn signed_by(&self, issuer: &Certificate) -> bool {
        use ring::signature as s;
        let alg: &dyn s::VerificationAlgorithm = match (self.sig_alg.as_slice(), &issuer.key) {
            (OID_RSA_SHA256, PublicKey::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA256,
            (OID_RSA_SHA384, PublicKey::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA384,
            (OID_RSA_SHA512, PublicKey::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA512,
            (OID_ECDSA_SHA256, PublicKey::P256(_)) => &s::ECDSA_P256_SHA256_ASN1,
            (OID_ECDSA_SHA384, PublicKey::P256(_)) => &s::ECDSA_P256_SHA384_ASN1,
            (OID_ECDSA_SHA256, PublicKey::P384(_)) => &s::ECDSA_P384_SHA256_ASN1,
            (OID_ECDSA_SHA384, PublicKey::P384(_)) => &s::ECDSA_P384_SHA384_ASN1,
            _ => return false,
        };
        let key = match &issuer.key {
            PublicKey::P256(k) | PublicKey::P384(k) | PublicKey::Rsa(k) => k,
            PublicKey::Other => return false,
        };
        s::UnparsedPublicKey::new(alg, key)
            .verify(self.tbs(), &self.signature)
            .is_ok()
    }

    /// The subject's common name, for log messages.
    pub fn common_name(&self) -> String {
        // Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
        let cn = [0x55, 0x04, 0x03];
        let mut out = String::new();
        if let Some((name, _)) = expect(&self.subject, SEQUENCE) {
            let mut r = name.value;
            while let Some((set, rest)) = expect(r, SET) {
                if let Some((atv, _)) = expect(set.value, SEQUENCE) {
                    if let Some((oid, v)) = expect(atv.value, OID) {
                        if oid.value == cn {
                            if let Some((val, _)) = tlv(v) {
                                out = String::from_utf8_lossy(val.value).into_owned();
                            }
                        }
                    }
                }
                r = rest;
            }
        }
        if out.is_empty() {
            "(no common name)".into()
        } else {
            out
        }
    }
}

fn parse_spki(b: &[u8]) -> Option<PublicKey> {
    let (alg, r) = expect(b, SEQUENCE)?;
    let (bits, _) = expect(r, BIT_STRING)?;
    let key = bits.value.strip_prefix(&[0])?.to_vec();
    let (oid, params) = expect(alg.value, OID)?;
    Some(if oid.value == OID_EC_PUBLIC_KEY {
        let curve = expect(params, OID)?.0.value;
        match (curve, key.len()) {
            (OID_P256, 65) => PublicKey::P256(key),
            (OID_P384, 97) => PublicKey::P384(key),
            _ => PublicKey::Other,
        }
    } else if oid.value == OID_RSA {
        PublicKey::Rsa(key)
    } else {
        PublicKey::Other
    })
}

/// Decode PEM (any number of `CERTIFICATE` blocks) or a single DER cert.
pub fn decode_certs(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return vec![data.to_vec()];
    };
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        return vec![data.to_vec()];
    }
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some(body) = block.split("-----END CERTIFICATE-----").next() else {
            continue;
        };
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push(der);
        }
    }
    out
}

/// TPM manufacturer CA certificates: self-signed roots, and intermediates
/// that are used only to build a path to one of those roots.
pub struct TrustStore {
    certs: Vec<Certificate>,
}

impl TrustStore {
    /// Load every certificate (PEM or DER) from a file or a directory.
    pub fn load(path: &Path) -> Result<TrustStore, String> {
        let files: Vec<std::path::PathBuf> = if path.is_dir() {
            let mut v: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .collect();
            v.sort();
            v
        } else {
            vec![path.to_path_buf()]
        };
        let mut certs = Vec::new();
        for f in files {
            let data = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            for der in decode_certs(&data) {
                match Certificate::parse(&der) {
                    Some(c) => certs.push(c),
                    None => eprintln!("gateway: {}: not a certificate, ignored", f.display()),
                }
            }
        }
        let store = TrustStore::from_certs(certs);
        if store.roots().count() == 0 {
            return Err(format!(
                "{}: no self-signed root CA certificate",
                path.display()
            ));
        }
        Ok(store)
    }

    pub fn from_certs(certs: Vec<Certificate>) -> TrustStore {
        TrustStore { certs }
    }

    fn roots(&self) -> impl Iterator<Item = &Certificate> {
        self.certs
            .iter()
            .filter(|c| c.is_ca && c.subject == c.issuer && c.signed_by(c))
    }

    pub fn len(&self) -> (usize, usize) {
        let roots = self.roots().count();
        (roots, self.certs.len() - roots)
    }

    /// Verify that `ek` chains to a root. Returns the common names of the
    /// path (EK certificate first, root last).
    pub fn verify(&self, ek: &Certificate) -> Result<Vec<String>, String> {
        let mut path = vec![ek.common_name()];
        let mut current = ek.clone();
        for _ in 0..4 {
            let issuer = self
                .certs
                .iter()
                .find(|c| c.is_ca && c.subject == current.issuer && current.signed_by(c))
                .ok_or_else(|| {
                    format!(
                        "no trusted CA signed '{}' (chain so far: {})",
                        current.common_name(),
                        path.join(" <- ")
                    )
                })?;
            path.push(issuer.common_name());
            if issuer.subject == issuer.issuer && issuer.signed_by(issuer) {
                return Ok(path);
            }
            current = issuer.clone();
        }
        Err(format!("certificate chain too long: {}", path.join(" <- ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A software TPM's EK certificate and its manufacturer CA, made by
    // tools/tpm_manufacture.sh (swtpm_localca): root -> EK CA -> EK cert.
    const ROOT: &[u8] = include_bytes!("../tests/data/tpm-ca-root.pem");
    const ISSUER: &[u8] = include_bytes!("../tests/data/tpm-ca-issuer.pem");
    const EK: &[u8] = include_bytes!("../tests/data/ek-p256.der");
    const OTHER_ROOT: &[u8] = include_bytes!("../tests/data/other-root.pem");

    fn cert(pem: &[u8]) -> Certificate {
        Certificate::parse(&decode_certs(pem)[0]).unwrap()
    }

    #[test]
    fn parses_a_tpm_ek_certificate() {
        let ek = Certificate::parse(EK).unwrap();
        assert!(ek.ek_usage, "TCG EK extended key usage");
        assert!(!ek.is_ca);
        assert!(matches!(&ek.key, PublicKey::P256(k) if k[0] == 4));
        assert!(cert(ROOT).is_ca && cert(ISSUER).is_ca);
    }

    #[test]
    fn chain_to_the_manufacturer_root() {
        let ek = Certificate::parse(EK).unwrap();
        let store = TrustStore::from_certs(vec![cert(ROOT), cert(ISSUER)]);
        assert_eq!(store.len(), (1, 1));
        let path = store.verify(&ek).unwrap();
        assert_eq!(path.len(), 3);

        // Without the intermediate, or with another vendor's root: refused.
        assert!(TrustStore::from_certs(vec![cert(ROOT)])
            .verify(&ek)
            .is_err());
        assert!(TrustStore::from_certs(vec![cert(OTHER_ROOT)])
            .verify(&ek)
            .is_err());
        // An intermediate alone is not a trust anchor.
        assert!(TrustStore::from_certs(vec![cert(ISSUER)])
            .verify(&ek)
            .is_err());

        // A forged EK certificate (one bit of the key changed): refused.
        let PublicKey::P256(key) = &ek.key else {
            panic!("P-256 EK")
        };
        let at = EK.windows(key.len()).position(|w| w == key).unwrap();
        let mut forged = EK.to_vec();
        forged[at + 10] ^= 1;
        let f = Certificate::parse(&forged).unwrap();
        assert_ne!(f.key, ek.key);
        assert!(store.verify(&f).is_err());
    }

    #[test]
    fn malformed_input_is_rejected_not_panicking() {
        for n in 0..EK.len() {
            let _ = Certificate::parse(&EK[..n]);
        }
        assert!(Certificate::parse(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_none());
        assert!(Certificate::parse(&[]).is_none());
        let mut trailing = EK.to_vec();
        trailing.push(0);
        assert!(Certificate::parse(&trailing).is_none());
    }
}
