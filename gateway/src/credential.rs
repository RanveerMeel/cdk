//! `TPM2_MakeCredential` in software (TPM 2.0 Part 1 §24, Part 4
//! `CryptSecretEncrypt` for ECC): a secret only the TPM holding a given
//! endorsement key *and* a given object (the AK, by name) can recover with
//! `TPM2_ActivateCredential`.
//!
//! For an ECC P-256 EK (template L-2: SHA-256, AES-128-CFB):
//!
//! ```text
//! (d_e, Q_e) ephemeral;  Z = (d_e · Q_EK).x
//! seed       = KDFe(SHA-256, Z, "IDENTITY", Q_e.x, Q_EK.x, 256)
//! encSecret  = TPMS_ECC_POINT Q_e
//! symKey     = KDFa(SHA-256, seed, "STORAGE", name(AK), ∅, 128)
//! encIdentity= AES-128-CFB(symKey, IV = 0, TPM2B_DIGEST credential)
//! hmacKey    = KDFa(SHA-256, seed, "INTEGRITY", ∅, ∅, 256)
//! idObject   = TPM2B(HMAC-SHA-256(hmacKey, encIdentity ‖ name(AK))) ‖ encIdentity
//! ```

use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// KDFa (SP 800-108 counter mode with HMAC; TPM 2.0 Part 1 §11.4.10.2).
/// `label` excludes the terminating NUL, which is added here.
pub fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes + 32);
    let mut counter = 1u32;
    while out.len() < bytes {
        let mut h = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
        h.update(&counter.to_be_bytes());
        h.update(label.as_bytes());
        h.update(&[0]);
        h.update(context_u);
        h.update(context_v);
        h.update(&bits.to_be_bytes());
        out.extend_from_slice(&h.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// KDFe (SP 800-56A concatenation KDF; TPM 2.0 Part 1 §11.4.10.3).
pub fn kdfe(z: &[u8], label: &str, party_u: &[u8], party_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes + 32);
    let mut counter = 1u32;
    while out.len() < bytes {
        let mut h = Sha256::new();
        h.update(counter.to_be_bytes());
        h.update(z);
        h.update(label.as_bytes());
        h.update([0]);
        h.update(party_u);
        h.update(party_v);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// AES-128 in CFB-128 mode with a zero IV (encryption).
fn aes128_cfb_encrypt(key: &[u8], data: &mut [u8]) {
    let cipher = aes::Aes128::new_from_slice(key).expect("16-byte key");
    let mut feedback = [0u8; 16];
    for chunk in data.chunks_mut(16) {
        let mut block = feedback.into();
        cipher.encrypt_block(&mut block);
        for (d, k) in chunk.iter_mut().zip(block.iter()) {
            *d ^= k;
        }
        feedback[..chunk.len()].copy_from_slice(chunk);
    }
}

/// `TPM2_MakeCredential` for the P-256 endorsement key `(ek_x, ek_y)` and
/// the object named `name`. Returns the bodies of `TPM2B_ID_OBJECT` and
/// `TPM2B_ENCRYPTED_SECRET`.
pub fn make_credential(
    ek_x: &[u8; 32],
    ek_y: &[u8; 32],
    name: &[u8],
    credential: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use ring::agreement;
    let mut ek_point = vec![4u8];
    ek_point.extend_from_slice(ek_x);
    ek_point.extend_from_slice(ek_y);
    let rng = ring::rand::SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(|_| "no randomness")?;
    let q_e = ephemeral
        .compute_public_key()
        .map_err(|_| "ephemeral key")?;
    let q_e = q_e.as_ref(); // 04 ‖ x ‖ y
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &ek_point);
    let z = agreement::agree_ephemeral(ephemeral, &peer, |z| z.to_vec())
        .map_err(|_| "the endorsement key is not a valid P-256 point")?;
    let seed = kdfe(&z, "IDENTITY", &q_e[1..33], ek_x, 256);

    let mut secret = Vec::with_capacity(68);
    secret.extend_from_slice(&32u16.to_be_bytes());
    secret.extend_from_slice(&q_e[1..33]);
    secret.extend_from_slice(&32u16.to_be_bytes());
    secret.extend_from_slice(&q_e[33..65]);

    let sym_key = kdfa(&seed, "STORAGE", name, &[], 128);
    let mut enc_identity = Vec::with_capacity(2 + credential.len());
    enc_identity.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    enc_identity.extend_from_slice(credential);
    aes128_cfb_encrypt(&sym_key, &mut enc_identity);

    let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], 256);
    let mut h = <HmacSha256 as Mac>::new_from_slice(&hmac_key).expect("any key length");
    h.update(&enc_identity);
    h.update(name);
    let outer = h.finalize().into_bytes();

    let mut id_object = Vec::with_capacity(2 + 32 + enc_identity.len());
    id_object.extend_from_slice(&32u16.to_be_bytes());
    id_object.extend_from_slice(&outer);
    id_object.extend_from_slice(&enc_identity);
    Ok((id_object, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ActivateCredential's side, as the TPM does it, for the round trip.
    fn activate(
        ek_secret: &p256::SecretKey,
        name: &[u8],
        id: &[u8],
        secret: &[u8],
    ) -> Option<Vec<u8>> {
        use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        let x: [u8; 32] = secret.get(2..34)?.try_into().ok()?;
        let y: [u8; 32] = secret.get(36..68)?.try_into().ok()?;
        let q_e = p256::PublicKey::from_encoded_point(
            &p256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false),
        );
        let q_e = Option::<p256::PublicKey>::from(q_e)?;
        let z = p256::ecdh::diffie_hellman(ek_secret.to_nonzero_scalar(), q_e.as_affine());
        let ek_pub = ek_secret.public_key().to_encoded_point(false);
        let seed = kdfe(z.raw_secret_bytes(), "IDENTITY", &x, ek_pub.x()?, 256);
        let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], 256);
        let outer = id.get(2..34)?;
        let enc = id.get(34..)?;
        let mut h = <HmacSha256 as Mac>::new_from_slice(&hmac_key).ok()?;
        h.update(enc);
        h.update(name);
        h.verify_slice(outer).ok()?;
        // CFB decryption: keystream from the previous ciphertext block.
        let sym = kdfa(&seed, "STORAGE", name, &[], 128);
        let cipher = aes::Aes128::new_from_slice(&sym).ok()?;
        let mut out = enc.to_vec();
        let mut feedback = [0u8; 16];
        for chunk in out.chunks_mut(16) {
            let mut block = feedback.into();
            cipher.encrypt_block(&mut block);
            let n = chunk.len();
            feedback[..n].copy_from_slice(chunk);
            for (d, k) in chunk.iter_mut().zip(block.iter()) {
                *d ^= k;
            }
        }
        let len = u16::from_be_bytes(out.get(..2)?.try_into().ok()?) as usize;
        Some(out.get(2..2 + len)?.to_vec())
    }

    #[test]
    fn make_then_activate_round_trip() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let ek = p256::SecretKey::from_bytes(&[3u8; 32].into()).unwrap();
        let p = ek.public_key().to_encoded_point(false);
        let (x, y): ([u8; 32], [u8; 32]) = (
            p.x().unwrap().as_slice().try_into().unwrap(),
            p.y().unwrap().as_slice().try_into().unwrap(),
        );
        let name = cdk_link::tpm::name(&cdk_link::tpm::ak_public(Some((&[1; 32], &[2; 32]))));
        let (id, secret) = make_credential(&x, &y, &name, &[0xAB; 32]).unwrap();
        assert_eq!((id.len(), secret.len()), (2 + 32 + 2 + 32, 68));
        assert_eq!(activate(&ek, &name, &id, &secret), Some(vec![0xAB; 32]));
        // Bound to the AK's name: another object cannot recover it.
        let other = cdk_link::tpm::name(b"other");
        assert_eq!(activate(&ek, &other, &id, &secret), None);
        // And to the EK: another TPM cannot.
        let ek2 = p256::SecretKey::from_bytes(&[4u8; 32].into()).unwrap();
        assert_eq!(activate(&ek2, &name, &id, &secret), None);
    }

    #[test]
    fn kdfa_matches_the_tpm_reference() {
        // Same construction as the reference TPM's CryptKDFa: the first
        // block is HMAC(key, 00000001 ‖ label ‖ 00 ‖ u ‖ v ‖ bits).
        let mut h = <HmacSha256 as Mac>::new_from_slice(b"k").unwrap();
        h.update(&[0, 0, 0, 1]);
        h.update(b"STORAGE\0uv");
        h.update(&128u32.to_be_bytes());
        let want = h.finalize().into_bytes();
        assert_eq!(kdfa(b"k", "STORAGE", b"u", b"v", 128), want[..16]);
        assert_eq!(kdfa(b"k", "X", &[], &[], 512).len(), 64);
    }
}
