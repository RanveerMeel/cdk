//! Published test vectors for the link's non-NIST primitives (roadmap 1.5;
//! NIST ACVP has no vectors for these): HKDF-SHA256 (RFC 5869), X25519
//! (RFC 7748) and ChaCha20-Poly1305 (RFC 8439).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn hkdf_sha256_rfc5869() {
    // A.1: basic test case.
    let ikm = [0x0b; 22];
    let salt = h("000102030405060708090a0b0c");
    let info = h("f0f1f2f3f4f5f6f7f8f9");
    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(
        prk.to_vec(),
        h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );

    // A.3: zero-length salt and info.
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    hk.expand(&[], &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn x25519_rfc7748() {
    // §5.2: scalar multiplication.
    let k: [u8; 32] = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        .try_into()
        .unwrap();
    let u: [u8; 32] = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        .try_into()
        .unwrap();
    assert_eq!(
        x25519_dalek::x25519(k, u).to_vec(),
        h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );

    // §6.1: Diffie-Hellman.
    let a = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(h(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ))
        .unwrap(),
    );
    let b = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(h(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ))
        .unwrap(),
    );
    let (pa, pb) = (
        x25519_dalek::PublicKey::from(&a),
        x25519_dalek::PublicKey::from(&b),
    );
    assert_eq!(
        pa.as_bytes().to_vec(),
        h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        pb.as_bytes().to_vec(),
        h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(a.diffie_hellman(&pb).as_bytes().to_vec(), shared);
    assert_eq!(b.diffie_hellman(&pa).as_bytes().to_vec(), shared);
}

#[test]
fn chacha20_poly1305_rfc8439() {
    // §2.8.2: AEAD construction example.
    let key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = h("070000004041424344454647");
    let aad = h("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut buf)
        .unwrap();
    assert_eq!(buf[..16].to_vec(), h("d31a8d34648e60db7b86afbc53ef7ec2"));
    assert_eq!(tag.to_vec(), h("1ae10b594f09e26a7e902ecbd0600691"));
    cipher
        .decrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut buf, &tag)
        .unwrap();
    assert_eq!(buf, plaintext);
}
