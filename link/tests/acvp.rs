//! NIST ACVP known-answer tests (roadmap 1.5) for the cryptography CDK uses:
//! ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203), Ed25519 (FIPS 186-5) and
//! SHA-256 (FIPS 180-4).
//!
//! The vectors come from NIST's ACVP-Server repository; fetch them with
//! `tools/fetch_acvp_vectors.sh` (pinned commit, SHA-256-checked) into
//! `target/acvp/`. Without them these tests print a note and pass, unless
//! `CDK_ACVP_REQUIRED=1` (CI) makes a missing file a failure.
//!
//! The crates and versions are the ones the kernel links (checked by
//! `tools/check_crypto_versions.sh`); run with
//! `RUSTFLAGS='--cfg curve25519_dalek_backend="serial"'` to use the same
//! Ed25519 backend as the kernel. SHA-256 is forced to the portable
//! implementation (dev-dependency feature `force-soft`), as in the kernel.
//!
//! Every test case of the parameter sets CDK uses is run, except categories
//! CDK does not use and the crates do not implement (HashML-DSA pre-hash
//! signing); those are counted and reported as skipped.

use std::path::PathBuf;

use serde_json::Value;

fn dir() -> PathBuf {
    std::env::var_os("CDK_ACVP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/acvp")))
}

/// The vector set, or `None` (with a note) if it has not been fetched.
fn load(set: &str) -> Option<Value> {
    let path = dir().join(format!("{set}.json"));
    match std::fs::read(&path) {
        Ok(b) => Some(serde_json::from_slice(&b).expect("valid ACVP JSON")),
        Err(_) if std::env::var_os("CDK_ACVP_REQUIRED").is_none() => {
            eprintln!(
                "acvp: {} missing — run tools/fetch_acvp_vectors.sh (skipped)",
                path.display()
            );
            None
        }
        Err(e) => panic!("acvp: {}: {e} (CDK_ACVP_REQUIRED is set)", path.display()),
    }
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn groups<'a>(
    v: &'a Value,
    filter: impl Fn(&Value) -> bool + 'a,
) -> impl Iterator<Item = &'a Value> + 'a {
    v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |g| filter(g))
}

fn tests(g: &Value) -> &Vec<Value> {
    g["tests"].as_array().unwrap()
}

fn report(what: &str, passed: usize, skipped: &[(&str, usize)]) {
    let skipped: Vec<String> = skipped
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(why, n)| format!("{n} {why}"))
        .collect();
    eprintln!(
        "acvp: {what}: {passed} passed{}",
        if skipped.is_empty() {
            String::new()
        } else {
            format!("; skipped {}", skipped.join(", "))
        }
    );
    assert!(passed > 0, "{what}: no vectors ran");
}

/// Hands out NIST's fixed `rnd` for hedged signing.
struct FixedRng(Vec<u8>);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(dst.len(), self.0.len(), "rnd length");
        dst.copy_from_slice(&self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

mod ml_dsa_65 {
    use super::*;
    use ml_dsa::{
        signature::Keypair, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
        MlDsa65, Signature, SigningKey, VerifyingKey, B32,
    };

    /// μ (64 bytes); the crate's own alias is private.
    type B64 = ml_dsa::common::array::Array<u8, ml_dsa::common::array::typenum::U64>;

    const SET: &str = "ML-DSA-65";

    fn sk(t: &Value) -> ExpandedSigningKey<MlDsa65> {
        let b = hex(&t["sk"]);
        #[allow(deprecated)]
        ExpandedSigningKey::from_expanded(
            &ExpandedSigningKeyBytes::<MlDsa65>::try_from(b.as_slice()).unwrap(),
        )
    }

    fn vk(t: &Value) -> VerifyingKey<MlDsa65> {
        let b = hex(&t["pk"]);
        VerifyingKey::decode(&EncodedVerifyingKey::<MlDsa65>::try_from(b.as_slice()).unwrap())
    }

    #[test]
    fn key_gen() {
        let Some(v) = load("ML-DSA-keyGen-FIPS204") else {
            return;
        };
        let mut n = 0;
        for g in groups(&v, |g| g["parameterSet"] == SET) {
            for t in tests(g) {
                let seed = B32::try_from(hex(&t["seed"]).as_slice()).unwrap();
                let key = SigningKey::<MlDsa65>::from_seed(&seed);
                assert_eq!(
                    key.verifying_key().encode().as_slice(),
                    hex(&t["pk"]),
                    "tcId {}",
                    t["tcId"]
                );
                #[allow(deprecated)]
                let expanded = key.expanded_key().to_expanded();
                assert_eq!(expanded.as_slice(), hex(&t["sk"]), "tcId {}", t["tcId"]);
                n += 1;
            }
        }
        report("ML-DSA-65 keyGen", n, &[]);
    }

    #[test]
    fn sig_gen() {
        let Some(v) = load("ML-DSA-sigGen-FIPS204") else {
            return;
        };
        let (mut n, mut prehash) = (0, 0);
        for g in groups(&v, |g| g["parameterSet"] == SET) {
            let deterministic = g["deterministic"].as_bool().unwrap();
            let interface = g["signatureInterface"].as_str().unwrap();
            let external_mu = g["externalMu"].as_bool().unwrap_or(false);
            if g["preHash"] == "preHash" {
                prehash += tests(g).len();
                continue;
            }
            for t in tests(g) {
                let key = sk(t);
                let rnd = if deterministic {
                    vec![0u8; 32]
                } else {
                    hex(&t["rnd"])
                };
                let sig: Signature<MlDsa65> = match (interface, external_mu) {
                    ("external", _) => {
                        let (msg, ctx) = (hex(&t["message"]), hex(&t["context"]));
                        if deterministic {
                            key.sign_deterministic(&msg, &ctx).unwrap()
                        } else {
                            key.sign_randomized(&msg, &ctx, &mut FixedRng(rnd)).unwrap()
                        }
                    }
                    ("internal", true) => {
                        let mu = B64::try_from(hex(&t["mu"]).as_slice()).unwrap();
                        if deterministic {
                            key.sign_mu_deterministic(&mu)
                        } else {
                            key.sign_mu_randomized(&mu, &mut FixedRng(rnd)).unwrap()
                        }
                    }
                    ("internal", false) => {
                        let msg = hex(&t["message"]);
                        key.sign_internal(&[&msg], &B32::try_from(rnd.as_slice()).unwrap())
                    }
                    other => panic!("unknown interface {other:?}"),
                };
                assert_eq!(
                    sig.encode().as_slice(),
                    hex(&t["signature"]),
                    "tcId {} ({interface}, deterministic={deterministic}, externalMu={external_mu})",
                    t["tcId"]
                );
                n += 1;
            }
        }
        report(
            "ML-DSA-65 sigGen",
            n,
            &[("HashML-DSA (pre-hash, not used by CDK)", prehash)],
        );
    }

    #[test]
    fn sig_ver() {
        let Some(v) = load("ML-DSA-sigVer-FIPS204") else {
            return;
        };
        let (mut n, mut prehash) = (0, 0);
        for g in groups(&v, |g| g["parameterSet"] == SET) {
            let interface = g["signatureInterface"].as_str().unwrap();
            let external_mu = g["externalMu"].as_bool().unwrap_or(false);
            if g["preHash"] == "preHash" {
                prehash += tests(g).len();
                continue;
            }
            for t in tests(g) {
                let key = vk(t);
                let sig = Signature::<MlDsa65>::try_from(hex(&t["signature"]).as_slice()).ok();
                let ok = sig.is_some_and(|sig| match (interface, external_mu) {
                    ("external", _) => {
                        key.verify_with_context(&hex(&t["message"]), &hex(&t["context"]), &sig)
                    }
                    ("internal", true) => {
                        key.verify_mu(&B64::try_from(hex(&t["mu"]).as_slice()).unwrap(), &sig)
                    }
                    ("internal", false) => key.verify_internal(&hex(&t["message"]), &sig),
                    other => panic!("unknown interface {other:?}"),
                });
                assert_eq!(
                    ok,
                    t["testPassed"].as_bool().unwrap(),
                    "tcId {} ({})",
                    t["tcId"],
                    t["reason"]
                );
                n += 1;
            }
        }
        report(
            "ML-DSA-65 sigVer",
            n,
            &[("HashML-DSA (pre-hash, not used by CDK)", prehash)],
        );
    }
}

mod ml_kem_768 {
    use super::*;
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed, B32};

    const SET: &str = "ML-KEM-768";

    #[allow(deprecated)]
    fn dk(b: &[u8]) -> Result<DecapsulationKey<MlKem768>, ml_kem::InvalidKey> {
        match b.try_into() {
            Ok(arr) => DecapsulationKey::<MlKem768>::from_expanded_bytes(&arr),
            Err(_) => Err(ml_kem::InvalidKey),
        }
    }

    fn ek(b: &[u8]) -> Result<EncapsulationKey<MlKem768>, ml_kem::InvalidKey> {
        match b.try_into() {
            Ok(arr) => EncapsulationKey::<MlKem768>::new(&arr),
            Err(_) => Err(ml_kem::InvalidKey),
        }
    }

    #[test]
    fn key_gen() {
        let Some(v) = load("ML-KEM-keyGen-FIPS203") else {
            return;
        };
        let mut n = 0;
        for g in groups(&v, |g| g["parameterSet"] == SET) {
            for t in tests(g) {
                // CDK's link keys: DecapsulationKey::from_seed(d || z).
                let mut seed = hex(&t["d"]);
                seed.extend(hex(&t["z"]));
                let key = DecapsulationKey::<MlKem768>::from_seed(
                    Seed::try_from(seed.as_slice()).unwrap(),
                );
                assert_eq!(
                    key.encapsulation_key().to_bytes().as_slice(),
                    hex(&t["ek"]),
                    "tcId {}",
                    t["tcId"]
                );
                #[allow(deprecated)]
                let expanded = key.to_expanded_bytes();
                assert_eq!(expanded.as_slice(), hex(&t["dk"]), "tcId {}", t["tcId"]);
                n += 1;
            }
        }
        report("ML-KEM-768 keyGen", n, &[]);
    }

    #[test]
    fn encap_decap() {
        let Some(v) = load("ML-KEM-encapDecap-FIPS203") else {
            return;
        };
        let mut counts = [0usize; 4];
        for g in groups(&v, |g| g["parameterSet"] == SET) {
            let function = g["function"].as_str().unwrap();
            for t in tests(g) {
                let id = &t["tcId"];
                match function {
                    "encapsulation" => {
                        let key = ek(&hex(&t["ek"])).expect("valid ek");
                        let m = B32::try_from(hex(&t["m"]).as_slice()).unwrap();
                        let (c, k) = key.encapsulate_deterministic(&m);
                        assert_eq!(c.as_slice(), hex(&t["c"]), "tcId {id}");
                        assert_eq!(k.as_slice(), hex(&t["k"]), "tcId {id}");
                        counts[0] += 1;
                    }
                    "decapsulation" => {
                        let key = dk(&hex(&t["dk"])).expect("valid dk");
                        let c = hex(&t["c"]);
                        let k = key.decapsulate(c.as_slice().try_into().unwrap());
                        // Includes implicit-rejection cases (modified ciphertexts).
                        assert_eq!(k.as_slice(), hex(&t["k"]), "tcId {id} ({})", t["reason"]);
                        counts[1] += 1;
                    }
                    "encapsulationKeyCheck" => {
                        let ok = ek(&hex(&t["ek"])).is_ok();
                        assert_eq!(
                            ok,
                            t["testPassed"].as_bool().unwrap(),
                            "tcId {id} ({})",
                            t["reason"]
                        );
                        counts[2] += 1;
                    }
                    "decapsulationKeyCheck" => {
                        let ok = dk(&hex(&t["dk"])).is_ok();
                        assert_eq!(
                            ok,
                            t["testPassed"].as_bool().unwrap(),
                            "tcId {id} ({})",
                            t["reason"]
                        );
                        counts[3] += 1;
                    }
                    other => panic!("unknown function {other}"),
                }
            }
        }
        eprintln!(
            "acvp: ML-KEM-768: encapsulation {}, decapsulation {}, ek checks {}, dk checks {}",
            counts[0], counts[1], counts[2], counts[3]
        );
        report("ML-KEM-768 encapDecap", counts.iter().sum(), &[]);
    }
}

mod ed25519 {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha512};

    const CURVE: &str = "ED-25519";

    fn arr<const N: usize>(v: &Value) -> [u8; N] {
        hex(v).try_into().expect("length")
    }

    #[test]
    fn key_gen() {
        let Some(v) = load("EDDSA-KeyGen-1.0") else {
            return;
        };
        let mut n = 0;
        for g in groups(&v, |g| g["curve"] == CURVE) {
            for t in tests(g) {
                let key = SigningKey::from_bytes(&arr(&t["d"]));
                assert_eq!(
                    key.verifying_key().to_bytes().to_vec(),
                    hex(&t["q"]),
                    "tcId {}",
                    t["tcId"]
                );
                n += 1;
            }
        }
        report("Ed25519 keyGen", n, &[]);
    }

    #[test]
    fn sig_gen() {
        let Some(v) = load("EDDSA-SigGen-1.0") else {
            return;
        };
        let (mut pure, mut ph) = (0, 0);
        for g in groups(&v, |g| g["curve"] == CURVE) {
            let key = SigningKey::from_bytes(&arr(&g["d"]));
            assert_eq!(
                key.verifying_key().to_bytes().to_vec(),
                hex(&g["q"]),
                "group {}",
                g["tgId"]
            );
            for t in tests(g) {
                let msg = hex(&t["message"]);
                let sig = if g["preHash"].as_bool().unwrap() {
                    let ctx = hex(&t["context"]);
                    ph += 1;
                    key.sign_prehashed(Sha512::new().chain_update(&msg), Some(&ctx))
                        .unwrap()
                } else {
                    pure += 1; // what CDK uses
                    key.sign(&msg)
                };
                assert_eq!(
                    sig.to_bytes().to_vec(),
                    hex(&t["signature"]),
                    "tcId {}",
                    t["tcId"]
                );
            }
        }
        eprintln!("acvp: Ed25519 sigGen: pure {pure}, Ed25519ph {ph}");
        report("Ed25519 sigGen", pure + ph, &[]);
    }

    #[test]
    fn sig_ver() {
        let Some(v) = load("EDDSA-SigVer-1.0") else {
            return;
        };
        let mut n = 0;
        for g in groups(&v, |g| g["curve"] == CURVE) {
            let prehash = g["preHash"].as_bool().unwrap();
            for t in tests(g) {
                let sig = Signature::from_bytes(&arr(&t["signature"]));
                let msg = hex(&t["message"]);
                // CDK verifies with verify_strict.
                let ok = VerifyingKey::from_bytes(&arr(&t["q"])).is_ok_and(|vk| {
                    if prehash {
                        vk.verify_prehashed_strict(Sha512::new().chain_update(&msg), None, &sig)
                            .is_ok()
                    } else {
                        vk.verify_strict(&msg, &sig).is_ok()
                    }
                });
                assert_eq!(
                    ok,
                    t["testPassed"].as_bool().unwrap(),
                    "tcId {} ({})",
                    t["tcId"],
                    t["reason"]
                );
                n += 1;
            }
        }
        report("Ed25519 sigVer", n, &[]);
    }
}

mod sha256 {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn aft_and_mct() {
        let Some(v) = load("SHA2-256-1.0") else {
            return;
        };
        let (mut aft, mut mct, mut ldt) = (0, 0, 0);
        for g in groups(&v, |_| true) {
            match g["testType"].as_str().unwrap() {
                "AFT" => {
                    for t in tests(g) {
                        let msg = hex(&t["msg"]);
                        assert_eq!(msg.len() * 8, t["len"].as_u64().unwrap() as usize);
                        assert_eq!(
                            Sha256::digest(&msg).to_vec(),
                            hex(&t["md"]),
                            "tcId {}",
                            t["tcId"]
                        );
                        aft += 1;
                    }
                }
                "MCT" => {
                    assert_eq!(
                        g["mctVersion"], "alternate",
                        "only the alternate MCT is in this set"
                    );
                    for t in tests(g) {
                        mct += monte_carlo_alternate(
                            &hex(&t["msg"]),
                            t["resultsArray"].as_array().unwrap(),
                        );
                    }
                }
                "LDT" => ldt += tests(g).len(),
                other => panic!("unknown test type {other}"),
            }
        }
        eprintln!("acvp: SHA-256: AFT {aft}, MCT {mct} iterations");
        report(
            "SHA-256 AFT+MCT",
            aft + mct,
            &[("large-data (1–8 GiB, run with --ignored)", ldt)],
        );
    }

    /// ACVP SHA-2 Monte Carlo test, "alternate" version (message length need
    /// not equal the digest length): each message is A‖B‖C cut or zero-padded
    /// to the seed's length.
    fn monte_carlo_alternate(seed: &[u8], results: &[Value]) -> usize {
        let len = seed.len();
        let mut seed = seed.to_vec();
        for (i, r) in results.iter().enumerate() {
            let (mut a, mut b, mut c) = (seed.clone(), seed.clone(), seed.clone());
            let mut md = Vec::new();
            for _ in 0..1000 {
                let mut msg = [a.as_slice(), b.as_slice(), c.as_slice()].concat();
                msg.resize(len, 0);
                md = Sha256::digest(&msg).to_vec();
                a = b;
                b = c;
                c = md.clone();
            }
            assert_eq!(md, hex(&r["md"]), "MCT iteration {i}");
            seed = md;
        }
        results.len()
    }

    /// 1, 2, 4 and 8 GiB messages (a 64-bit pattern repeated). Slow; run
    /// with `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn large_data() {
        let Some(v) = load("SHA2-256-1.0") else {
            return;
        };
        let mut n = 0;
        for g in groups(&v, |g| g["testType"] == "LDT") {
            for t in tests(g) {
                let m = &t["largeMsg"];
                assert_eq!(m["expansionTechnique"], "repeating");
                let content = hex(&m["content"]);
                let full = m["fullLength"].as_u64().unwrap() / 8;
                let block: Vec<u8> = content.iter().copied().cycle().take(1 << 20).collect();
                let mut h = Sha256::new();
                let mut left = full;
                while left > 0 {
                    let k = left.min(block.len() as u64) as usize;
                    h.update(&block[..k]);
                    left -= k as u64;
                }
                assert_eq!(h.finalize().to_vec(), hex(&t["md"]), "tcId {}", t["tcId"]);
                n += 1;
            }
        }
        report("SHA-256 LDT", n, &[]);
    }
}
