//! Kernel capability issuer: a hybrid Ed25519 + ML-DSA-65 signing identity.
//!
//! Capability tokens are only meaningful if they are verified against a key
//! the verifier already trusts. The kernel generates one [`Issuer`] at boot
//! and pins its public half; tokens signed by any other key are rejected, no
//! matter what they carry.
//!
//! ## Hybrid signatures
//!
//! Every signature is a pair: Ed25519 (classical, RFC 8032) and ML-DSA-65
//! (post-quantum, FIPS 204, NIST security category 3). [`IssuerPublic::verify`]
//! accepts only when **both** verify, so forging a token requires breaking
//! both schemes — a future quantum computer (Shor) breaks Ed25519 but not
//! ML-DSA, and an undiscovered flaw in the newer lattice scheme would not
//! break Ed25519.
//!
//! Both signatures are deterministic. Every signature is made for one
//! [`SigDomain`] (capability tokens, audit checkpoints, ...): the ML-DSA half
//! carries the domain's FIPS 204 context string and callers prefix their
//! digests per domain, so a signature from one domain never verifies in
//! another.
//!
//! ## Crypto stack
//!
//! ML-DSA-65 needs far more stack than any kernel stack provides (measured on
//! the host: ~280 KiB for key generation, ~100 KiB to sign, ~66 KiB to verify;
//! the boot stack is 100 KiB and per-CPU interrupt/syscall stacks are 16 KiB).
//! Every issuer operation therefore runs on a dedicated [`crypto_stack`], so it
//! is safe to call from any kernel context. Operations are serialized.

extern crate alloc;

use alloc::boxed::Box;

use ed25519_dalek::Signer;
use ml_dsa::{signature::Keypair, EncodedSignature, EncodedVerifyingKey, MlDsa65, B32};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use spin::Once;
use zeroize::Zeroize;

use crate::rng::{self, EntropySource, KernelRng};

pub const ED25519_SIG_LEN: usize = 64;
pub const ED25519_KEY_LEN: usize = 32;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub const MLDSA65_KEY_LEN: usize = 1952;
pub const ISSUER_ID_LEN: usize = 16;

const ISSUER_ID_DOMAIN: &[u8] = b"CDK-ISSUER-v1";

/// What a signature is for. Each domain has its own FIPS 204 context string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigDomain {
    /// Capability token proofs.
    Capability,
    /// Audit-log checkpoints.
    AuditCheckpoint,
}

impl SigDomain {
    /// FIPS 204 context string for the ML-DSA half.
    pub const fn mldsa_context(self) -> &'static [u8] {
        match self {
            SigDomain::Capability => b"CDK-CAP-v1",
            SigDomain::AuditCheckpoint => b"CDK-AUDIT-v1",
        }
    }
}

/// Short, stable fingerprint of an issuer's public keys.
pub type IssuerId = [u8; ISSUER_ID_LEN];

/// A hybrid signature: both halves must verify.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519: [u8; ED25519_SIG_LEN],
    /// Boxed: 3.3 KB would otherwise be copied on every token clone/move.
    pub mldsa65: Box<[u8; MLDSA65_SIG_LEN]>,
}

impl core::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSignature").finish_non_exhaustive()
    }
}

/// The public half of an issuer: enough to verify its tokens anywhere.
#[derive(Clone)]
pub struct IssuerPublic {
    pub id: IssuerId,
    pub ed25519: [u8; ED25519_KEY_LEN],
    pub mldsa65: Box<[u8; MLDSA65_KEY_LEN]>,
}

impl IssuerPublic {
    /// Verify a hybrid signature over a 32-byte message digest.
    ///
    /// Decodes the ML-DSA key on every call; the kernel's own issuer uses
    /// [`Issuer::verify`], which reuses a pre-decoded key.
    pub fn verify(&self, domain: SigDomain, digest: &[u8; 32], sig: &HybridSignature) -> bool {
        crypto_stack::run(|| {
            let Ok(ml_key) = EncodedVerifyingKey::<MlDsa65>::try_from(&self.mldsa65[..]) else {
                return false;
            };
            let ml_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&ml_key);
            verify_ed25519(&self.ed25519, digest, sig) && verify_mldsa(&ml_vk, domain, digest, sig)
        })
    }
}

/// A signing identity. Secret keys never leave this struct.
pub struct Issuer {
    ed: ed25519_dalek::SigningKey,
    ml: Box<ml_dsa::SigningKey<MlDsa65>>,
    /// Pre-decoded ML-DSA verifying key (expanding it is the costly part).
    ml_vk: Box<ml_dsa::VerifyingKey<MlDsa65>>,
    public: IssuerPublic,
    entropy: EntropySource,
}

impl Issuer {
    /// Build an issuer from two independent 32-byte seeds.
    pub fn from_seeds(ed_seed: &[u8; 32], ml_seed: &[u8; 32], entropy: EntropySource) -> Self {
        crypto_stack::run(|| Self::from_seeds_inner(ed_seed, ml_seed, entropy))
    }

    fn from_seeds_inner(ed_seed: &[u8; 32], ml_seed: &[u8; 32], entropy: EntropySource) -> Self {
        let ed = ed25519_dalek::SigningKey::from_bytes(ed_seed);
        let mut ml_seed_arr = B32::from(*ml_seed);
        let ml = Box::new(ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_seed_arr));
        ml_seed_arr.zeroize();
        let ml_vk = Box::new(ml.verifying_key());

        let ed_pub = ed.verifying_key().to_bytes();
        let mut ml_pub = Box::new([0u8; MLDSA65_KEY_LEN]);
        ml_pub.copy_from_slice(&ml_vk.encode());
        let id = issuer_id(&ed_pub, &ml_pub);

        Self {
            ed,
            ml,
            ml_vk,
            public: IssuerPublic {
                id,
                ed25519: ed_pub,
                mldsa65: ml_pub,
            },
            entropy,
        }
    }

    /// Generate a fresh issuer from the kernel RNG.
    pub fn generate() -> Self {
        let mut ed_seed = [0u8; 32];
        let mut ml_seed = [0u8; 32];
        KernelRng.fill_bytes(&mut ed_seed);
        KernelRng.fill_bytes(&mut ml_seed);
        let issuer = Self::from_seeds(&ed_seed, &ml_seed, rng::entropy_source());
        ed_seed.zeroize();
        ml_seed.zeroize();
        issuer
    }

    pub fn public(&self) -> &IssuerPublic {
        &self.public
    }

    pub fn id(&self) -> &IssuerId {
        &self.public.id
    }

    /// Entropy source the keys were generated from.
    pub fn entropy(&self) -> EntropySource {
        self.entropy
    }

    /// Hybrid-sign a 32-byte message digest for `domain` (deterministic).
    pub fn sign(&self, domain: SigDomain, digest: &[u8; 32]) -> HybridSignature {
        crypto_stack::run(|| self.sign_inner(domain, digest))
    }

    fn sign_inner(&self, domain: SigDomain, digest: &[u8; 32]) -> HybridSignature {
        let ed = self.ed.sign(digest).to_bytes();
        let ml = self
            .ml
            .expanded_key()
            .sign_deterministic(digest, domain.mldsa_context())
            .expect("context string is under 255 bytes");
        let mut mldsa65 = Box::new([0u8; MLDSA65_SIG_LEN]);
        mldsa65.copy_from_slice(&ml.encode());
        HybridSignature {
            ed25519: ed,
            mldsa65,
        }
    }

    /// Verify a hybrid signature made by this issuer for `domain`.
    pub fn verify(&self, domain: SigDomain, digest: &[u8; 32], sig: &HybridSignature) -> bool {
        crypto_stack::run(|| {
            verify_ed25519(&self.public.ed25519, digest, sig)
                && verify_mldsa(&self.ml_vk, domain, digest, sig)
        })
    }
}

fn verify_ed25519(key: &[u8; ED25519_KEY_LEN], digest: &[u8; 32], sig: &HybridSignature) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
    // Strict verification rejects small-order keys and malleable signatures.
    vk.verify_strict(digest, &sig).is_ok()
}

fn verify_mldsa(
    vk: &ml_dsa::VerifyingKey<MlDsa65>,
    domain: SigDomain,
    digest: &[u8; 32],
    sig: &HybridSignature,
) -> bool {
    let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(&sig.mldsa65[..]) else {
        return false;
    };
    let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&enc) else {
        return false;
    };
    vk.verify_with_context(digest, domain.mldsa_context(), &sig)
}

/// `SHA-256("CDK-ISSUER-v1" ‖ ed25519_pub ‖ mldsa65_pub)[..16]`.
pub fn issuer_id(ed_pub: &[u8; ED25519_KEY_LEN], ml_pub: &[u8; MLDSA65_KEY_LEN]) -> IssuerId {
    let mut h = Sha256::new();
    h.update(ISSUER_ID_DOMAIN);
    h.update(ed_pub);
    h.update(ml_pub);
    let digest = h.finalize();
    let mut id = [0u8; ISSUER_ID_LEN];
    id.copy_from_slice(&digest[..ISSUER_ID_LEN]);
    id
}

/// A dedicated, large stack for post-quantum operations.
pub mod crypto_stack {
    /// Size of the crypto stack: the measured ML-DSA-65 key-generation peak
    /// (~280 KiB on the host) plus generous headroom.
    pub const SIZE: usize = 512 * 1024;

    #[cfg(target_os = "none")]
    mod imp {
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use spin::Mutex;

        use super::SIZE;

        const PAINT: u8 = 0xC5;

        #[repr(C, align(16))]
        struct Stack([u8; SIZE]);
        static mut STACK: Stack = Stack([0; SIZE]);
        static LOCK: Mutex<()> = Mutex::new(());
        static PAINTED: AtomicBool = AtomicBool::new(false);
        /// Peak usage seen so far (scrubbing re-paints, so it can't be rescanned).
        static PEAK: AtomicUsize = AtomicUsize::new(0);

        core::arch::global_asm!(
            r#"
            // void cdk_call_on_stack(void *arg, void (*f)(void *), void *stack_top)
            .global cdk_call_on_stack
            .type cdk_call_on_stack, @function
            cdk_call_on_stack:
                push rbp
                mov rbp, rsp
                mov rsp, rdx
                call rsi
                mov rsp, rbp
                pop rbp
                ret
            "#
        );

        unsafe extern "C" {
            fn cdk_call_on_stack(arg: *mut u8, f: extern "C" fn(*mut u8), stack_top: *mut u8);
        }

        extern "C" fn trampoline(arg: *mut u8) {
            // SAFETY: `arg` is the `&mut &mut dyn FnMut()` built in `run`.
            let f = unsafe { &mut *(arg as *mut &mut dyn FnMut()) };
            f();
        }

        fn bounds() -> (usize, usize) {
            let base = (&raw const STACK) as usize;
            (base, base + SIZE)
        }

        fn on_crypto_stack() -> bool {
            let rsp: usize;
            unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack)) };
            let (lo, hi) = bounds();
            rsp >= lo && rsp < hi
        }

        pub fn run<R>(f: impl FnOnce() -> R) -> R {
            if on_crypto_stack() {
                // Nested call (already switched): just run it; the outer
                // call scrubs.
                return f();
            }
            let _guard = LOCK.lock();
            if !PAINTED.swap(true, Ordering::AcqRel) {
                // SAFETY: the lock is held and nothing runs on the stack yet.
                unsafe { core::ptr::write_bytes((&raw mut STACK) as *mut u8, PAINT, SIZE) };
            }
            let mut f = Some(f);
            let mut out = None;
            let mut call = || out = Some((f.take().expect("called once"))());
            let mut dyn_call: &mut dyn FnMut() = &mut call;
            let top = bounds().1 as *mut u8;
            // SAFETY: the crypto stack is exclusively ours while `LOCK` is held;
            // `top` is 16-byte aligned; the callee returns on the same stack.
            unsafe { cdk_call_on_stack((&mut dyn_call) as *mut _ as *mut u8, trampoline, top) };
            let used = used_bytes();
            PEAK.fetch_max(used, Ordering::AcqRel);
            // Overwrite everything the operation touched so no key material
            // or intermediates remain on the stack between operations.
            let (_, hi) = bounds();
            // SAFETY: lock held; the region [hi-used, hi) is no longer live.
            unsafe { core::ptr::write_bytes((hi - used) as *mut u8, PAINT, used) };
            out.expect("crypto closure ran")
        }

        /// Bytes below the top that no longer hold the paint pattern.
        fn used_bytes() -> usize {
            let (lo, _) = bounds();
            // SAFETY: called with LOCK held, after the operation returned.
            let bytes = unsafe { core::slice::from_raw_parts(lo as *const u8, SIZE) };
            SIZE - bytes.iter().take_while(|&&b| b == PAINT).count()
        }

        pub fn high_water() -> usize {
            PEAK.load(Ordering::Acquire)
        }

        pub fn residue() -> usize {
            if !PAINTED.load(Ordering::Acquire) {
                return 0;
            }
            let _guard = LOCK.lock();
            used_bytes()
        }
    }

    #[cfg(not(target_os = "none"))]
    mod imp {
        pub fn run<R>(f: impl FnOnce() -> R) -> R {
            f()
        }

        pub fn high_water() -> usize {
            0
        }

        pub fn residue() -> usize {
            0
        }
    }

    /// Run `f` on the crypto stack (directly on the host). Afterwards the part
    /// of the stack `f` used is overwritten, so no key material or
    /// intermediates remain between operations.
    pub fn run<R>(f: impl FnOnce() -> R) -> R {
        imp::run(f)
    }

    /// Peak crypto-stack usage in bytes since boot (0 on the host).
    pub fn high_water() -> usize {
        imp::high_water()
    }

    /// Bytes left on the crypto stack by the last operation (always 0 after
    /// scrubbing; kept as a self-check shown by the `issuer` command).
    pub fn residue() -> usize {
        imp::residue()
    }
}

static KERNEL_ISSUER: Once<Issuer> = Once::new();

/// Generate the kernel issuer (idempotent). Call once at boot, after the heap
/// is up; later calls return the same issuer.
pub fn init() -> &'static Issuer {
    KERNEL_ISSUER.call_once(Issuer::generate)
}

/// The kernel's issuer, generating it on first use.
pub fn kernel() -> &'static Issuer {
    init()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(n: u8) -> Issuer {
        Issuer::from_seeds(&[n; 32], &[n.wrapping_add(100); 32], EntropySource::Os)
    }

    const MSG: [u8; 32] = [0x42; 32];
    const D: SigDomain = SigDomain::Capability;

    #[test]
    fn signature_does_not_cross_domains() {
        let i = issuer(9);
        let sig = i.sign(SigDomain::Capability, &MSG);
        assert!(i.verify(SigDomain::Capability, &MSG, &sig));
        assert!(!i.verify(SigDomain::AuditCheckpoint, &MSG, &sig));
        assert!(!i.public().verify(SigDomain::AuditCheckpoint, &MSG, &sig));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let i = issuer(1);
        let sig = i.sign(D, &MSG);
        assert!(i.verify(D, &MSG, &sig));
        assert!(i.public().verify(D, &MSG, &sig));
    }

    #[test]
    fn signatures_are_deterministic() {
        let i = issuer(2);
        assert!(i.sign(D, &MSG) == i.sign(D, &MSG));
    }

    #[test]
    fn other_issuer_signature_is_rejected() {
        let a = issuer(3);
        let b = issuer(4);
        let sig = b.sign(D, &MSG);
        assert!(!a.verify(D, &MSG, &sig));
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn both_halves_are_required() {
        let i = issuer(5);
        let good = i.sign(D, &MSG);

        let mut bad_ed = good.clone();
        bad_ed.ed25519[0] ^= 1;
        assert!(!i.verify(D, &MSG, &bad_ed));

        let mut bad_ml = good.clone();
        bad_ml.mldsa65[100] ^= 1;
        assert!(!i.verify(D, &MSG, &bad_ml));

        // Splice halves from two different issuers.
        let other = issuer(6).sign(D, &MSG);
        let mixed = HybridSignature {
            ed25519: good.ed25519,
            mldsa65: other.mldsa65,
        };
        assert!(!i.verify(D, &MSG, &mixed));
    }

    #[test]
    fn wrong_message_is_rejected() {
        let i = issuer(7);
        let sig = i.sign(D, &MSG);
        let mut other = MSG;
        other[31] ^= 1;
        assert!(!i.verify(D, &other, &sig));
    }

    #[test]
    fn issuer_id_depends_on_both_keys() {
        let a = Issuer::from_seeds(&[1; 32], &[2; 32], EntropySource::Os);
        let b = Issuer::from_seeds(&[1; 32], &[3; 32], EntropySource::Os);
        let c = Issuer::from_seeds(&[9; 32], &[2; 32], EntropySource::Os);
        assert_ne!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
    }

    #[test]
    fn key_and_signature_sizes_match_fips_204() {
        let i = issuer(8);
        assert_eq!(i.public().mldsa65.len(), 1952);
        assert_eq!(i.sign(D, &MSG).mldsa65.len(), 3309);
    }

    fn hex(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate().take(s.len() / 2) {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Known-answer test: RFC 8032 §7.1 TEST 2 and TEST 3 (Ed25519).
    /// Also reproduced independently with OpenSSL 3.0 while writing this test.
    #[test]
    fn ed25519_matches_rfc8032_vectors() {
        use ed25519_dalek::{Signer, SigningKey};
        let cases = [
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                &[0x72u8][..],
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                &[0xafu8, 0x82][..],
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (secret, public, msg, sig) in cases {
            let seed: [u8; 32] = hex(secret)[..32].try_into().unwrap();
            let key = SigningKey::from_bytes(&seed);
            assert_eq!(key.verifying_key().to_bytes()[..], hex(public)[..32]);
            let expected = hex(&sig.replace(' ', ""));
            let got = key.sign(msg);
            assert_eq!(got.to_bytes(), expected);
            assert!(key.verifying_key().verify_strict(msg, &got).is_ok());

            // Our issuer derives the same Ed25519 public key from the seed.
            let issuer = Issuer::from_seeds(&seed, &[0; 32], EntropySource::Os);
            assert_eq!(issuer.public().ed25519[..], hex(public)[..32]);
        }
    }

    /// Known-answer test: ML-DSA-65 key generation (FIPS 204 KeyGen_internal)
    /// from seed 00..1f must reproduce the public key of the IETF LAMPS
    /// example `ML-DSA-65.pub` (github.com/lamps-wg/dilithium-certificates,
    /// examples/; also shipped in the ml-dsa crate's tests/examples/).
    #[test]
    fn mldsa65_keygen_matches_ietf_lamps_example() {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let issuer = Issuer::from_seeds(&[0; 32], &seed, EntropySource::Os);
        let public = &issuer.public().mldsa65[..];
        assert_eq!(public[..16], hex("48683d91978e31eb3dddb8b0473482d2")[..16]);
        let digest: [u8; 32] = Sha256::digest(public).into();
        assert_eq!(
            digest[..],
            hex("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9")[..32]
        );
    }

    #[test]
    fn kernel_issuer_is_stable() {
        assert!(core::ptr::eq(kernel(), init()));
        assert_eq!(kernel().id(), init().id());
    }
}
