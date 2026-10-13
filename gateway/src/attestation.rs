//! Attestation of CDK's measured boot (roadmap 4.2).
//!
//! Right after each handshake the gateway sends a fresh nonce; CDK answers
//! with its boot verdict, release key id and measurement registers. With
//! `--expect FILE` (from `cdk-sign measure`) the gateway serves tools,
//! models and approvals only if the registers match exactly; otherwise it
//! logs what it saw and serves anyway.

use cdk_link::attest::{self, Message, REGISTERS};
use rand_core::{OsRng, RngCore};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// No answer yet for this session.
    Pending,
    /// Matched the expected measurements (or none were configured).
    Trusted,
    /// Wrong nonce or different measurements.
    Rejected,
}

pub struct Attestor {
    expect: Option<[[u8; 32]; REGISTERS]>,
    nonce: [u8; 32],
    pub status: Status,
}

impl Attestor {
    pub fn new(expect: Option<[[u8; 32]; REGISTERS]>) -> Self {
        Attestor {
            expect,
            nonce: [0; 32],
            status: Status::Pending,
        }
    }

    /// Start attesting a new session; returns the request to send.
    pub fn request(&mut self) -> Vec<u8> {
        OsRng.fill_bytes(&mut self.nonce);
        self.status = Status::Pending;
        attest::encode_request(&self.nonce)
    }

    /// Whether tool, model and approval traffic may be served.
    pub fn serving(&self) -> bool {
        self.status == Status::Trusted || (self.expect.is_none() && self.status != Status::Rejected)
    }

    pub fn on_message(&mut self, msg: &[u8]) {
        let Some(Message::Attestation(a)) = attest::decode(msg) else {
            eprintln!("gateway: malformed attestation ignored");
            return;
        };
        if a.nonce != self.nonce {
            eprintln!("gateway: attestation with a stale or wrong nonce — REJECTED");
            self.status = Status::Rejected;
            return;
        }
        eprintln!(
            "gateway: <- attestation: boot {}, release key {}",
            a.verdict.name(),
            attest::hex(&a.release_id[..4])
        );
        for (i, r) in a.registers.iter().enumerate() {
            eprintln!("gateway:    register {i} {}", attest::hex(r));
        }
        self.status = match &self.expect {
            None => {
                eprintln!("gateway: attestation not checked (no --expect)");
                Status::Trusted
            }
            Some(exp) if *exp == a.registers => {
                eprintln!("gateway: attestation MATCHES the expected measurements — serving");
                Status::Trusted
            }
            Some(exp) => {
                for (i, (got, want)) in a.registers.iter().zip(exp).enumerate() {
                    if got != want {
                        eprintln!(
                            "gateway:    register {i} differs: expected {}",
                            attest::hex(want)
                        );
                    }
                }
                eprintln!("gateway: attestation MISMATCH — refusing tools, models and approvals for this session");
                Status::Rejected
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_link::attest::{encode_attestation, expected_registers, Attestation, Verdict};

    fn answer(at: &Attestor, regs: [[u8; 32]; REGISTERS]) -> Vec<u8> {
        encode_attestation(&Attestation {
            nonce: at.nonce,
            verdict: Verdict::Verified,
            release_id: [1; 16],
            registers: regs,
            log: "",
        })
    }

    #[test]
    fn serves_only_matching_fresh_attestations() {
        let good = expected_registers(b"k", b"r", Verdict::Verified, &[1; 16]);
        let bad = expected_registers(b"k", b"r2", Verdict::Verified, &[1; 16]);

        let mut a = Attestor::new(Some(good));
        a.request();
        assert!(!a.serving(), "nothing before the answer");
        a.on_message(&answer(&a, good));
        assert!(a.serving());

        a.request();
        a.on_message(&answer(&a, bad));
        assert_eq!(a.status, Status::Rejected);
        assert!(!a.serving());

        // A replayed answer (old nonce) is rejected.
        let old = answer(&a, good);
        a.request();
        a.on_message(&old);
        assert_eq!(a.status, Status::Rejected);

        // Without --expect: serve, but not after a wrong nonce.
        let mut b = Attestor::new(None);
        b.request();
        assert!(b.serving());
        b.on_message(&old);
        assert!(!b.serving());
    }
}
