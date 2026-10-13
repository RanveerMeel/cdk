//! Handshake messages from an untrusted peer: a ClientHello at the gateway,
//! a ServerHello at CDK. Must be rejected cleanly, never accepted.
#![no_main]
use std::sync::OnceLock;

use cdk_link::secure::{self, hybrid, ClientRandom, ServerRandom};
use libfuzzer_sys::fuzz_target;

fn keys() -> &'static (hybrid::Keypair, hybrid::Keypair) {
    static K: OnceLock<(hybrid::Keypair, hybrid::Keypair)> = OnceLock::new();
    K.get_or_init(|| {
        (
            hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]),
            hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let (cli, srv) = keys();
    // As a ClientHello: may produce a ServerHello (it is unauthenticated),
    // but must not panic.
    let _ = secure::server_respond(
        data,
        ServerRandom {
            x25519: [8; 32],
            kem_m: [9; 32],
            nonce: [10; 32],
        },
        srv.public(),
        |d| srv.sign(d),
    );
    // As a ServerHello: without the pinned gateway's signature it must fail.
    let (cs, _ch) = secure::client_hello(ClientRandom {
        x25519: [5; 32],
        kem_seed: [6; 64],
        nonce: [7; 32],
    });
    let pinned = srv.public().clone();
    let r = secure::client_finish(
        cs,
        data,
        |id, d, s| *id == pinned && hybrid::verify(id, d, s),
        cli.public(),
        |d| cli.sign(d),
    );
    assert!(r.is_err(), "forged ServerHello accepted");
});
