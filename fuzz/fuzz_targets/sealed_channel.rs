//! The ChaCha20-Poly1305 session: forged frames must never open, and real
//! ones must round-trip exactly, in order.
#![no_main]
use std::sync::{Mutex, OnceLock};

use cdk_link::secure::{self, hybrid, ClientRandom, ServerRandom, Session, MAX_PLAINTEXT};
use cdk_link::MAX_PAYLOAD;
use libfuzzer_sys::fuzz_target;

fn sessions() -> &'static Mutex<(Session, Session)> {
    static S: OnceLock<Mutex<(Session, Session)>> = OnceLock::new();
    S.get_or_init(|| {
        let cli = hybrid::Keypair::from_seeds(&[1; 32], &[2; 32]);
        let srv = hybrid::Keypair::from_seeds(&[3; 32], &[4; 32]);
        let (cs, ch) = secure::client_hello(ClientRandom {
            x25519: [5; 32],
            kem_seed: [6; 64],
            nonce: [7; 32],
        });
        let (ss, sh) = secure::server_respond(
            &ch,
            ServerRandom {
                x25519: [8; 32],
                kem_m: [9; 32],
                nonce: [10; 32],
            },
            srv.public(),
            |d| srv.sign(d),
        )
        .unwrap();
        let (client, cf, _) =
            secure::client_finish(cs, &sh, hybrid::verify, cli.public(), |d| cli.sign(d)).unwrap();
        let (server, _) = secure::server_finish(ss, &cf, hybrid::verify).unwrap();
        Mutex::new((client, server))
    })
}

fuzz_target!(|data: &[u8]| {
    let mut s = sessions().lock().unwrap();
    let (client, server) = &mut *s;
    let mut out = [0u8; MAX_PAYLOAD];
    // Arbitrary bytes as a sealed frame: must be rejected.
    assert!(
        server.open(data, &mut out).is_err(),
        "a forged frame opened"
    );
    // Arbitrary bytes as plaintext: must round-trip (or be refused as too large).
    let mut sealed = [0u8; MAX_PAYLOAD];
    match client.seal(data, &mut sealed) {
        Ok(n) => {
            assert!(data.len() <= MAX_PLAINTEXT);
            let m = server
                .open(&sealed[..n], &mut out)
                .expect("genuine frame must open");
            assert_eq!(&out[..m], data);
            // Replaying it must fail.
            assert!(
                server.open(&sealed[..n], &mut out).is_err(),
                "replay accepted"
            );
        }
        Err(_) => assert!(data.len() > MAX_PLAINTEXT),
    }
});
