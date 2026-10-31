//! The vsock link's stream endpoint (roadmap 5.2): packets come from the
//! hypervisor, so any sequence of headers must keep the endpoint sane —
//! never more than two replies, never an answer to a reset, data accepted
//! only from the connected peer, and sends never beyond the peer's credit.
#![no_main]
use cdk::virtio_vsock::{op, Endpoint, Header, HDR_LEN, HOST_CID, LINK_PORT};
use libfuzzer_sys::fuzz_target;

const ME: u64 = 3;

fuzz_target!(|data: &[u8]| {
    let mut ep = Endpoint::new(ME);
    for chunk in data.chunks(HDR_LEN + 1) {
        let Some(mut h) = Header::decode(chunk) else {
            break;
        };
        // Steer most packets at us so the state machine is exercised.
        let steer = chunk[HDR_LEN..].first().copied().unwrap_or(0);
        if steer & 1 == 0 {
            h.dst_cid = ME;
            h.typ = 1;
        }
        if steer & 2 == 0 {
            h.dst_port = LINK_PORT;
            h.src_cid = HOST_CID;
        }
        h.op %= 9;
        let peer_before = ep.peer;
        let a = ep.on_packet(&h);
        assert!(a.replies.len() <= 2);
        if h.op == op::RST {
            assert!(a.replies.is_empty(), "a reset is never answered");
        }
        if a.deliver {
            assert_eq!(h.op, op::RW);
            assert_eq!(
                peer_before,
                Some((h.src_cid, h.src_port)),
                "data only from the peer"
            );
        }
        for r in a.replies.iter() {
            assert_eq!(r.src_cid, ME);
            assert_ne!(r.op, op::RW, "replies carry no data");
        }
        // Sending: never beyond the credit, never without a peer.
        let want = (steer as u32) << 4;
        let credit = ep.credit();
        match ep.data(want) {
            Some(d) => {
                assert!(want <= credit);
                assert_eq!(Some((d.dst_cid, d.dst_port)), ep.peer);
            }
            None => assert!(ep.peer.is_none() || want > credit),
        }
        assert!(ep.credit() <= credit, "sending never grows the credit");
    }
});
