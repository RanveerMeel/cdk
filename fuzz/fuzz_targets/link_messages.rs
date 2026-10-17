//! Tool, model, approval and peer (roadmap 3.5) messages inside the sealed
//! channel, and portable capabilities / node certificates from a peer. Anything
//! that decodes must re-encode to the same bytes (no two encodings of one
//! message), and reassembly must never produce more than it was given.
#![no_main]
use cdk_link::{approval, peer, tool};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Peer capabilities come from an untrusted courier: decoding is strict
    // (canonical), and verification never panics.
    if let Some(c) = peer::NodeCert::decode(data) {
        assert_eq!(c.encode(), data);
    }
    if let Some(p) = peer::PortableCap::decode(data) {
        assert_eq!(p.encode(), data);
        let registry = p.cert.issuer.clone();
        let _ = p.verify(&registry, "fuzz", 0);
    }
    let mut blobs = peer::BlobAssembler::default();
    for part in data.split(|&b| b == 0xfe) {
        if let Ok(Some((_, out))) = blobs.push(part) {
            assert!(out.len() <= peer::MAX_BLOB);
        }
    }
    if let Some(name) = peer::decode_import_request(data) {
        assert!(peer::valid_file_name(name));
    }
    let _ = peer::decode_status(data);
    match tool::decode(data) {
        Ok(tool::Message::ListRequest) => assert_eq!(tool::encode_list_request(), data),
        Ok(tool::Message::ListResponse(entries)) => {
            assert_eq!(tool::encode_list_response(&entries).unwrap(), data)
        }
        Ok(tool::Message::CallRequest {
            call_id,
            name,
            args,
        }) => {
            assert_eq!(
                tool::encode_call_request(call_id, name, args).unwrap(),
                data
            )
        }
        Ok(tool::Message::CallResponse {
            call_id,
            status,
            body,
        }) => {
            assert_eq!(tool::encode_call_response(call_id, status, body), data)
        }
        Ok(tool::Message::CallChunk { .. }) | Err(_) => {}
    }
    match approval::decode(data) {
        Ok(approval::Message::Request(r)) => {
            assert_eq!(approval::encode_request(&r).unwrap(), data);
            assert_ne!(
                approval::statement(&r, true),
                approval::statement(&r, false)
            );
        }
        Ok(approval::Message::Resolved { id, outcome }) => {
            assert_eq!(approval::encode_resolved(id, outcome), data)
        }
        Ok(approval::Message::DecisionPart { .. }) | Err(_) => {}
    }
    // Treat the input as a stream of decision parts.
    let mut asm = approval::Assembler::new();
    let mut fed = 0usize;
    for part in data.split(|&b| b == 0xff) {
        if let Ok(approval::Message::DecisionPart {
            id,
            operator,
            approve,
            total,
            offset,
            bytes,
        }) = approval::decode(part)
        {
            fed += bytes.len();
            if let Some((_, _, _, sig)) = asm.push(id, operator, approve, total, offset, bytes) {
                assert_eq!(sig.len(), total as usize);
                assert!(sig.len() <= fed);
            }
        }
    }
});
