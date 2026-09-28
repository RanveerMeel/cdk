//! Tool-call messages between CDK and the gateway (roadmap 3.3).
//!
//! Carried as plaintext *inside* sealed frames (the secure channel provides
//! confidentiality and integrity). The gateway translates them to MCP
//! JSON-RPC (`tools/list`, `tools/call`) for the actual tool servers; CDK
//! never parses JSON. Little-endian, fixed layouts:
//!
//! ```text
//! ListRequest  : 3
//! ListResponse : 4 | count u8 | (len u8 | name)*
//! CallRequest  : 1 | call_id u32 | len u8 | name | args_len u16 | args (JSON bytes, passed through)
//! CallResponse : 2 | call_id u32 | status u8 | len u16 | body (UTF-8 text)
//! ```

use alloc::vec::Vec;

pub const LIST_REQUEST: u8 = 3;
pub const LIST_RESPONSE: u8 = 4;
pub const CALL_REQUEST: u8 = 1;
pub const CALL_RESPONSE: u8 = 2;

/// Longest tool name.
pub const MAX_NAME: usize = 48;
/// Largest `args` / `body` that fits a sealed frame with its header.
pub const MAX_BODY: usize = crate::secure::MAX_PLAINTEXT - 8 - MAX_NAME;
/// Tools listed at most.
pub const MAX_TOOLS: usize = 16;

/// Outcome of a tool call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// The tool ran and reported an error (MCP `isError`).
    ToolError = 1,
    UnknownTool = 2,
    /// The gateway's policy refused the call.
    Refused = 3,
    /// The tool server failed or timed out.
    Unavailable = 4,
    /// The result was cut to fit [`MAX_BODY`].
    Truncated = 5,
}

impl Status {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Status::Ok,
            1 => Status::ToolError,
            2 => Status::UnknownTool,
            3 => Status::Refused,
            4 => Status::Unavailable,
            5 => Status::Truncated,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolMsgError {
    Malformed,
    TooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    ListRequest,
    ListResponse(Vec<&'a str>),
    CallRequest {
        call_id: u32,
        name: &'a str,
        args: &'a [u8],
    },
    CallResponse {
        call_id: u32,
        status: Status,
        body: &'a [u8],
    },
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

pub fn encode_list_request() -> Vec<u8> {
    alloc::vec![LIST_REQUEST]
}

pub fn encode_list_response(names: &[&str]) -> Result<Vec<u8>, ToolMsgError> {
    if names.len() > MAX_TOOLS || !names.iter().all(|n| valid_name(n)) {
        return Err(ToolMsgError::TooLarge);
    }
    let mut out = alloc::vec![LIST_RESPONSE, names.len() as u8];
    for n in names {
        out.push(n.len() as u8);
        out.extend_from_slice(n.as_bytes());
    }
    Ok(out)
}

pub fn encode_call_request(call_id: u32, name: &str, args: &[u8]) -> Result<Vec<u8>, ToolMsgError> {
    if !valid_name(name) || args.len() > MAX_BODY {
        return Err(ToolMsgError::TooLarge);
    }
    let mut out = alloc::vec![CALL_REQUEST];
    out.extend_from_slice(&call_id.to_le_bytes());
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(args.len() as u16).to_le_bytes());
    out.extend_from_slice(args);
    Ok(out)
}

/// Encode a response, truncating `body` to [`MAX_BODY`] (status becomes
/// [`Status::Truncated`] if it was `Ok`).
pub fn encode_call_response(call_id: u32, mut status: Status, body: &[u8]) -> Vec<u8> {
    let body = if body.len() > MAX_BODY {
        if status == Status::Ok {
            status = Status::Truncated;
        }
        &body[..MAX_BODY]
    } else {
        body
    };
    let mut out = alloc::vec![CALL_RESPONSE];
    out.extend_from_slice(&call_id.to_le_bytes());
    out.push(status as u8);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Parse any tool message; every length is bounds-checked.
pub fn decode(b: &[u8]) -> Result<Message<'_>, ToolMsgError> {
    let bad = ToolMsgError::Malformed;
    let (&tag, rest) = b.split_first().ok_or(bad)?;
    let u32_at = |s: &[u8]| -> Result<u32, ToolMsgError> {
        Ok(u32::from_le_bytes(
            s.get(..4).ok_or(bad)?.try_into().map_err(|_| bad)?,
        ))
    };
    let u16_at = |s: &[u8]| -> Result<usize, ToolMsgError> {
        Ok(u16::from_le_bytes(s.get(..2).ok_or(bad)?.try_into().map_err(|_| bad)?) as usize)
    };
    match tag {
        LIST_REQUEST if rest.is_empty() => Ok(Message::ListRequest),
        LIST_RESPONSE => {
            let (&count, mut r) = rest.split_first().ok_or(bad)?;
            if count as usize > MAX_TOOLS {
                return Err(bad);
            }
            let mut names = Vec::new();
            for _ in 0..count {
                let (&len, tail) = r.split_first().ok_or(bad)?;
                let name = tail.get(..len as usize).ok_or(bad)?;
                let name = core::str::from_utf8(name).map_err(|_| bad)?;
                if !valid_name(name) {
                    return Err(bad);
                }
                names.push(name);
                r = &tail[len as usize..];
            }
            if !r.is_empty() {
                return Err(bad);
            }
            Ok(Message::ListResponse(names))
        }
        CALL_REQUEST => {
            let call_id = u32_at(rest)?;
            let r = &rest[4..];
            let (&len, r) = r.split_first().ok_or(bad)?;
            let name = core::str::from_utf8(r.get(..len as usize).ok_or(bad)?).map_err(|_| bad)?;
            if !valid_name(name) {
                return Err(bad);
            }
            let r = &r[len as usize..];
            let alen = u16_at(r)?;
            let args = r.get(2..2 + alen).ok_or(bad)?;
            if r.len() != 2 + alen {
                return Err(bad);
            }
            Ok(Message::CallRequest {
                call_id,
                name,
                args,
            })
        }
        CALL_RESPONSE => {
            let call_id = u32_at(rest)?;
            let r = &rest[4..];
            let (&st, r) = r.split_first().ok_or(bad)?;
            let status = Status::from_u8(st).ok_or(bad)?;
            let blen = u16_at(r)?;
            let body = r.get(2..2 + blen).ok_or(bad)?;
            if r.len() != 2 + blen {
                return Err(bad);
            }
            Ok(Message::CallResponse {
                call_id,
                status,
                body,
            })
        }
        _ => Err(bad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(decode(&encode_list_request()), Ok(Message::ListRequest));
        let l = encode_list_response(&["echo", "word_count"]).unwrap();
        assert_eq!(
            decode(&l),
            Ok(Message::ListResponse(alloc::vec!["echo", "word_count"]))
        );
        let c = encode_call_request(7, "echo", br#"{"text":"hi"}"#).unwrap();
        assert_eq!(
            decode(&c),
            Ok(Message::CallRequest {
                call_id: 7,
                name: "echo",
                args: br#"{"text":"hi"}"#
            })
        );
        let r = encode_call_response(7, Status::Ok, b"hi");
        assert_eq!(
            decode(&r),
            Ok(Message::CallResponse {
                call_id: 7,
                status: Status::Ok,
                body: b"hi"
            })
        );
    }

    #[test]
    fn requests_fit_a_sealed_frame() {
        let name = "n".repeat(MAX_NAME);
        let c = encode_call_request(1, &name, &[b'x'; MAX_BODY]).unwrap();
        assert!(c.len() <= crate::secure::MAX_PLAINTEXT);
        assert_eq!(
            encode_call_request(1, "a", &[0; MAX_BODY + 1]),
            Err(ToolMsgError::TooLarge)
        );
        assert_eq!(
            encode_call_request(1, "bad name", b"{}"),
            Err(ToolMsgError::TooLarge)
        );
        let big = encode_call_response(2, Status::Ok, &[b'y'; MAX_BODY + 50]);
        match decode(&big).unwrap() {
            Message::CallResponse { status, body, .. } => {
                assert_eq!(status, Status::Truncated);
                assert_eq!(body.len(), MAX_BODY);
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn malformed_messages_are_rejected() {
        for b in [
            &[][..],
            &[9][..],
            &[LIST_REQUEST, 0][..],
            &[LIST_RESPONSE, 1, 5, b'a'][..],
            &[CALL_REQUEST, 1, 0, 0, 0, 4, b'e', b'c', b'h', b'o', 9, 0][..],
            &[CALL_RESPONSE, 1, 0, 0, 0, 77, 0, 0][..],
            &[CALL_RESPONSE, 1, 0, 0, 0, 0, 3, 0, b'a'][..],
        ] {
            assert_eq!(decode(b), Err(ToolMsgError::Malformed), "{b:?}");
        }
    }
}
