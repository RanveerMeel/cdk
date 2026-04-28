use heapless::String;
use core::str::FromStr;

const MAX_PAYLOAD_LEN: usize = 64;
const MAX_ID_LEN: usize = 64;
const MAX_TEXT_LEN: usize = 64;

#[derive(Clone, Debug)]
pub struct Message {
    pub from: String<MAX_ID_LEN>,
    pub to: String<MAX_ID_LEN>,
    pub payload: MessagePayload,
}

#[derive(Clone, Debug)]
pub enum MessagePayload {
    Data(heapless::Vec<u8, MAX_PAYLOAD_LEN>),
    Text(String<MAX_TEXT_LEN>),
    Command(String<MAX_TEXT_LEN>),
    Request { 
        method: String<MAX_TEXT_LEN>, 
        params: heapless::Vec<String<MAX_TEXT_LEN>, 8> 
    },
    Response { 
        result: String<MAX_TEXT_LEN> 
    },
}

impl Message {
    pub fn new(
        from: &str,
        to: &str,
        payload: MessagePayload,
    ) -> Result<Self, ()> {
        Ok(Self {
            from: String::from_str(from).map_err(|_| ())?,
            to: String::from_str(to).map_err(|_| ())?,
            payload,
        })
    }

    pub fn text(from: &str, to: &str, text: &str) -> Result<Self, ()> {
        Self::new(
            from,
            to,
            MessagePayload::Text(String::from_str(text).map_err(|_| ())?),
        )
    }

    pub fn command(from: &str, to: &str, cmd: &str) -> Result<Self, ()> {
        Self::new(
            from,
            to,
            MessagePayload::Command(String::from_str(cmd).map_err(|_| ())?),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_message_round_trip() {
        let msg = Message::text("sender", "receiver", "hello").unwrap();
        assert_eq!(msg.from.as_str(), "sender");
        assert_eq!(msg.to.as_str(), "receiver");
        match &msg.payload {
            MessagePayload::Text(t) => assert_eq!(t.as_str(), "hello"),
            _ => panic!("expected Text payload"),
        }
    }

    #[test]
    fn command_message_round_trip() {
        let msg = Message::command("kernel", "obj-1", "shutdown").unwrap();
        assert_eq!(msg.from.as_str(), "kernel");
        assert_eq!(msg.to.as_str(), "obj-1");
        match &msg.payload {
            MessagePayload::Command(c) => assert_eq!(c.as_str(), "shutdown"),
            _ => panic!("expected Command payload"),
        }
    }

    #[test]
    fn data_message_round_trip() {
        let mut data = heapless::Vec::<u8, 64>::new();
        data.extend_from_slice(&[1u8, 2, 3, 4]).unwrap();
        let msg = Message::new("a", "b", MessagePayload::Data(data)).unwrap();
        match &msg.payload {
            MessagePayload::Data(d) => assert_eq!(&d[..], &[1, 2, 3, 4]),
            _ => panic!("expected Data payload"),
        }
    }

    #[test]
    fn message_too_long_returns_error() {
        // MAX_TEXT_LEN is 64; a 65-char string should fail.
        let long = "x".repeat(65);
        assert!(Message::text("a", "b", &long).is_err());
    }

    #[test]
    fn response_payload() {
        let msg = Message::new(
            "srv",
            "cli",
            MessagePayload::Response { result: String::from_str("ok").unwrap() },
        )
        .unwrap();
        match &msg.payload {
            MessagePayload::Response { result } => assert_eq!(result.as_str(), "ok"),
            _ => panic!("expected Response payload"),
        }
    }
}
