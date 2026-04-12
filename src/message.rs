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
