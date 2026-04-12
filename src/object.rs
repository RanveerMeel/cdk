use crate::message::Message;
use heapless::Deque;
use heapless::String;
use core::str::FromStr;

const MAX_ID_LEN: usize = 64;
const MAX_KIND_LEN: usize = 32;
const MAX_INTENT_LEN: usize = 32;
const MAX_MESSAGES: usize = 8;

pub struct KernelObject {
    pub id: String<MAX_ID_LEN>,
    pub kind: String<MAX_KIND_LEN>,
    pub intent: String<MAX_INTENT_LEN>,
    pub message_queue: Deque<Message, MAX_MESSAGES>,
}

impl KernelObject {
    pub fn new_compute(name: &str, intent: &str) -> Self {
        // Simple ID generation (replace with proper RNG in production)
        let id = Self::generate_id();
        
        Self {
            id,
            kind: String::from_str(name).unwrap_or_default(),
            intent: String::from_str(intent).unwrap_or_default(),
            message_queue: Deque::new(),
        }
    }

    pub fn receive_message(&mut self, msg: Message) -> Result<(), ()> {
        self.message_queue.push_back(msg).map_err(|_| ())
    }

    pub fn pop_message(&mut self) -> Option<Message> {
        self.message_queue.pop_front()
    }

    pub fn message_count(&self) -> usize {
        self.message_queue.len()
    }

    fn generate_id() -> String<MAX_ID_LEN> {
        // Simple counter-based ID (in production, use proper RNG)
        static mut COUNTER: u64 = 0;
        unsafe {
            COUNTER += 1;
            let mut id = String::new();
            let _ = id.push_str("obj-");
            let _ = write_number(&mut id, COUNTER);
            id
        }
    }
}

fn write_number(s: &mut String<MAX_ID_LEN>, n: u64) -> Result<(), ()> {
    if n == 0 {
        return s.push_str("0");
    }
    
    let mut num = n;
    let mut digits = heapless::Vec::<u8, 20>::new();
    
    while num > 0 {
        digits.push((num % 10) as u8 + b'0').map_err(|_| ())?;
        num /= 10;
    }
    
    for &digit in digits.iter().rev() {
        s.push(digit as char).map_err(|_| ())?;
    }
    
    Ok(())
}
