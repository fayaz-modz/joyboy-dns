use crate::structs::{dns_packet_buffer::DNSPacketBuffer, error::ParseError};

#[derive(Debug, Clone)]
pub struct TXTRecord(pub String);

impl TXTRecord {
    // pub const TYPE: u16 = 16;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse TXT record
        if data_length < 2 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid TXT record: Data length should be at least 2 bytes".to_string(),
            });
        }
        let text_data = String::from_utf8_lossy(&raw_data[2..]).to_string();
        Ok(TXTRecord(text_data))
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {}
}

