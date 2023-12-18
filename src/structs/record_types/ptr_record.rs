use crate::structs::{dns_packet_buffer::DNSPacketBuffer, error::ParseError};

#[derive(Debug, Clone)]
pub struct PTRRecord(pub String);

impl PTRRecord {
    // pub const TYPE: u16 = 12;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse PTR record
        if data_length < 2 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid PTR record: Data length should be at least 2 bytes".to_string(),
            });
        }
        let domain_name = String::from_utf8_lossy(&raw_data[2..]).to_string();
        Ok(PTRRecord(domain_name))
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {}
}

