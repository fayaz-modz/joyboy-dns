use crate::structs::{dns_packet_buffer::{DNSPacketBuffer, DNSLabel}, error::ParseError};

#[derive(Debug, Clone)]
pub struct CNAMERecord(pub Vec<DNSLabel>);

impl CNAMERecord {
    // pub const TYPE: u16 = 5;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse CNAME record
        if data_length < 2 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid CNAME record: Data length should be at least 2 bytes".to_string(),
            });
        }
        let alias = DNSPacketBuffer::small(raw_data).parse_labels()?;
        Ok(CNAMERecord(alias))
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), String> {
        buffer.push_labels(&self.0)?;
        Ok(())
    }
}
