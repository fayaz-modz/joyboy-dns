use crate::structs::{dns_packet_buffer::DNSPacketBuffer, error::ParseError};

#[derive(Debug, Clone)]
pub struct SRVRecord {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

impl SRVRecord {
    // pub const TYPE: u16 = 33;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse SRV record
        if data_length != 16 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid SRV record: Data length should be 16 bytes".to_string(),
            });
        }
        let priority = u16::from_be_bytes([raw_data[0], raw_data[1]]);
        let weight = u16::from_be_bytes([raw_data[2], raw_data[3]]);
        let port = u16::from_be_bytes([raw_data[4], raw_data[5]]);
        let target = String::from_utf8_lossy(&raw_data[6..]).to_string();
        Ok(SRVRecord {
            priority,
            weight,
            port,
            target,
        })
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {}
}
