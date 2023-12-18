use crate::structs::{dns_packet_buffer::DNSPacketBuffer, error::ParseError};

#[derive(Debug, Clone)]
pub struct AAAARecord(pub std::net::Ipv6Addr);

impl AAAARecord {
    // pub const TYPE: u16 = 28;

    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse AAAA record (IPv6)
        if data_length != 16 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid AAAA record: Data length should be 16 bytes".to_string(),
            });
        }
        let mut ipv6_bytes = [0; 16];
        ipv6_bytes.copy_from_slice(&raw_data);
        let ip_address = std::net::Ipv6Addr::from(ipv6_bytes);
        Ok(AAAARecord(ip_address))
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {
        for item in self.0.octets() {
            buffer.write_u8(item);
        }
    }
}
