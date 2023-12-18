use crate::structs::{error::ParseError, dns_packet_buffer::DNSPacketBuffer};

// Define the structs for each DNS record type
#[derive(Debug, Clone)]
pub struct ARecord(pub std::net::Ipv4Addr);

impl ARecord {
    pub const TYPE: u16 = 1;

    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse A record
        if data_length != 4 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid A record: Data length should be 4 bytes".to_string(),
            });
        }
        let ip_address =
            std::net::Ipv4Addr::new(raw_data[0], raw_data[1], raw_data[2], raw_data[3]);
        Ok(ARecord(ip_address))
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {
        let octets = self.0.octets();
        buffer.write_u8(octets[0]);
        buffer.write_u8(octets[1]);
        buffer.write_u8(octets[2]);
        buffer.write_u8(octets[3]);
    }
}

