use crate::structs::{dns_packet_buffer::DNSPacketBuffer, error::ParseError};

#[derive(Debug, Clone)]
pub struct SOARecord {
    primary_ns: String,
    responsible_email: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
}

impl SOARecord {
    // pub const TYPE: u16 = 6;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse SOA record
        if data_length < 22 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid SOA record: Data length should be at least 22 bytes".to_string(),
            });
        }
        let primary_ns = String::from_utf8_lossy(&raw_data[0..]).to_string();
        let responsible_email = String::from_utf8_lossy(&raw_data[primary_ns.len()..]).to_string();
        let serial = u32::from_be_bytes([
            raw_data[primary_ns.len() + responsible_email.len()],
            raw_data[primary_ns.len() + responsible_email.len() + 1],
            raw_data[primary_ns.len() + responsible_email.len() + 2],
            raw_data[primary_ns.len() + responsible_email.len() + 3],
        ]);
        let refresh = u32::from_be_bytes([
            raw_data[primary_ns.len() + responsible_email.len() + 4],
            raw_data[primary_ns.len() + responsible_email.len() + 5],
            raw_data[primary_ns.len() + responsible_email.len() + 6],
            raw_data[primary_ns.len() + responsible_email.len() + 7],
        ]);
        let retry = u32::from_be_bytes([
            raw_data[primary_ns.len() + responsible_email.len() + 8],
            raw_data[primary_ns.len() + responsible_email.len() + 9],
            raw_data[primary_ns.len() + responsible_email.len() + 10],
            raw_data[primary_ns.len() + responsible_email.len() + 11],
        ]);
        let expire = u32::from_be_bytes([
            raw_data[primary_ns.len() + responsible_email.len() + 12],
            raw_data[primary_ns.len() + responsible_email.len() + 13],
            raw_data[primary_ns.len() + responsible_email.len() + 14],
            raw_data[primary_ns.len() + responsible_email.len() + 15],
        ]);
        let minimum_ttl = u32::from_be_bytes([
            raw_data[primary_ns.len() + responsible_email.len() + 16],
            raw_data[primary_ns.len() + responsible_email.len() + 17],
            raw_data[primary_ns.len() + responsible_email.len() + 18],
            raw_data[primary_ns.len() + responsible_email.len() + 19],
        ]);

        Ok(SOARecord {
            primary_ns,
            responsible_email,
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl,
        })
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {}
}
