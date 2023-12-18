use crate::structs::{
    dns_packet_buffer::{DNSLabel, DNSPacketBuffer},
    error::ParseError,
};

#[derive(Debug, Clone)]
pub struct MXRecord {
    preference: u16,
    mail_exchange: Vec<DNSLabel>,
}

impl MXRecord {
    // pub const TYPE: u16 = 15;
    pub fn parse(data_length: usize, raw_data: &[u8]) -> Result<Self, ParseError> {
        // Parse MX record
        if data_length != 6 {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid MX record: Data length should be 6 bytes".to_string(),
            });
        }
        let preference = u16::from_be_bytes([raw_data[0], raw_data[1]]);
        let mail_exchange = DNSPacketBuffer::small(raw_data).parse_labels()?;
        Ok(MXRecord {
            preference,
            mail_exchange,
        })
    }
    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), String> {
        buffer.write_u16(self.preference);
        buffer.push_labels(&self.mail_exchange)?;

        Ok(())
    }
}
