use super::{
    dns_flags::DNSFlags, dns_packet::DNSPacket, dns_packet_buffer::DNSPacketBuffer,
    error::ParseError,
};

#[derive(Debug)]
pub struct DNSHeader {
    /// A 16 bit identifier assigned by the program that
    /// generates any kind of query.
    ///
    /// This helps matching the requests with responses.
    pub id: u16,
    /// All the flags for the query.
    pub flags: DNSFlags,
    /// The number of questions asked by the request
    pub questions_count: u16,
    /// The number of answer RRs returned
    pub answers_count: u16,
    /// The number of authority nameservers RRs in
    /// authority records section
    pub authorities_count: u16,
    /// The number of additional RRs returned
    pub additionals_count: u16,
}

impl DNSHeader {
    const SIZE: usize = 12;

    /// The header is of 12 bytes. So the list shall
    /// contain 12 bytes exactly
    pub fn parse(buffer: &mut DNSPacketBuffer) -> Result<Self, ParseError> {
        if buffer.remaining_bytes(Self::SIZE) {
            return Err(ParseError::InvalidHeader {
                msg: "Packet is too short".to_string(),
            });
        }
        let id = buffer.read_u16();
        let flags = DNSFlags::parse(buffer)?;

        let questions_count: u16 = buffer.read_u16();
        let answers_count: u16 = buffer.read_u16();
        let authorities_count: u16 = buffer.read_u16();
        let additionals: u16 = buffer.read_u16();

        Ok(DNSHeader {
            id,
            flags,
            questions_count,
            answers_count,
            authorities_count,
            additionals_count: additionals,
        })
    }

    pub fn from_dns_struct(dns: &DNSPacket, id: u16) -> Self {
        let mut flags = DNSFlags::new();

        if (dns.answers.len() > 0) || (dns.authorities.len() > 0) || (dns.additionals.len() > 0) {
            flags.qr = false;
        } else {
            flags.qr = true;
        }

        flags.opcode = 0;
        flags.aa = true;
        flags.tc = false;
        flags.rd = true;
        flags.ra = true;
        flags.z = 0;
        flags.rcode = 0;

        DNSHeader {
            id,
            flags,
            questions_count: dns.questions.len() as u16,
            answers_count: dns.answers.len() as u16,
            authorities_count: dns.authorities.len() as u16,
            additionals_count: dns.additionals.len() as u16,
        }
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) {
        buffer.write_u16(self.id);
        buffer.write_bytes(&self.flags.to_u8());
        buffer.write_u16(self.questions_count);
        buffer.write_u16(self.answers_count);
        buffer.write_u16(self.authorities_count);
        buffer.write_u16(self.additionals_count);
    }
}
