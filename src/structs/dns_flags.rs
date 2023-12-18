use super::{error::ParseError, dns_packet_buffer::DNSPacketBuffer};

#[derive(Debug)]
pub struct DNSFlags {
    /// specifies if this is a query or a response
    /// false(0) for a query and true(1) for a response
    pub qr: bool,
    /// A 4-bit field that specifies kind of query in this
    /// message.  This value is set by the originator of a query
    /// and copied into the response.  The values are:
    ///
    /// ->  0     a standard query (QUERY)
    /// ->  1     an inverse query (IQUERY)
    /// ->  2     a server status request (STATUS)
    /// ->  3-15  reserved for future use
    pub opcode: u8,
    /// A 1 bit field that specifies whether this message is
    /// Authoritative or not. Meaning that the response answer
    /// RR is stored on this server or not.
    pub aa: bool,
    /// Truncation flag. If the response answer is too big for
    /// a UDP response packet, the response is truncated. The
    /// request should be made using a TCP protocol instead.
    pub tc: bool,
    /// Recursion Desired. If set to true the server can request
    /// the client to reply to the query recursively.
    /// i.e., the server can request queries from other dns servers.
    /// If set to false and if the information is not available
    /// locally, the server will respond with a referral to the client,
    /// which then needs to query authoritative servers directly.
    pub rd: bool,
    /// Recursion Available. A flag indicating whether recursive
    /// response is available for this server.
    pub ra: bool,
    /// Z Its a 3-bit response code. And is reserved for future
    /// use. This is currently set to 000;
    pub z: u8,
    /// Response Code is the code indicating the type of response.
    /// The values range from 0-15. The codes are:
    /// ->  0     no error condition
    /// ->  1     format error
    /// ->  2     server failure
    /// ->  3     name error
    /// ->  4     not implemented
    /// ->  5     refused
    /// ->  6-15  reserved for future use
    pub rcode: u8,
}

impl DNSFlags {
    pub fn new() -> Self {
        DNSFlags {
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
        }
    }

    /// The flags span over 2 bytes i.e 16 bits.
    /// So this function parses the flags from a list bytes
    /// which is of length 2
    pub fn parse(buffer: &mut DNSPacketBuffer) -> Result<Self, ParseError> {
        let chunk = buffer.next_chunk(2); // get two bytes

        // bit wise oprations
        // let qr = chunk[0] & 0b1000_0000 == 0b1000_0000;
        // let opcode = (chunk[0] >> 3) & 0b0000_1111;
        // let aa = chunk[0] & 0b0000_0100 == 0b0000_0100;
        // let tc = chunk[0] & 0b0000_0010 == 0b0000_0010;
        // let rd = chunk[0] & 0b0000_0001 == 0b0000_0001;
        // let ra = chunk[1] & 0b1000_0000 == 0b1000_0000;
        // let z = (chunk[1] >> 4) & 0b0000_0111;
        // let rcode = chunk[1] & 0b0000_1111;

        // hex wise oprations [updated]
        let qr = chunk[0] & 0x80 == 0x80;
        let opcode = (chunk[0] >> 3) & 0x0F;
        let aa = chunk[0] & 0x04 == 0x04;
        let tc = chunk[0] & 0x02 == 0x02;
        let rd = chunk[0] & 0x01 == 0x01;
        let ra = chunk[1] & 0x80 == 0x08;
        let z = (chunk[1] >> 4) & 0x07;
        let rcode = chunk[1] & 0x0F;

        Ok(Self {
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
        })
    }

    pub fn to_u8(&self) -> [u8; 2] {
        let mut buffer: [u8; 2] = [0, 0];
        buffer[0] |= (self.qr as u8) << 7;
        buffer[0] |= (self.opcode as u8) << 3;
        buffer[0] |= (self.aa as u8) << 2;
        buffer[0] |= (self.tc as u8) << 1;
        buffer[0] |= self.rd as u8;

        buffer[1] |= (self.ra as u8) << 7;
        buffer[1] |= (self.z as u8) << 4;
        buffer[1] |= self.rcode as u8;

        buffer
    }

}
