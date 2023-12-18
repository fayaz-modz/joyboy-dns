use super::{
    dns_packet_buffer::{DNSLabel, DNSPacketBuffer},
    error::ParseError, dns_record_types::DNSRecord, record_types::a_record::ARecord,
};

#[derive(Debug, Clone)]
pub struct DNSResourceRecord {
    /// domain name to which this RR applies
    /// in the form of labels ["www", "example", "com"]
    pub name: Vec<DNSLabel>,
    /// a 16 bit unsigned integer that specifies the type
    /// of the query. Can be A, AAA, CNAME, MX etc.
    /// +------+----------+------------------------------+
    /// | Code | QTYPE    | Meaning                      |
    /// +------+----------+------------------------------+
    /// | 1    | A        | IPv4 Address                 |
    /// | 2    | NS       | Name Server                  |
    /// | 5    | CNAME    | Canonical Name (Alias)       |
    /// | 6    | SOA      | Start of Authority           |
    /// | 12   | PTR      | Pointer (Reverse DNS Lookup) |
    /// | 15   | MX       | Mail Exchange                |
    /// | 16   | TXT      | Text                         |
    /// | 28   | AAAA     | IPv6 Address                 |
    /// | 33   | SRV      | Service (Locator)            |
    /// | 255  | ANY      | All Records                  |
    /// +------+----------+------------------------------+
    pub rtype: u16,
    /// +------+--------+---------------------------+
    /// | Code | QCLASS | Meaning                   |
    /// +------+--------+---------------------------+
    /// | 1    | IN     | Internet                  |
    /// | 2    | CS     | CSNET (Obsolete)          |
    /// | 3    | CH     | Chaos                     |
    /// | 4    | HS     | Hesiod                    |
    /// | 255  | ANY    | All Classes (Rarely used) |
    /// +------+--------+---------------------------+
    pub class: u16,
    /// a 32 bit unsigned integer that specifies the time
    /// interval (in seconds) that the resource record may be
    /// cached before it should be discarded. Zero values are
    /// interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    pub ttl: u32,
    /// a 16 bit unsigned integer that specifies the length
    /// of the data in bytes
    pub rdlength: u16,
    /// The actual data is a vector of bytes.
    pub data: DNSRecord,
}

impl DNSResourceRecord {
    pub fn new() -> Self {
        Self {
            name: vec![],
            rtype: ARecord::TYPE,
            class: 0,
            ttl: 0,
            rdlength: 0,
            data: DNSRecord::Unknown {
                record_type: 0,
                data_length: 0,
                raw_data: vec![],
            },
        }
    }

    pub fn push_name_label(mut self, name: String) -> Self  {
        self.name.push(DNSLabel {
            value: name,
            offset: None
        });
        self
    }

    pub fn rtype(mut self, rtype: u16) -> Self {
        self.rtype = rtype;
        self
    }

    pub fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }

    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn rdlength(mut self, rdlength: u16) -> Self {
        self.rdlength = rdlength;
        self
    }

    pub fn data(mut self, data: DNSRecord) -> Self {
        self.data = data;
        self
    }

    pub fn parse(buffer: &mut DNSPacketBuffer) -> Result<Self, ParseError> {
        let labels = buffer.parse_labels()?;
        let r_type = buffer.read_u16();
        let r_class = buffer.read_u16();
        let ttl = buffer.read_u32();
        let rdlength = buffer.read_u16();

        let data = DNSRecord::parse_dns_record_data(
            r_type,
            rdlength as usize,
            buffer.next_chunk(rdlength as usize),
        )?;

        Ok(Self {
            name: labels,
            rtype: r_type,
            class: r_class,
            ttl,
            rdlength,
            data,
        })
    }

    pub fn parse_multiple(
        count: usize,
        buffer: &mut DNSPacketBuffer,
    ) -> Result<Vec<Self>, ParseError> {
        let mut records: Vec<Self> = vec![];
        for _ in 0..count {
            records.push(Self::parse(buffer)?);
        }
        Ok(records)
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), String> {
        buffer.push_labels(&self.name)?;
        buffer.write_u16(self.rtype);
        buffer.write_u16(self.class);
        buffer.write_u32(self.ttl);
        buffer.write_u16(self.rdlength);
        self.data.write_to_bytes(buffer);

        Ok(())
    }
}
