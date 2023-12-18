use super::{
    dns_packet_buffer::{DNSLabel, DNSPacketBuffer},
    error::ParseError,
};

#[derive(Debug)]
pub struct DNSQuestion {
    /// The name of the domain represented in the form of
    /// labels (subdomains) seperated by dots. Each label
    /// has a length byte which defines the lenght of the label
    /// at the start. And followed by a null byte to terminate qname.
    pub qname: Vec<DNSLabel>,
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
    pub qtype: u16,
    /// +------+--------+---------------------------+
    /// | Code | QCLASS | Meaning                   |
    /// +------+--------+---------------------------+
    /// | 1    | IN     | Internet                  |
    /// | 2    | CS     | CSNET (Obsolete)          |
    /// | 3    | CH     | Chaos                     |
    /// | 4    | HS     | Hesiod                    |
    /// | 255  | ANY    | All Classes (Rarely used) |
    /// +------+--------+---------------------------+
    pub qclass: u16,
}

impl DNSQuestion {
    // pub fn new() -> Self {
    //     Self {
    //         qname: vec![],
    //         qtype: 0,
    //         qclass: 0,
    //     }
    // }
    //
    // pub fn push_qname(&mut self, qname: DNSLabel) -> &mut Self {
    //     self.qname.push(qname);
    //     self
    // }
    //
    // pub fn qtype(&mut self, qtype: u16) -> &mut Self {
    //     self.qtype = qtype;
    //     self
    // }
    //
    // pub fn qclass(&mut self, qclass: u16) -> &mut Self {
    //     self.qclass = qclass;
    //     self
    // }

    /// This should be run from a loop. The offset is required
    /// which marks the start of the question, and the packet
    /// is the full udp packet
    ///
    /// the packet should be the full packet
    pub fn parse_questions(
        count: usize,
        buffer: &mut DNSPacketBuffer,
    ) -> Result<Vec<DNSQuestion>, ParseError> {
        let mut i = 0; // we are dealing with question cout
        let mut questions: Vec<DNSQuestion> = vec![];

        loop {
            if i >= count as usize {
                break;
            }

            let labels = buffer.parse_labels()?;
            let q_type = buffer.read_u16();
            let q_class = buffer.read_u16();

            questions.push(DNSQuestion {
                qname: labels,
                qtype: q_type,
                qclass: q_class,
            });

            i = i + 1;
        }

        Ok(questions)
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), String> {
        buffer.push_labels(&self.qname)?;
        buffer.write_u16(self.qtype);
        buffer.write_u16(self.qclass);

        Ok(())
    }

    pub fn from_simple_string(domain: &str, q_type: u16, q_class: u16) -> Self {
        let labels_raw: Vec<&str> = domain.split(".").collect();

        let lables = labels_raw.iter().map(|m| DNSLabel {
            value: m.to_string(),
            offset: None,
        }).collect();

        return Self {
            qname: lables,
            qclass: q_class,
            qtype: q_type,
        };
    }
}
