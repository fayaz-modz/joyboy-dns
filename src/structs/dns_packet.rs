use crate::utils::contains_domain;

use super::dns_flags::DNSFlags;
use super::dns_header::DNSHeader;
use super::dns_packet_buffer::{DNSLabel, DNSPacketBuffer};
use super::dns_question::DNSQuestion;
use super::dns_resource_record::DNSResourceRecord;
use super::error::ParseError;

#[derive(Debug)]
pub struct DNSPacket {
    /// contains the information about the packet
    /// The header contains the following fields:
    ///.                               1  1  1  1  1  1
    ///. 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      ID                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QDCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ANCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    NSCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ARCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub header: DNSHeader,
    /// contains the questions
    pub questions: Vec<DNSQuestion>,
    /// contains the RRs answering the questions
    pub answers: Vec<DNSResourceRecord>,
    /// contains the RRs pointing to the authorities
    pub authorities: Vec<DNSResourceRecord>,
    /// contains the RRs containing additional information
    pub additionals: Vec<DNSResourceRecord>,
}

impl DNSPacket {
    pub fn new() -> Self {
        DNSPacket {
            header: DNSHeader {
                id: 0,
                flags: DNSFlags {
                    qr: false,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: false,
                    ra: false,
                    z: 0,
                    rcode: 0,
                },
                questions_count: 0,
                additionals_count: 0,
                answers_count: 0,
                authorities_count: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn push_questions(&mut self, questions: DNSQuestion) -> &mut Self {
        self.questions.push(questions);
        self
    }

    pub fn push_answers(&mut self, answers: DNSResourceRecord) -> &mut Self {
        self.answers.push(answers);
        self
    }

    pub fn push_authorities(&mut self, authorities: DNSResourceRecord) -> &mut Self {
        self.authorities.push(authorities);
        self
    }

    pub fn push_additionals(&mut self, additionals: DNSResourceRecord) -> &mut Self {
        self.additionals.push(additionals);
        self
    }

    pub fn parse(packet: [u8; 512]) -> Result<Self, ParseError> {
        let mut buffer = DNSPacketBuffer::new(packet);
        let header = DNSHeader::parse(&mut buffer)?;

        let questions: Vec<DNSQuestion> =
            DNSQuestion::parse_questions(header.questions_count as usize, &mut buffer)?;
        let answers: Vec<DNSResourceRecord> =
            DNSResourceRecord::parse_multiple(header.answers_count as usize, &mut buffer)?;
        let authorities: Vec<DNSResourceRecord> =
            DNSResourceRecord::parse_multiple(header.authorities_count as usize, &mut buffer)?;
        let additionals: Vec<DNSResourceRecord> =
            DNSResourceRecord::parse_multiple(header.additionals_count as usize, &mut buffer)?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), String> {
        // writing the header
        self.header.write_to_buffer(buffer);

        // writing the questions
        for question in self.questions.iter() {
            question.write_to_buffer(buffer)?;
        }

        // writing the answers
        for answer in self.answers.iter() {
            answer.write_to_buffer(buffer)?;
        }

        // writing the authorities
        for authority in self.authorities.iter() {
            authority.write_to_buffer(buffer)?;
        }

        // writing the additionals
        for additional in self.additionals.iter() {
            additional.write_to_buffer(buffer)?;
        }

        Ok(())
    }

    pub fn contains_question(&self, domain: Vec<DNSLabel>) -> bool {
        let mut found_match = false;
        let domain_size = domain.len();

        for question_check in &self.questions {
            if question_check.qname.len() != domain_size {
                continue;
            }

            if contains_domain(&question_check.qname, &domain, domain_size) {
                found_match = true;
            }

            if found_match {
                break;
            }
        }

        return found_match;
    }

    pub fn contains_resource_record(
        &self,
        domain: Vec<DNSLabel>,
        rrtype: PacketRecordType,
    ) -> Option<DNSResourceRecord> {
        let mut found_match = false;
        let mut result = None::<DNSResourceRecord>;
        let domain_size = domain.len();

        let check_rrs = match rrtype {
            PacketRecordType::Answer => &self.answers,
            PacketRecordType::Authority => &self.authorities,
            PacketRecordType::Additional => &self.additionals,
        };

        for check in check_rrs {
            if contains_domain(&check.name, &domain, domain_size) {
                found_match = true;
                result = Some(check.clone());
            }

            if found_match {
                break;
            }
        }

        result
    }
}

pub enum PacketRecordType {
    Answer,
    Authority,
    Additional,
}
