use std::net::Ipv4Addr;

use crate::structs::{
    dns_header::DNSHeader, dns_packet::DNSPacket, dns_packet_buffer::DNSLabel,
    dns_question::DNSQuestion, dns_record_types::DNSRecord, dns_resource_record::DNSResourceRecord,
    record_types::a_record::ARecord,
};

pub fn print_bytes_to_hex(data: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();

    for chunk in data.chunks(16) {
        lines.push(chunk.to_vec());
    }

    for line in &lines {
        for byte in line {
            print!("{:02X} ", byte);
        }
        for _ in 0..16 - line.len() {
            print!("{:02X} ", 0);
        }
        for &byte in line {
            if byte.is_ascii_graphic() {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }

    lines
}

pub fn temp_dns_packet(header: DNSHeader, questions: Vec<DNSQuestion>) -> DNSPacket {
    let mut packet = DNSPacket::new();
    packet.questions = questions;

    let answers = DNSResourceRecord::new()
        .push_name_label(String::from("www"))
        .push_name_label(String::from("google"))
        .push_name_label(String::from("com"))
        .rtype(ARecord::TYPE)
        .ttl(50)
        .class(1)
        .rdlength(4)
        .data(DNSRecord::A(ARecord(Ipv4Addr::new(127, 0, 0, 1))));

    packet.push_answers(answers);
    packet.header = DNSHeader::from_dns_struct(&packet, header.id);
    packet
}

pub fn contains_domain(lables: &Vec<DNSLabel>, domain: &Vec<DNSLabel>, domain_size: usize) -> bool {
    let mut match_count = 0;
    let mut i = 0;
    for check in lables.iter().rev() {
        if check.value == domain[domain_size - 1 - i].value {
            match_count += 1;
        } else {
            break;
        }

        i += 1;
    }

    domain.len() == lables.len()
}

pub trait ToDNSLabels {
    fn to_dns_labels(&self) -> Vec<DNSLabel>;
}

impl ToDNSLabels for String {
    fn to_dns_labels(&self) -> Vec<DNSLabel> {
        self.split('.')
            .map(|label| DNSLabel {
                value: label.to_string(),
                offset: None,
            })
            .collect()
    }
}

impl ToDNSLabels for &str {
    fn to_dns_labels(&self) -> Vec<DNSLabel> {
        self.split('.')
            .map(|label| DNSLabel {
                value: label.to_string(),
                offset: None,
            })
            .collect()
    }
}
