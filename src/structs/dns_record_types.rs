use super::{
    dns_packet_buffer::DNSPacketBuffer,
    error::ParseError,
    record_types::{
        a_record::ARecord,
        aaaa_record::AAAARecord,
        cname_record::CNAMERecord,
        mx_record::MXRecord,
        ns_record::{NSRecord, PTRRecord},
        soa_record::SOARecord,
        srv_record::SRVRecord,
        txt_record::TXTRecord,
    },
};

// Define an enum for DNS record types
#[derive(Debug, Clone)]
pub enum DNSRecord {
    A(ARecord),
    AAAA(AAAARecord),
    CNAME(CNAMERecord),
    MX(MXRecord),
    TXT(TXTRecord),
    SRV(SRVRecord),
    NS(NSRecord),
    PTR(PTRRecord),
    SOA(SOARecord),
    Unknown {
        record_type: u16,
        data_length: usize,
        raw_data: Vec<u8>,
    },
}

impl DNSRecord {
    pub fn parse_dns_record_data(
        record_type: u16,
        data_length: usize,
        data: &[u8],
    ) -> Result<DNSRecord, ParseError> {
        if data.len() < data_length as usize {
            return Err(ParseError::InvalidResourceRecord {
                msg: "Invalid DNS record: Data length does not match actual data".to_string(),
            });
        }

        match record_type {
            // Handle known record types
            1 => Ok(DNSRecord::A(ARecord::parse(data_length as usize, &data)?)),
            28 => Ok(DNSRecord::AAAA(AAAARecord::parse(
                data_length as usize,
                &data,
            )?)),
            // Handle other known record types here...
            5 => Ok(DNSRecord::CNAME(CNAMERecord::parse(
                data_length as usize,
                &data,
            )?)),
            15 => {
                // Parse MX record
                Ok(DNSRecord::MX(MXRecord::parse(data_length as usize, &data)?))
            }
            16 => Ok(DNSRecord::TXT(TXTRecord::parse(
                data_length as usize,
                &data,
            )?)),
            33 => Ok(DNSRecord::SRV(SRVRecord::parse(
                data_length as usize,
                &data,
            )?)),
            2 => Ok(DNSRecord::NS(NSRecord::parse(data_length as usize, &data)?)),
            12 => Ok(DNSRecord::PTR(PTRRecord::parse(
                data_length as usize,
                &data,
            )?)),
            6 => Ok(DNSRecord::SOA(SOARecord::parse(
                data_length as usize,
                &data,
            )?)),
            // For unknown record types, store raw data
            _ => Ok(DNSRecord::Unknown {
                record_type,
                data_length,
                raw_data: data.to_vec(),
            }),
        }
    }
    pub fn write_to_bytes(&self, buffer: &mut DNSPacketBuffer) {
        match self {
            DNSRecord::A(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::AAAA(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::CNAME(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::MX(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::TXT(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::SRV(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::NS(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::PTR(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::SOA(record) => {
                record.write_to_buffer(buffer);
            }
            DNSRecord::Unknown {
                record_type,
                data_length,
                raw_data,
            } => todo!(),
        }
    }
}
