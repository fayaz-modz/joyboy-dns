use super::error::ParseError;

#[derive(Debug, Clone)]
pub struct DNSLabel {
    pub value: String,
    pub offset: Option<usize>,
}

pub struct DNSPacketBuffer {
    pub buffer: [u8; 512],
    pub offset: usize,
    pub domains: Vec<Vec<DNSLabel>>,
}

impl DNSPacketBuffer {
    pub fn new(buffer: [u8; 512]) -> Self {
        Self {
            buffer,
            offset: 0,
            domains: Vec::new(),
        }
    }

    pub fn small(buffer: &[u8]) -> Self {
        let mut nbuffer = [0u8; 512];
        for i in 0..buffer.len() {
            nbuffer[i] = buffer[i];
        }

        Self {
            buffer: nbuffer,
            offset: 0,
            domains: Vec::new(),
        }
    }

    pub fn next_chunk(&mut self, size: usize) -> &[u8] {
        let val = &self.buffer[self.offset..self.offset + size];
        self.offset += size;
        val
    }

    pub fn read_u16(&mut self) -> u16 {
        let val = ((self.buffer[self.offset] as u16) << 8) | (self.buffer[self.offset + 1] as u16);
        self.offset += 2;
        val
    }

    pub fn read_u32(&mut self) -> u32 {
        let val = ((self.buffer[self.offset] as u32) << 24)
            | ((self.buffer[self.offset + 1] as u32) << 16)
            | ((self.buffer[self.offset + 2] as u32) << 8)
            | (self.buffer[self.offset + 3] as u32);
        self.offset += 4;
        val
    }

    pub fn write_u8(&mut self, val: u8) {
        self.buffer[self.offset] = val;
        self.offset += 1;
    }

    pub fn write_u16(&mut self, val: u16) {
        self.buffer[self.offset] = (val >> 8) as u8;
        self.offset += 1;
        self.buffer[self.offset] = (val & 0x00FF) as u8;
        self.offset += 1;
    }

    pub fn write_u32(&mut self, val: u32) {
        self.buffer[self.offset] = (val >> 24) as u8;
        self.offset += 1;
        self.buffer[self.offset] = (val >> 16) as u8;
        self.offset += 1;
        self.buffer[self.offset] = (val >> 8) as u8;
        self.offset += 1;
        self.buffer[self.offset] = (val & 0x0000_00FF) as u8;
        self.offset += 1;
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for i in 0..bytes.len() {
            self.buffer[self.offset + i] = bytes[i].clone();
        }
        self.offset += bytes.len();
    }

    /// this requires the full packet to be passed
    /// for the compression algorithm to work
    pub fn parse_labels(&mut self) -> Result<Vec<DNSLabel>, ParseError> {
        let mut labels: Vec<DNSLabel> = vec![];

        let max_pointers: usize = 10;
        let mut is_pointer: bool = false;
        let mut pointer_count: usize = 0;

        // the offset before jumping
        let mut jump_prev_offset: usize = 0;
        while self.buffer[self.offset] != 0 {
            // jump
            if (self.buffer[self.offset] & 0xC0) == 0xC0 {
                if pointer_count > max_pointers {
                    return Err(ParseError::InvalidQuestion {
                        msg: "Maximum pointers exceeded. 
                              To avoid an overflow, the maximum number of pointers is 10"
                            .to_string(),
                    });
                }
                is_pointer = true;
                pointer_count += 1;
                jump_prev_offset = self.offset;

                let mut pointer = self.read_u16();
                pointer = (pointer & 0x3FFF) as u16;
                self.offset = pointer as usize;
                continue;
            }

            let mut current_label = String::new();

            let label_length = &self.buffer[self.offset];
            self.offset += 1;

            let label = &self.buffer[self.offset..(self.offset + *label_length as usize)];
            self.offset += *label_length as usize;

            for item in label {
                current_label.push(*item as char);
            }

            // the offset must be none for future purposes
            labels.push(DNSLabel {
                value: current_label,
                offset: None,
            });
        }

        if is_pointer {
            self.offset = jump_prev_offset;
        }

        // now the current offset is a null byte
        // so we skip a byte
        // if jumps we are skipping the pointer
        self.offset += 1;

        Ok(labels)
    }

    pub fn push_labels(&mut self, labels: &Vec<DNSLabel>) -> Result<(), String> {
        let mut pointer_offset = 0;
        let mut pointer_accuracy = 0;

        for domain_index in 0..self.domains.len() {
            let domain = &self.domains[domain_index];

            let mut new_pointer_offset = 0;
            let mut new_pointer_accuracy = 0;

            let mut i = domain.len() - 1;
            for label in labels.iter().rev() {
                if i >= domain.len() {
                    break;
                }
                // the main compression logic
                let clabel = domain[i].clone();
                match clabel.offset {
                    Some(offset) => {
                        if clabel.value == label.value {
                            new_pointer_accuracy += 1;
                            new_pointer_offset = offset;
                        }
                    }
                    None => {}
                }

                if i > 0 {
                    i -= 1;
                } else {
                    break;
                }
            }

            if new_pointer_accuracy > pointer_accuracy {
                pointer_accuracy = new_pointer_accuracy;
                pointer_offset = new_pointer_offset;
            }
        }

        // we found pointers for the labels
        if pointer_accuracy > 0 {
            // found full domain
            if pointer_accuracy == labels.len() {
                if pointer_offset > 63 {
                    // :( pointer cannot be made
                    return Err("label could not be made. Greater than 63 characters".to_string());
                }
                let mut pointer = 0xC000;
                pointer |= pointer_offset as u16;
                self.write_u16(pointer);
            } else if pointer_accuracy < labels.len() {
                // not using this condition for future pointer
                // to avoid nested pointers
                for i in 0..(labels.len() - pointer_accuracy) {
                    let label = &labels[i];
                    self.write_u8(label.value.len() as u8);
                    self.write_bytes(label.value.as_bytes());
                }
                let pointer_bytes = 0xC000 | (pointer_offset as u16);
                self.write_u16(pointer_bytes);
            } else {
                // this should not exist
            }
        } else {
            let mut new_domain: Vec<DNSLabel> = vec![];
            // no pointers found
            for label in labels {
                // TODO: optimise this
                let mut new_label = label.clone();
                new_label.offset = Some(self.offset);
                new_domain.push(new_label);

                self.write_u8(label.value.len() as u8);
                self.write_bytes(label.value.as_bytes());
            }

            self.domains.push(new_domain);
        }

        // end with empty bytes
        if pointer_accuracy <= 0 {
            self.write_u8(0);
        }

        Ok(())
    }

    pub fn read_character_string(&mut self) -> Result<String, ParseError> {
        let mut string = String::new();

        Ok(string)
    }

    pub fn remaining_bytes(&self, size: usize) -> bool {
        self.offset + size >= self.buffer.len()
    }

    pub fn response_bytes(&self) -> &[u8] {
        self.buffer[0..self.offset].as_ref()
    }

    pub fn base_packet(&self) -> &[u8] {
        let mut offset = 0;

        for i in 0..self.buffer.len() {
            if self.buffer[i] != 0 {
                offset = i;
            }
        }

        &self.buffer[0..(offset + 1)]
    }
}
