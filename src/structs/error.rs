#[derive(Debug)]
pub enum ParseError {
    // InvalidPacket { msg: String },
    InvalidHeader { msg: String },
    InvalidQuestion { msg: String },
    InvalidResourceRecord { msg: String },
}
