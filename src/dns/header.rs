use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(PartialEq, Debug)]
/// DNS Header with fields as specified in IETF RFC 1035
///
/// This struct does not layout the bits exactly as specified in RFC 1035. Instead it needs to be
/// converted to a packed_header
pub(crate) struct Header {
    pub(crate) id: u16,
    pub(crate) qr: bool,
    pub(crate) opcode: Opcode,
    pub(crate) aa: bool,
    pub(crate) tc: bool,
    pub(crate) rd: bool,
    pub(crate) ra: bool,
    pub(crate) z: u8,     // ideally u3
    pub(crate) rcode: u8, // ideally u4
    pub(crate) qdcount: u16,
    pub(crate) ancount: u16,
    pub(crate) nscount: u16,
    pub(crate) arcount: u16,
}

#[derive(PartialEq, Debug)]
/// DNS Header packed into 16-bit fields
struct PackedHeader {
    data: [u16; 6],
}

pub(crate) struct ParsedHeader {
    /// Number of buffer bytes parsed to construct the header
    pub(crate) parsed_bytes: usize,
    pub(crate) header: Header,
}

/// Field in header
///
/// All fields are assumed to be 2 bytes long since this is compliant with RFC 1035
struct Field {
    /// offset in bytes
    offset: usize,
}

const FIELD_ID: Field = Field { offset: 0 };
const FIELD_FLAGS: Field = Field { offset: 2 };
const FIELD_QDCOUNT: Field = Field { offset: 4 };
const FIELD_ANCOUNT: Field = Field { offset: 6 };
const FIELD_NSCOUNT: Field = Field { offset: 8 };
const FIELD_ARCOUNT: Field = Field { offset: 10 };

/// Flag in header
struct Flag {
    /// bit offset in the flags section, the second 16 bits of the header
    offset: u8,
    /// number of bits for the flag
    width: usize,
}

// Flags in header
const FLAG_QR: Flag = Flag {
    offset: 0,
    width: 1,
};
const FLAG_OPCODE: Flag = Flag {
    offset: 1,
    width: 4,
};
const FLAG_AA: Flag = Flag {
    offset: 5,
    width: 1,
};
const FLAG_TC: Flag = Flag {
    offset: 6,
    width: 1,
};
const FLAG_RD: Flag = Flag {
    offset: 7,
    width: 1,
};
const FLAG_RA: Flag = Flag {
    offset: 8,
    width: 1,
};
const FLAG_Z: Flag = Flag {
    offset: 9,
    width: 3,
};
const FLAG_RCODE: Flag = Flag {
    offset: 12,
    width: 4,
};

const BITMASKS: [u16; 8] = [0b0, 0b1, 0b11, 0b111, 0b1111, 0b11111, 0b111111, 0b1111111];

#[repr(u8)]
#[derive(FromPrimitive, PartialEq, Debug, Copy, Clone)]
/// Opcode as specified in RFC 1035
pub(crate) enum Opcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
}

impl Header {
    fn pack(&self) -> PackedHeader {
        let second_u16: u16 = 0 ^ self.qr as u16
            ^ ((self.opcode as u16 & BITMASKS[FLAG_OPCODE.width]) << FLAG_OPCODE.offset)
            ^ ((self.aa as u16) << FLAG_AA.offset)
            ^ ((self.tc as u16) << FLAG_TC.offset)
            ^ ((self.rd as u16) << FLAG_RD.offset)
            ^ ((self.ra as u16) << FLAG_RA.offset)
            ^ (0)   // z bits are only set to 0 in RFC 1035
            ^ ((self.rcode as u16 & BITMASKS[FLAG_RCODE.width]) << FLAG_RCODE.offset);
        return PackedHeader {
            data: [
                self.id,
                second_u16,
                self.qdcount,
                self.ancount,
                self.nscount,
                self.arcount,
            ],
        };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        return self
            .pack()
            .data
            .iter()
            .flat_map(|entry| return entry.to_le_bytes().to_vec())
            .collect();
    }

    fn from_bytes(buffer: &[u8]) -> Result<Header, String> {
        let packed_flags =
            u16::from_le_bytes([buffer[FIELD_FLAGS.offset], buffer[FIELD_FLAGS.offset + 1]]);
        let opcode_int = (packed_flags & BITMASKS[FLAG_OPCODE.width]) >> FLAG_OPCODE.offset;
        let opcode = match Opcode::from_u16(opcode_int) {
            None => return Err(format!("Unsupported opcode {}", opcode_int)),
            Some(op) => op,
        };

        return Ok(Header {
            id: u16::from_le_bytes([buffer[FIELD_ID.offset], buffer[FIELD_ID.offset + 1]]),
            qdcount: u16::from_le_bytes([
                buffer[FIELD_QDCOUNT.offset],
                buffer[FIELD_QDCOUNT.offset + 1],
            ]),
            ancount: u16::from_le_bytes([
                buffer[FIELD_ANCOUNT.offset],
                buffer[FIELD_ANCOUNT.offset + 1],
            ]),
            nscount: u16::from_le_bytes([
                buffer[FIELD_NSCOUNT.offset],
                buffer[FIELD_NSCOUNT.offset + 1],
            ]),
            arcount: u16::from_le_bytes([
                buffer[FIELD_ARCOUNT.offset],
                buffer[FIELD_ARCOUNT.offset + 1],
            ]),
            // Flags
            qr: packed_flags & BITMASKS[FLAG_QR.width] >> FLAG_QR.offset != 0,
            opcode,
            aa: (packed_flags >> FLAG_AA.offset) & BITMASKS[FLAG_AA.width] != 0,
            tc: (packed_flags >> FLAG_TC.offset) & BITMASKS[FLAG_TC.width] != 0,
            rd: (packed_flags >> FLAG_RD.offset) & BITMASKS[FLAG_RD.width] != 0,
            ra: (packed_flags >> FLAG_RA.offset) & BITMASKS[FLAG_RA.width] != 0,
            z: ((packed_flags >> FLAG_Z.offset) & BITMASKS[FLAG_Z.width]) as u8,
            rcode: ((packed_flags >> FLAG_RCODE.offset) & BITMASKS[FLAG_RCODE.width]) as u8,
        });
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<ParsedHeader, String> {
        // RFC 1035 specifies a header format that is effectively 6 2-byte fields
        let parsed_bytes = 2 * 6;

        let header = Header::from_bytes(buffer)?;

        return Ok(ParsedHeader {
            parsed_bytes,
            header,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::header::{Header, Opcode, PackedHeader};

    #[test]
    fn pack_simple_header() {
        let header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 3,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        let expected = PackedHeader {
            data: [0xdb42, 0b0011000010000000, 1, 2, 3, 4],
        };
        assert_eq!(expected, header.pack());
    }

    #[test]
    fn simple_header_to_bytes() {
        let header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 3,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        let expected: Vec<u8> = vec![0x42, 0xdb, 0b10000000, 0b00110000, 1, 0, 2, 0, 3, 0, 4, 0];
        assert_eq!(expected, header.to_bytes());
    }

    #[test]
    fn parse_simple_header() {
        let extra_bytes = (0x12345678 as u32).to_le_bytes();

        let mut bytes: Vec<u8> = vec![0x42, 0xdb, 0b10000000, 0b00110000, 1, 0, 2, 0, 3, 0, 4, 0];
        bytes.extend(&extra_bytes);

        let header_length: usize = 12;

        let expected_header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: 3,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        let result = Header::parse(bytes.as_slice()).unwrap();
        assert_eq!(header_length, result.parsed_bytes as usize);
        assert_eq!(expected_header, result.header);
    }

    #[test]
    fn parse_rd_header() {
        let extra_bytes = (0x12345678 as u32).to_le_bytes();

        let mut bytes: Vec<u8> = vec![
            // Header
            0x42, 0xdb, 0b10000001, 0b00000000, 0, 0, 1, 0, 0, 0, 0, 0,
        ];
        bytes.extend(&extra_bytes);

        let header_length: usize = 12;

        let expected_header = Header {
            id: 0xdb42,
            qr: true,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0, // z should always be 0 as per RFC 1035
            rcode: 0,
            qdcount: 0,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let result = Header::parse(bytes.as_slice()).unwrap();
        assert_eq!(header_length, result.parsed_bytes as usize);
        assert_eq!(expected_header, result.header);
    }

    #[test]
    fn to_and_from_bytes_produce_orginal_input() {
        let header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0, // z should be set to 0 as specified in RFC 1035
            rcode: 3,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        assert_eq!(
            header,
            Header::from_bytes(header.to_bytes().as_slice()).unwrap()
        );
    }

    #[test]
    fn from_and_to_bytes_produce_orginal_input() {
        let bytes: [u8; 12] = [0x42, 0xdb, 0b10000000, 0b00110000, 1, 0, 2, 0, 3, 0, 4, 0];
        assert_eq!(
            bytes,
            Header::from_bytes(&bytes).unwrap().to_bytes().as_slice()
        );
    }
}
