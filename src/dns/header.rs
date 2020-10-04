/// DNS Header with fields as specified in IETF RFC 1035
///
/// This struct does not layout the bits exactly as specified in RFC 1035. Instead it needs to be
/// converted to a packed_header
struct Header {
    id: u16,
    qr: bool,
    opcode: Opcode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,     // ideally u3
    rcode: u8, // ideally u4
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[derive(PartialEq, Debug)]
/// DNS Header packed into 16-bit fields
struct PackedHeader {
    data: [u16; 6],
}

#[repr(u8)]
#[derive(Copy, Clone)]
/// Opcode as specified in RFC 1035
enum Opcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
}

impl Header {
    fn pack(&self) -> PackedHeader {
        let second_u16: u16 = 0 ^ self.qr as u16
            ^ ((self.opcode as u16 & 0b1111) << 1)
            ^ ((self.aa as u16) << 5)
            ^ ((self.tc as u16) << 6)
            ^ ((self.rd as u16) << 7)
            ^ ((self.ra as u16) << 8)
            ^ (0)   // z bits are only set to 0 in RFC 1035
            ^ ((self.rcode as u16 & 0b1111) << 12);
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
            z: 7,   // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 3,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };

        let expected = PackedHeader { data: [0xdb42, 0b0011000010000000, 1, 2, 3, 4] };
        assert_eq!(expected, header.pack());
    }
}