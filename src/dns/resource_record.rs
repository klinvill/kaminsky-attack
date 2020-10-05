use crate::dns::classes::Class;
use crate::dns::hostname::Hostname;
use crate::dns::types::Type;
use num_traits::FromPrimitive;

#[derive(PartialEq, Debug)]
/// Resource record format as specified in IETF RFC 1035
pub(crate) struct ResourceRecord {
    pub(crate) name: Hostname,
    pub(crate) rtype: Type,
    pub(crate) class: Class,
    pub(crate) ttl: u32,
    pub(crate) rdlength: u16,
    pub(crate) rdata: Vec<u8>,
}

#[derive(PartialEq, Debug)]
struct PackedResourceRecord {
    data: Vec<u8>,
}

pub(crate) struct ParsedResourceRecord {
    /// Number of buffer bytes parsed to construct a resource record
    pub(crate) parsed_bytes: u8,
    pub(crate) record: ResourceRecord,
}

impl ResourceRecord {
    fn pack(&self) -> PackedResourceRecord {
        let mut packed = Vec::new();
        packed.extend(self.name.to_bytes());
        packed.extend(&(self.rtype as u16).to_le_bytes());
        packed.extend(&(self.class as u16).to_le_bytes());
        packed.extend(&self.ttl.to_le_bytes());
        packed.extend(&self.rdlength.to_le_bytes());
        packed.extend(&self.rdata);
        return PackedResourceRecord { data: packed };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        return self.pack().data;
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<ParsedResourceRecord, String> {
        let mut parsed_bytes: usize = 0;

        let parsed_hostname = Hostname::parse(buffer)?;
        parsed_bytes += parsed_hostname.parsed_bytes as usize;

        let rtype_int = u16::from_le_bytes([buffer[parsed_bytes], buffer[parsed_bytes + 1]]);
        let rtype = match Type::from_u16(rtype_int) {
            None => return Err(format!("Unsupported QTYPE {}", rtype_int)),
            Some(op) => op,
        };
        parsed_bytes += 2;

        let class_int = u16::from_le_bytes([buffer[parsed_bytes], buffer[parsed_bytes + 1]]);
        let class = match Class::from_u16(class_int) {
            None => return Err(format!("Unsupported QCLASS {}", class_int)),
            Some(op) => op,
        };
        parsed_bytes += 2;

        let ttl = u32::from_le_bytes([
            buffer[parsed_bytes],
            buffer[parsed_bytes + 1],
            buffer[parsed_bytes + 2],
            buffer[parsed_bytes + 3],
        ]);
        parsed_bytes += 4;

        let rdlength = u16::from_le_bytes([buffer[parsed_bytes], buffer[parsed_bytes + 1]]);
        parsed_bytes += 2;

        let rdata: Vec<u8> = buffer[parsed_bytes..parsed_bytes + rdlength as usize].to_vec();
        parsed_bytes += rdlength as usize;

        if parsed_bytes > u8::max_value() as usize {
            return Err("Parsed more bytes than can fit into a u8".to_string());
        }

        return Ok(ParsedResourceRecord {
            parsed_bytes: parsed_bytes as u8,
            record: ResourceRecord {
                name: parsed_hostname.hostname,
                rtype,
                class,
                ttl,
                rdlength,
                rdata,
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::classes::Class;
    use crate::dns::hostname::Hostname;
    use crate::dns::resource_record::{PackedResourceRecord, ResourceRecord};
    use crate::dns::types::Type;

    #[test]
    fn pack_resource_record() {
        let record = ResourceRecord {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let mut expected_data = Vec::new();
        expected_data.push(3);
        expected_data.extend("www".as_bytes());
        expected_data.push(7);
        expected_data.extend("example".as_bytes());
        expected_data.push(3);
        expected_data.extend("com".as_bytes());
        expected_data.push(0);
        expected_data.extend(&(Type::A as u16).to_le_bytes());
        expected_data.extend(&(Class::IN as u16).to_le_bytes());
        expected_data.extend(&(0x258 as u32).to_le_bytes());
        expected_data.extend(&(4 as u16).to_le_bytes());
        expected_data.extend(&(0x9b211144 as u32).to_le_bytes());
        let expected = PackedResourceRecord {
            data: expected_data,
        };
        assert_eq!(expected, record.pack())
    }

    #[test]
    fn parse_resource_record() {
        let extra_bytes = (0x12345678 as u32).to_le_bytes();

        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_le_bytes());
        bytes.extend(&(Class::IN as u16).to_le_bytes());
        bytes.extend(&(0x258 as u32).to_le_bytes());
        bytes.extend(&(4 as u16).to_le_bytes());
        bytes.extend(&(0x9b211144 as u32).to_le_bytes());
        bytes.extend(&extra_bytes);

        let record_length = bytes.len() - extra_bytes.len();

        let expected = ResourceRecord {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let result = ResourceRecord::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.record);
        assert_eq!(record_length, result.parsed_bytes as usize);
    }
}
