use crate::dns::classes::Class;
use crate::dns::hostname::Hostname;
use crate::dns::types::Type;

/// Resource record format as specified in IETF RFC 1035
pub(crate) struct ResourceRecord<'record> {
    pub(crate) name: Hostname<'record>,
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

impl ResourceRecord<'_> {
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
}
