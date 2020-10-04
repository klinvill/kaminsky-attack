use crate::dns::hostname::Hostname;

/// Resource record format as specified in IETF RFC 1035
struct ResourceRecord<'record> {
    name: Hostname<'record>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

#[derive(PartialEq, Debug)]
struct PackedResourceRecord {
    data: Vec<u8>,
}

impl ResourceRecord<'_> {
    fn pack(&self) -> PackedResourceRecord {
        let mut packed = Vec::new();
        packed.extend(self.name.to_bytes());
        packed.extend(&self.rtype.to_le_bytes());
        packed.extend(&self.class.to_le_bytes());
        packed.extend(&self.ttl.to_le_bytes());
        packed.extend(&self.rdlength.to_le_bytes());
        packed.extend(&self.rdata);
        return PackedResourceRecord { data: packed };
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::hostname::Hostname;
    use crate::dns::resource_record::{PackedResourceRecord, ResourceRecord};

    #[test]
    fn pack_resource_record() {
        let question = ResourceRecord {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: 1,
            class: 2,
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
        expected_data.extend(&(1 as u16).to_le_bytes());
        expected_data.extend(&(2 as u16).to_le_bytes());
        expected_data.extend(&(0x258 as u32).to_le_bytes());
        expected_data.extend(&(4 as u16).to_le_bytes());
        expected_data.extend(&(0x9b211144 as u32).to_le_bytes());
        let expected = PackedResourceRecord {
            data: expected_data,
        };
        assert_eq!(expected, question.pack())
    }
}
