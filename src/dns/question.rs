use crate::dns::hostname::Hostname;

/// DNS question section with fields as specified in IETF RFC 1035
struct Question<'question> {
    qname: Hostname<'question>,
    qtype: u16,
    qclass: u16,
}

#[derive(PartialEq, Debug)]
struct PackedQuestion {
    data: Vec<u8>,
}

impl Question<'_> {
    fn pack(&self) -> PackedQuestion {
        let mut packed = Vec::new();
        packed.extend(self.qname.to_bytes());
        packed.extend(&self.qtype.to_le_bytes());
        packed.extend(&self.qclass.to_le_bytes());
        return PackedQuestion { data: packed };
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::hostname::Hostname;
    use crate::dns::question::{PackedQuestion, Question};

    #[test]
    fn pack_aligned_question() {
        let question = Question {
            qname: Hostname::from_string("www.example.com").unwrap(),
            qtype: 1,
            qclass: 2,
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
        let expected = PackedQuestion {
            data: expected_data,
        };
        assert_eq!(expected, question.pack())
    }
}
