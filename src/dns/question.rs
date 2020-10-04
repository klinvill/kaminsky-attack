use crate::dns::classes::Class;
use crate::dns::hostname::Hostname;
use crate::dns::types::Type;

/// DNS question section with fields as specified in IETF RFC 1035
pub(crate) struct Question<'question> {
    pub(crate) qname: Hostname<'question>,
    pub(crate) qtype: Type,
    pub(crate) qclass: Class,
}

#[derive(PartialEq, Debug)]
struct PackedQuestion {
    data: Vec<u8>,
}

impl Question<'_> {
    fn pack(&self) -> PackedQuestion {
        let mut packed = Vec::new();
        packed.extend(self.qname.to_bytes());
        packed.extend(&(self.qtype as u16).to_le_bytes());
        packed.extend(&(self.qclass as u16).to_le_bytes());
        return PackedQuestion { data: packed };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        return self.pack().data;
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::classes::Class;
    use crate::dns::hostname::Hostname;
    use crate::dns::question::{PackedQuestion, Question};
    use crate::dns::types::Type;

    #[test]
    fn pack_aligned_question() {
        let question = Question {
            qname: Hostname::from_string("www.example.com").unwrap(),
            qtype: Type::A,
            qclass: Class::IN,
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
        let expected = PackedQuestion {
            data: expected_data,
        };
        assert_eq!(expected, question.pack())
    }
}
