use crate::dns::classes::Class;
use crate::dns::hostname::Hostname;
use crate::dns::types::Type;
use num_traits::FromPrimitive;

#[derive(PartialEq, Debug)]
/// DNS question section with fields as specified in IETF RFC 1035
pub(crate) struct Question {
    pub(crate) qname: Hostname,
    pub(crate) qtype: Type,
    pub(crate) qclass: Class,
}

#[derive(PartialEq, Debug)]
struct PackedQuestion {
    data: Vec<u8>,
}

pub(crate) struct ParsedQuestion {
    /// Number of buffer bytes parsed to construct a question
    pub(crate) parsed_bytes: u8,
    pub(crate) question: Question,
}

impl Question {
    fn pack(&self) -> PackedQuestion {
        let mut packed = Vec::new();
        packed.extend(self.qname.to_bytes());
        packed.extend(&(self.qtype as u16).to_be_bytes());
        packed.extend(&(self.qclass as u16).to_be_bytes());
        return PackedQuestion { data: packed };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        return self.pack().data;
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<ParsedQuestion, String> {
        let mut parsed_bytes: usize = 0;

        let parsed_hostname = Hostname::parse(buffer)?;
        parsed_bytes += parsed_hostname.parsed_bytes as usize;

        let qtype_int = u16::from_be_bytes([buffer[parsed_bytes], buffer[parsed_bytes + 1]]);
        let qtype = match Type::from_u16(qtype_int) {
            None => return Err(format!("Unsupported QTYPE {}", qtype_int)),
            Some(op) => op,
        };
        parsed_bytes += 2;

        let qclass_int = u16::from_be_bytes([buffer[parsed_bytes], buffer[parsed_bytes + 1]]);
        let qclass = match Class::from_u16(qclass_int) {
            None => return Err(format!("Unsupported QCLASS {}", qclass_int)),
            Some(op) => op,
        };
        parsed_bytes += 2;

        if parsed_bytes > u8::max_value() as usize {
            return Err("Parsed more bytes than can fit into a u8".to_string());
        }

        return Ok(ParsedQuestion {
            parsed_bytes: parsed_bytes as u8,
            question: Question {
                qname: parsed_hostname.hostname,
                qtype,
                qclass,
            },
        });
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
        expected_data.push(0);
        expected_data.extend(&(Type::A as u16).to_be_bytes());
        expected_data.extend(&(Class::IN as u16).to_be_bytes());
        let expected = PackedQuestion {
            data: expected_data,
        };
        assert_eq!(expected, question.pack())
    }

    #[test]
    fn parse_question() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&extra_bytes);

        let question_length = bytes.len() - extra_bytes.len();

        let expected = Question {
            qname: Hostname::from_string("www.example.com").unwrap(),
            qtype: Type::A,
            qclass: Class::IN,
        };

        let result = Question::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.question);
        assert_eq!(question_length, result.parsed_bytes as usize);
    }
}
