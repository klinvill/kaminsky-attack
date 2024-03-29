use crate::dns::additional::Additional;
use crate::dns::answer::Answer;
use crate::dns::authority::Authority;
use crate::dns::header::Header;
use crate::dns::question::Question;

#[derive(PartialEq, Clone, Debug)]
/// DNS message format as specified in IETF RFC 1035
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
    pub authorities: Vec<Authority>,
    pub additionals: Vec<Additional>,
}

impl Message {
    pub(crate) fn new(header: Header) -> Message {
        return Message {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.to_bytes());
        bytes.extend(self.questions.iter().flat_map(|q| q.to_bytes()));
        bytes.extend(self.answers.iter().flat_map(|an| an.to_bytes()));
        bytes.extend(self.authorities.iter().flat_map(|au| au.to_bytes()));
        bytes.extend(self.additionals.iter().flat_map(|ad| ad.to_bytes()));
        return bytes;
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<Message, String> {
        let mut parsed_bytes = 0;

        let parsed_header = Header::parse(buffer)?;
        let header = parsed_header.header;
        parsed_bytes += parsed_header.parsed_bytes;

        let mut questions: Vec<Question> = Vec::new();
        for _ in 0..header.qdcount {
            let parsed_question = Question::parse(&buffer[parsed_bytes..])?;
            questions.push(parsed_question.question);
            parsed_bytes += parsed_question.parsed_bytes as usize;
        }

        let mut answers: Vec<Answer> = Vec::new();
        for _ in 0..header.ancount {
            let parsed_answer = Answer::parse(&buffer[parsed_bytes..])?;
            answers.push(parsed_answer.record);
            parsed_bytes += parsed_answer.parsed_bytes as usize;
        }

        let mut authorities: Vec<Answer> = Vec::new();
        for _ in 0..header.nscount {
            let parsed_authority = Authority::parse(&buffer[parsed_bytes..])?;
            authorities.push(parsed_authority.record);
            parsed_bytes += parsed_authority.parsed_bytes as usize;
        }

        let mut additionals: Vec<Answer> = Vec::new();
        for _ in 0..header.arcount {
            let parsed_additional = Additional::parse(&buffer[parsed_bytes..])?;
            additionals.push(parsed_additional.record);
            parsed_bytes += parsed_additional.parsed_bytes as usize;
        }

        if parsed_bytes < buffer.len() {
            eprintln!("Only parsed {} of {} bytes to create the message. Any additional bytes in the buffer have been ignored", parsed_bytes, buffer.len());
        }

        return Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::additional::Additional;
    use crate::dns::answer::Answer;
    use crate::dns::authority::Authority;
    use crate::dns::classes::Class;
    use crate::dns::header::{Header, Opcode};
    use crate::dns::hostname::Hostname;
    use crate::dns::message::Message;
    use crate::dns::question::Question;
    use crate::dns::types::Type;

    #[test]
    fn simple_question_to_bytes() {
        let header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let question = Question {
            qname: Hostname::from_string("www.example.com").unwrap(),
            qtype: Type::A,
            qclass: Class::IN,
        };

        let message = Message {
            questions: vec![question],
            ..Message::new(header)
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b00000001, 0b00000000, 0, 1, 0, 0, 0, 0, 0, 0,
        ];
        // Question
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());

        assert_eq!(expected, message.to_bytes());
    }

    #[test]
    fn multiple_questions_to_bytes() {
        let header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 0,
            qdcount: 2,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let questions = vec![
            Question {
                qname: Hostname::from_string("www.example.com").unwrap(),
                qtype: Type::A,
                qclass: Class::IN,
            },
            Question {
                qname: Hostname::from_string("www.google.com").unwrap(),
                qtype: Type::A,
                qclass: Class::IN,
            },
        ];

        let message = Message {
            questions,
            ..Message::new(header)
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b00000001, 0b00000000, 0, 2, 0, 0, 0, 0, 0, 0,
        ];
        // Question for www.example.com
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());

        // Question for www.google.com
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(6);
        expected.extend("google".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());

        assert_eq!(expected, message.to_bytes());
    }

    #[test]
    fn parse_simple_question() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b00000001, 0b00000000, 0, 1, 0, 0, 0, 0, 0, 0,
        ];
        // Question
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

        let expected_header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0, // z should always be 0 as per RFC 1035
            rcode: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let expected_question = Question {
            qname: Hostname::from_string("www.example.com").unwrap(),
            qtype: Type::A,
            qclass: Class::IN,
        };

        let expected_message = Message {
            questions: vec![expected_question],
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, Message::parse(bytes.as_slice()).unwrap());
    }

    #[test]
    fn parse_multiple_questions() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b00000001, 0b00000000, 0, 2, 0, 0, 0, 0, 0, 0,
        ];
        // Question for www.example.com
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());

        // Question for www.google.com
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(6);
        bytes.extend("google".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&extra_bytes);

        let expected_header = Header {
            id: 0xdb42,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0, // z should always be 0 as per RFC 1035
            rcode: 0,
            qdcount: 2,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let expected_questions = vec![
            Question {
                qname: Hostname::from_string("www.example.com").unwrap(),
                qtype: Type::A,
                qclass: Class::IN,
            },
            Question {
                qname: Hostname::from_string("www.google.com").unwrap(),
                qtype: Type::A,
                qclass: Class::IN,
            },
        ];

        let expected_message = Message {
            questions: expected_questions,
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, Message::parse(bytes.as_slice()).unwrap());
    }

    #[test]
    fn simple_answer_to_bytes() {
        let header = Header {
            id: 0xdb42,
            qr: true,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 0,
            qdcount: 0,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let message = Message {
            answers: vec![answer],
            ..Message::new(header)
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b10000001, 0b00000000, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        // Answer
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());
        expected.extend(&(0x258 as u32).to_be_bytes());
        expected.extend(&(4 as u16).to_be_bytes());
        expected.extend(&(0x9b211144 as u32).to_be_bytes());

        assert_eq!(expected, message.to_bytes());
    }

    #[test]
    fn multiple_responses_to_bytes() {
        let header = Header {
            id: 0xdb42,
            qr: true,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 7, // z should be ignored since RFC 1035 specifies it set to 0
            rcode: 0,
            qdcount: 0,
            ancount: 1,
            nscount: 1,
            arcount: 1,
        };

        let answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let authority = Authority {
            name: Hostname::from_string("example.com").unwrap(),
            rtype: Type::NS,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let additional = Additional {
            name: Hostname::from_string("www.other.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let message = Message {
            answers: vec![answer],
            authorities: vec![authority],
            additionals: vec![additional],
            ..Message::new(header)
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b10000001, 0b00000000, 0, 0, 0, 1, 0, 1, 0, 1,
        ];
        // Answer
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());
        expected.extend(&(0x258 as u32).to_be_bytes());
        expected.extend(&(4 as u16).to_be_bytes());
        expected.extend(&(0x9b211144 as u32).to_be_bytes());

        // Authority
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::NS as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());
        expected.extend(&(0x258 as u32).to_be_bytes());
        expected.extend(&(4 as u16).to_be_bytes());
        expected.extend(&(0x9b211144 as u32).to_be_bytes());

        // Additional
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(5);
        expected.extend("other".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);
        expected.extend(&(Type::A as u16).to_be_bytes());
        expected.extend(&(Class::IN as u16).to_be_bytes());
        expected.extend(&(0x258 as u32).to_be_bytes());
        expected.extend(&(4 as u16).to_be_bytes());
        expected.extend(&(0x9b211144 as u32).to_be_bytes());

        assert_eq!(expected, message.to_bytes());
    }

    #[test]
    fn parse_simple_response() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b10000001, 0b00000000, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        // Answer
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&(0x258 as u32).to_be_bytes());
        bytes.extend(&(4 as u16).to_be_bytes());
        bytes.extend(&(0x9b211144 as u32).to_be_bytes());
        bytes.extend(&extra_bytes);

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

        let expected_answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let expected_message = Message {
            answers: vec![expected_answer],
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, Message::parse(bytes.as_slice()).unwrap());
    }

    #[test]
    fn parse_multiple_responses() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = vec![
            // Header
            0xdb, 0x42, 0b10000001, 0b00000000, 0, 0, 0, 1, 0, 1, 0, 1,
        ];
        // Answer
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&(0x258 as u32).to_be_bytes());
        bytes.extend(&(4 as u16).to_be_bytes());
        bytes.extend(&(0x9b211144 as u32).to_be_bytes());

        // Authority
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::NS as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&(0x258 as u32).to_be_bytes());
        bytes.extend(&(4 as u16).to_be_bytes());
        bytes.extend(&(0x9b211144 as u32).to_be_bytes());

        // Additional
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(5);
        bytes.extend("other".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&(Type::A as u16).to_be_bytes());
        bytes.extend(&(Class::IN as u16).to_be_bytes());
        bytes.extend(&(0x258 as u32).to_be_bytes());
        bytes.extend(&(4 as u16).to_be_bytes());
        bytes.extend(&(0x9b211144 as u32).to_be_bytes());

        bytes.extend(&extra_bytes);

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
            nscount: 1,
            arcount: 1,
        };

        let expected_answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let expected_authority = Authority {
            name: Hostname::from_string("example.com").unwrap(),
            rtype: Type::NS,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let expected_additional = Additional {
            name: Hostname::from_string("www.other.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let expected_message = Message {
            answers: vec![expected_answer],
            authorities: vec![expected_authority],
            additionals: vec![expected_additional],
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, Message::parse(bytes.as_slice()).unwrap());
    }
}
