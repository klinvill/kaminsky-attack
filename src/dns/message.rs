use crate::dns::additional::Additional;
use crate::dns::answer::Answer;
use crate::dns::authority::Authority;
use crate::dns::header::Header;
use crate::dns::question::Question;

#[derive(Default)]
struct ResponsePayload<'payload> {
    answers: Option<Vec<Answer<'payload>>>,
    authorities: Option<Vec<Authority<'payload>>>,
    additionals: Option<Vec<Additional<'payload>>>,
}

enum MessagePayload<'payload> {
    QUESTIONS(Vec<Question<'payload>>),
    RESPONSES(ResponsePayload<'payload>),
}

/// DNS message format, mostly as specified in IETF RFC 1035
///
/// For this implementation I took the liberty of making the question and resource record sections mutually exclusive
struct Message<'message> {
    header: Header,
    payload: MessagePayload<'message>,
}

impl Message<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.to_bytes());
        bytes.extend(self.payload.to_bytes());

        return bytes;
    }
}

impl MessagePayload<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            MessagePayload::QUESTIONS(qs) => bytes.extend(qs.iter().flat_map(|q| q.to_bytes())),
            MessagePayload::RESPONSES(rs) => bytes.extend(rs.to_bytes()),
        }

        return bytes;
    }
}

impl ResponsePayload<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(
            self.answers
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .flat_map(|ans| ans.to_bytes()),
        );
        bytes.extend(
            self.authorities
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .flat_map(|au| au.to_bytes()),
        );
        bytes.extend(
            self.additionals
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .flat_map(|ad| ad.to_bytes()),
        );
        return bytes;
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::additional::Additional;
    use crate::dns::answer::Answer;
    use crate::dns::authority::Authority;
    use crate::dns::header::{Header, Opcode};
    use crate::dns::hostname::Hostname;
    use crate::dns::message::{Message, MessagePayload, ResponsePayload};
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
            qclass: 2,
        };

        let message = Message {
            header,
            payload: MessagePayload::QUESTIONS(vec![question]),
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0x42, 0xdb, 0b10000000, 0b00000000, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        // Question
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(2 as u16).to_le_bytes());

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
                qclass: 2,
            },
            Question {
                qname: Hostname::from_string("www.google.com").unwrap(),
                qtype: Type::A,
                qclass: 2,
            },
        ];

        let message = Message {
            header,
            payload: MessagePayload::QUESTIONS(questions),
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0x42, 0xdb, 0b10000000, 0b00000000, 2, 0, 0, 0, 0, 0, 0, 0,
        ];
        // Question for www.example.com
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(2 as u16).to_le_bytes());

        // Question for www.google.com
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(6);
        expected.extend("google".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(2 as u16).to_le_bytes());

        assert_eq!(expected, message.to_bytes());
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
            class: 1,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let message = Message {
            header,
            payload: MessagePayload::RESPONSES(ResponsePayload {
                answers: Some(vec![answer]),
                ..ResponsePayload::default()
            }),
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0x42, 0xdb, 0b10000001, 0b00000000, 0, 0, 1, 0, 0, 0, 0, 0,
        ];
        // Answer
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(1 as u16).to_le_bytes());
        expected.extend(&(0x258 as u32).to_le_bytes());
        expected.extend(&(4 as u16).to_le_bytes());
        expected.extend(&(0x9b211144 as u32).to_le_bytes());

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
            nscount: 0,
            arcount: 0,
        };

        let answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: 1,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let authority = Authority {
            name: Hostname::from_string("example.com").unwrap(),
            rtype: Type::NS,
            class: 1,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let additional = Additional {
            name: Hostname::from_string("www.other.com").unwrap(),
            rtype: Type::A,
            class: 1,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_le_bytes().to_vec(),
        };

        let message = Message {
            header,
            payload: MessagePayload::RESPONSES(ResponsePayload {
                answers: Some(vec![answer]),
                authorities: Some(vec![authority]),
                additionals: Some(vec![additional]),
            }),
        };

        let mut expected: Vec<u8> = vec![
            // Header
            0x42, 0xdb, 0b10000001, 0b00000000, 0, 0, 1, 0, 0, 0, 0, 0,
        ];
        // Answer
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(1 as u16).to_le_bytes());
        expected.extend(&(0x258 as u32).to_le_bytes());
        expected.extend(&(4 as u16).to_le_bytes());
        expected.extend(&(0x9b211144 as u32).to_le_bytes());

        // Authority
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::NS as u16).to_le_bytes());
        expected.extend(&(1 as u16).to_le_bytes());
        expected.extend(&(0x258 as u32).to_le_bytes());
        expected.extend(&(4 as u16).to_le_bytes());
        expected.extend(&(0x9b211144 as u32).to_le_bytes());

        // Additional
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(5);
        expected.extend("other".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.extend(&(Type::A as u16).to_le_bytes());
        expected.extend(&(1 as u16).to_le_bytes());
        expected.extend(&(0x258 as u32).to_le_bytes());
        expected.extend(&(4 as u16).to_le_bytes());
        expected.extend(&(0x9b211144 as u32).to_le_bytes());

        assert_eq!(expected, message.to_bytes());
    }
}
