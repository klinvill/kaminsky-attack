use crate::dns::additional::Additional;
use crate::dns::answer::Answer;
use crate::dns::authority::Authority;
use crate::dns::classes::Class;
use crate::dns::hostname::Hostname;
use crate::dns::message::Message;
use crate::dns::resource_record::ResourceRecord;
use crate::dns::types::Type;

#[derive(PartialEq, Debug)]
pub struct Response {
    pub query: Message,
    pub rcode: u8,
    pub answers: Vec<Answer>,
    pub authorities: Vec<Authority>,
    pub additionals: Vec<Additional>,
    pub authoritative_answer: bool,
    pub recursion_available: bool,
}

#[derive(Clone)]
pub enum Record {
    A(ARecord),
    NS(NSRecord),
}

#[derive(Clone)]
pub struct ARecord {
    name: String,
    ttl: u32,
    ip: [u8; 4],
}

#[derive(Clone)]
pub struct NSRecord {
    name: String,
    ttl: u32,
    ns: String,
}

impl Record {
    fn to_rr(&self) -> Result<ResourceRecord, String> {
        match self {
            Record::A(record) => record.to_rr(),
            Record::NS(record) => record.to_rr(),
        }
    }
}

impl ARecord {
    fn to_rr(&self) -> Result<ResourceRecord, String> {
        return Ok(ResourceRecord {
            name: Hostname::from_string(self.name.as_str())?,
            rtype: Type::A,
            class: Class::IN,
            ttl: self.ttl,
            rdlength: 4,
            rdata: self.ip.to_vec(),
        });
    }
}

impl NSRecord {
    fn to_rr(&self) -> Result<ResourceRecord, String> {
        let ns_bytes = Hostname::from_string(self.ns.as_str())?.to_bytes();
        return Ok(ResourceRecord {
            name: Hostname::from_string(self.name.as_str())?,
            rtype: Type::NS,
            class: Class::IN,
            ttl: self.ttl,
            rdlength: ns_bytes.len() as u16,
            rdata: ns_bytes,
        });
    }
}

impl Response {
    pub fn new(query: Message) -> Response {
        return Response {
            query,
            rcode: 0,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            // Setting authoritative bit to true by default in order to make spoofing attacks easier by default
            authoritative_answer: true,
            recursion_available: true,
        };
    }

    pub fn add_answer(&mut self, record: Record) -> Result<(), String> {
        self.answers.push(record.to_rr()?);
        return Ok(());
    }

    pub fn add_authority(&mut self, record: Record) -> Result<(), String> {
        self.authorities.push(record.to_rr()?);
        return Ok(());
    }

    pub fn add_additional(&mut self, record: Record) -> Result<(), String> {
        self.additionals.push(record.to_rr()?);
        return Ok(());
    }

    pub(crate) fn to_message(&self) -> Result<Message, String> {
        let mut header = self.query.header;
        let questions = self.query.questions.clone();

        header.qr = true;
        header.aa = self.authoritative_answer;
        header.ra = self.recursion_available;
        header.rcode = self.rcode;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authorities.len() as u16;
        header.arcount = self.additionals.len() as u16;

        // TODO: reduce amount of cloning in this code
        return Ok(Message {
            header,
            questions,
            answers: self.answers.clone(),
            authorities: self.authorities.clone(),
            additionals: self.additionals.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::answer::Answer;
    use crate::dns::classes::Class;
    use crate::dns::header::{Header, Opcode};
    use crate::dns::hostname::Hostname;
    use crate::dns::message::Message;
    use crate::dns::question::Question;
    use crate::dns::response::{ARecord, NSRecord, Record, Response};
    use crate::dns::types::Type;

    #[test]
    fn response_to_message() {
        let header = Header {
            id: 0x1234,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
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

        let original_query = Message {
            questions: vec![question.clone()],
            ..Message::new(header)
        };

        let response = Response::new(original_query);

        let expected_header = Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::QUERY,
            aa: true,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 0,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let expected_message = Message {
            questions: vec![question],
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, response.to_message().unwrap());
    }

    #[test]
    fn response_with_answers_to_message() {
        let header = Header {
            id: 0x1234,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
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

        let original_query = Message {
            questions: vec![question.clone()],
            ..Message::new(header)
        };

        let answer = Answer {
            name: Hostname::from_string("www.example.com").unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 0x258,
            rdlength: 4,
            rdata: (0x9b211144 as u32).to_be_bytes().to_vec(),
        };

        let response = Response {
            answers: vec![answer.clone()],
            ..Response::new(original_query)
        };

        let expected_header = Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::QUERY,
            aa: true,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 0,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let expected_message = Message {
            questions: vec![question],
            answers: vec![answer],
            ..Message::new(expected_header)
        };

        assert_eq!(expected_message, response.to_message().unwrap());
    }

    #[test]
    fn add_A_record() {
        let record = Record::A(ARecord {
            name: "www.example.com".to_string(),
            ttl: 0x1234,
            ip: [127, 0, 0, 1],
        });

        let header = Header {
            id: 0x1234,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
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

        let original_query = Message {
            questions: vec![question.clone()],
            ..Message::new(header)
        };

        let mut response = Response::new(original_query.clone());
        response.add_answer(record.clone()).unwrap();

        let expected_response = Response {
            answers: vec![record.to_rr().unwrap()],
            ..Response::new(original_query)
        };

        assert_eq!(expected_response, response);
    }

    #[test]
    fn add_A_NS_records() {
        let a_record = Record::A(ARecord {
            name: "www.example.com".to_string(),
            ttl: 0x1234,
            ip: [127, 0, 0, 1],
        });

        let ns_record = Record::NS(NSRecord {
            name: "www.example.com".to_string(),
            ttl: 0x1234,
            ns: "ns.example.com".to_string(),
        });

        let header = Header {
            id: 0x1234,
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
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

        let original_query = Message {
            questions: vec![question.clone()],
            ..Message::new(header)
        };

        let mut response = Response::new(original_query.clone());
        response.add_answer(a_record.clone()).unwrap();
        response.add_answer(ns_record.clone()).unwrap();

        let expected_response = Response {
            answers: vec![a_record.to_rr().unwrap(), ns_record.to_rr().unwrap()],
            ..Response::new(original_query)
        };

        assert_eq!(expected_response, response);
    }
}
