use crate::dns::classes::Class;
use crate::dns::header::{Header, Opcode};
use crate::dns::hostname::Hostname;
use crate::dns::message::QuestionMessage;
use crate::dns::question::Question;
use crate::dns::types::Type;
use rand;

pub struct Query {
    pub hostnames: Vec<String>,
    pub qtype: Type,
    pub opcode: Opcode,
    pub recursion_desired: bool,
}

impl Query {
    pub fn new(hostnames: Vec<String>) -> Query {
        return Query {
            hostnames,
            qtype: Type::A,
            opcode: Opcode::QUERY,
            recursion_desired: false,
        };
    }

    pub(crate) fn to_message(&self) -> Result<QuestionMessage, String> {
        if self.hostnames.len() > u16::max_value() as usize {
            return Err(format!(
                "Too many hostnames entered, cannot query for more than {} hostnames",
                u16::max_value()
            ));
        }

        let id = rand::random::<u16>();

        let qdcount: u16 = self.hostnames.len() as u16;

        let header = Header {
            id,
            qr: false, // query rather than response
            opcode: self.opcode,
            aa: false,
            tc: false, // TODO: need to ensure that the message never exceeds a length greater than that permitted by the transmission channel
            rd: self.recursion_desired,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let questions: Result<Vec<Question>, String> = self
            .hostnames
            .iter()
            .map(|hostname| {
                let qname = Hostname::from_string(hostname)?;
                return Ok(Question {
                    qname,
                    qtype: self.qtype,
                    qclass: Class::IN,
                });
            })
            .collect();

        return Ok(QuestionMessage {
            header,
            questions: questions?,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::classes::Class;
    use crate::dns::header::{Header, Opcode};
    use crate::dns::hostname::Hostname;
    use crate::dns::message::QuestionMessage;
    use crate::dns::query::Query;
    use crate::dns::question::Question;
    use crate::dns::types::Type;

    #[test]
    fn query_to_message() {
        let query = Query::new(vec!["www.example.com".to_string()]);
        let message = query.to_message().unwrap();

        let expected = QuestionMessage {
            header: Header {
                id: message.header.id,
                qr: false,
                opcode: Opcode::QUERY,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![Question {
                qname: Hostname::from_string("www.example.com").unwrap(),
                qtype: Type::A,
                qclass: Class::IN,
            }],
        };

        assert_eq!(expected, message);
    }
}
