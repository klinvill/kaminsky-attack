use crate::dns::classes::Class;
use crate::dns::header::{Header, Opcode};
use crate::dns::hostname::Hostname;
use crate::dns::message::QuestionMessage;
use crate::dns::question::Question;
use crate::dns::types::Type;
use rand;

fn build_query(
    hostnames: Vec<&str>,
    qtype: Option<Type>,
    opcode: Option<Opcode>,
    recursion_desired: Option<bool>,
) -> Result<QuestionMessage, String> {
    let id = rand::random::<u16>();

    if hostnames.len() > u16::max_value() as usize {
        return Err(format!(
            "Too many hostnames entered, cannot query for more than {} hostnames",
            u16::max_value()
        ));
    }
    let qdcount: u16 = hostnames.len() as u16;

    let header = Header {
        id,
        qr: false, // query rather than response
        opcode: opcode.unwrap_or(Opcode::QUERY),
        aa: false,
        tc: false, // TODO: need to ensure that the message never exceeds a length greater than that permitted by the transmission channel
        rd: recursion_desired.unwrap_or(false),
        ra: false,
        z: 0,
        rcode: 0,
        qdcount,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let questions: Result<Vec<Question>, String> = hostnames
        .iter()
        .map(|hostname| {
            let qname = Hostname::from_string(hostname)?;
            return Ok(Question {
                qname,
                qtype: qtype.unwrap_or(Type::A),
                qclass: Class::IN,
            });
        })
        .collect();

    let message = QuestionMessage {
        header,
        questions: questions?,
    };

    return Ok(message);
}

#[cfg(test)]
mod tests {
    use crate::dns::classes::Class;
    use crate::dns::header::{Header, Opcode};
    use crate::dns::hostname::Hostname;
    use crate::dns::message::QuestionMessage;
    use crate::dns::query::build_query;
    use crate::dns::question::Question;
    use crate::dns::types::Type;

    #[test]
    fn simple_build_query() {
        // TODO: How should optional function arguments be declared and supplied?
        let message = build_query(vec!["www.example.com"], None, None, None).unwrap();

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
