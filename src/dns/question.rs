/// DNS question section with fields as specified in IETF RFC 1035
struct Question<'question> {
    qname: Qname<'question>,
    qtype: u16,
    qclass: u16,
}

#[derive(PartialEq, Debug)]
struct PackedQuestion {
    data: Vec<u8>,
}

#[derive(PartialEq, Debug)]
struct Qname<'qname>(Vec<QnameLabel<'qname>>);

#[derive(PartialEq, Debug)]
struct QnameLabel<'label> {
    length: u8,
    label: &'label str,
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

impl QnameLabel<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.length);
        bytes.extend(self.label.bytes());
        return bytes;
    }
}

impl Qname<'_> {
    fn from_hostname(hostname: &str) -> Result<Qname, &'static str> {
        if !valid_hostname(hostname) {
            return Err("Invalid hostname");
        }
        return Ok(Qname(
            hostname
                .split('.')
                .map(|label| {
                    return QnameLabel {
                        length: label.len() as u8,
                        label,
                    };
                })
                .collect(),
        ));
    }

    fn to_bytes(&self) -> Vec<u8> {
        return self.0.iter().flat_map(|label| label.to_bytes()).collect();
    }
}
/// Attempts to validate that a hostname is valid as per RFC 1123
fn valid_hostname(hostname: &str) -> bool {
    const ALLOWED_SPECIAL_CHARS: &str = "-.";
    let mut host_iter = hostname.chars();
    return hostname.len() < 256
        // Will fail if there are no characters since ' ' is not alphanumeric
        && host_iter.next().unwrap_or(' ').is_ascii_alphanumeric()
        // Will still succeed if there is only one character since 'a' is alphanumeric
        && host_iter.next_back().unwrap_or('a').is_ascii_alphanumeric()
        && host_iter.all(|c| {
            c.is_ascii_alphanumeric() || ALLOWED_SPECIAL_CHARS.contains(c)
        });
}

#[cfg(test)]
mod tests {
    use crate::dns::question::{PackedQuestion, Qname, QnameLabel, Question};

    #[test]
    fn test_qname_from_hostname() {
        let expected = Qname(vec![
            QnameLabel {
                length: 3,
                label: "www",
            },
            QnameLabel {
                length: 7,
                label: "example",
            },
            QnameLabel {
                length: 3,
                label: "com",
            },
        ]);
        assert_eq!(expected, Qname::from_hostname("www.example.com").unwrap());
    }

    #[test]
    fn pack_aligned_question() {
        let question = Question {
            qname: Qname::from_hostname("www.example.com").unwrap(),
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
