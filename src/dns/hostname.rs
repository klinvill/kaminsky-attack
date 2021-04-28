#[derive(PartialEq, Clone, Debug)]
/// Hostname format as specified in IETF RFC 1035
///
/// This format is used for the *NAME fields
pub struct Hostname(Vec<Label>);

#[derive(PartialEq, Clone, Debug)]
enum Label {
    NORMAL(HostnameLabel),
    COMPRESSED(CompressedHostnameLabel),
}

impl Label {
    fn to_bytes(&self) -> Vec<u8> {
        return match self {
            Label::NORMAL(label) => label.to_bytes(),
            Label::COMPRESSED(label) => label.to_bytes(),
        };
    }
}

#[derive(PartialEq, Clone, Debug)]
struct HostnameLabel {
    length: u8,
    label: String,
}

#[derive(PartialEq, Clone, Copy, Debug)]
struct CompressedHostnameLabel {
    pointer: u16,
}

pub(crate) struct ParsedHostname {
    /// Number of buffer bytes parsed to construct a hostname
    pub(crate) parsed_bytes: u8,
    pub(crate) hostname: Hostname,
}

impl HostnameLabel {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.length);
        bytes.extend(self.label.bytes());
        return bytes;
    }
}

// a compressed record is indicated by the first two bits being set
const COMPRESSED_MASK: u16 = 0xc000;
const COMPRESSED_INDICATOR: u16 = 0xc000;

impl CompressedHostnameLabel {
    fn to_bytes(&self) -> Vec<u8> {
        let packed_value = COMPRESSED_INDICATOR ^ self.pointer;
        return packed_value.to_be_bytes().to_vec();
    }
}

impl Hostname {
    // TODO: use From trait instead of a separate function
    pub(crate) fn from_string(hostname: &str) -> Result<Hostname, String> {
        if !valid_hostname(hostname) {
            return Err("Invalid hostname".to_string());
        }

        return Ok(Hostname(
            hostname
                .split('.')
                .map(|label| {
                    // TODO: labels are restricted to 63 octets or less as per RFC 1035
                    return Label::NORMAL(HostnameLabel {
                        length: label.len() as u8,
                        label: String::from(label),
                    });
                })
                .collect(),
        ));
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.0.iter().flat_map(|label| label.to_bytes()).collect();
        // each hostname is terminated by the zero-length octet (e.g. null byte)
        bytes.push(0);
        return bytes;
    }

    pub(crate) fn parse(buffer: &[u8]) -> Result<ParsedHostname, String> {
        let mut labels: Vec<Label> = Vec::new();
        let mut i: usize = 0;

        // TODO: add bounds check for a more friendly error than rust's panic
        loop {
            let next_bytes = u16::from_be_bytes([buffer[i], buffer[i + 1]]);

            if next_bytes & COMPRESSED_MASK == COMPRESSED_INDICATOR {
                let pointer = next_bytes;
                labels.push(Label::COMPRESSED(CompressedHostnameLabel { pointer }));
                i += 2;
                break; // as per RFC 1035, a NAME ends in either a pointer or a zero octet
            } else {
                let label_size = buffer[i];
                i += 1;
                // TODO: should use errors instead of relying on panic here
                let label =
                    String::from_utf8(buffer[i..i + (label_size as usize)].to_vec()).unwrap();

                labels.push(Label::NORMAL(HostnameLabel {
                    length: label_size,
                    label,
                }));
                i += label_size as usize;

                if buffer[i] == 0 {
                    i += 1;
                    break; // as per RFC 1035, a NAME ends in either a pointer or a zero octet
                }
            }
        }

        let parsed_bytes: u8 = (i) as u8;
        if parsed_bytes as usize != i {
            // Note: this can still fail silently if the number of bytes parsed also calls usize to overflow
            return Err("Parsed more bytes than can be represented in a u8".to_string());
        }

        return Ok(ParsedHostname {
            parsed_bytes,
            hostname: Hostname(labels),
        });
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
    use crate::dns::hostname::{CompressedHostnameLabel, Hostname, HostnameLabel, Label};

    #[test]
    fn test_hostname_from_string() {
        let expected = Hostname(vec![
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "www".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 7,
                label: "example".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "com".to_string(),
            }),
        ]);
        assert_eq!(expected, Hostname::from_string("www.example.com").unwrap());
    }

    #[test]
    fn simple_hostname_to_bytes() {
        let hostname = Hostname(vec![
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "www".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 7,
                label: "example".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "com".to_string(),
            }),
        ]);

        let mut expected: Vec<u8> = Vec::new();
        expected.push(3);
        expected.extend("www".as_bytes());
        expected.push(7);
        expected.extend("example".as_bytes());
        expected.push(3);
        expected.extend("com".as_bytes());
        expected.push(0);

        assert_eq!(expected, hostname.to_bytes());
    }

    #[test]
    fn parse_simple_hostname() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(3);
        bytes.extend("www".as_bytes());
        bytes.push(7);
        bytes.extend("example".as_bytes());
        bytes.push(3);
        bytes.extend("com".as_bytes());
        bytes.push(0);
        bytes.extend(&extra_bytes);

        let hostname_length = bytes.len() - extra_bytes.len();

        let expected = Hostname(vec![
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "www".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 7,
                label: "example".to_string(),
            }),
            Label::NORMAL(HostnameLabel {
                length: 3,
                label: "com".to_string(),
            }),
        ]);

        let result = Hostname::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.hostname);
        assert_eq!(hostname_length, result.parsed_bytes as usize);
    }

    #[test]
    fn parse_compressed_hostname() {
        let extra_bytes = (0x00123456 as u32).to_be_bytes();

        let compressed_pointer: u16 = 0xc00c;

        let mut bytes: Vec<u8> = compressed_pointer.to_be_bytes().to_vec();
        bytes.extend(&extra_bytes);

        let hostname_length = bytes.len() - extra_bytes.len();

        let expected = Hostname(vec![Label::COMPRESSED(CompressedHostnameLabel {
            pointer: compressed_pointer,
        })]);

        let result = Hostname::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.hostname);
        assert_eq!(hostname_length, result.parsed_bytes as usize);
    }

    #[test]
    fn parse_partially_compressed_hostname() {
        let extra_bytes = (0x12345678 as u32).to_be_bytes();

        let compressed_pointer: u16 = 0xc00c;

        // This mimics an example query where perhaps a query that contains a request to
        // www.example.com can shorten another entry that contains service.example.com by using a
        // pointer to example.com
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(7);
        bytes.extend("service".as_bytes());
        bytes.extend(&compressed_pointer.to_be_bytes());
        bytes.extend(&extra_bytes);

        let hostname_length = bytes.len() - extra_bytes.len();

        let expected = Hostname(vec![
            Label::NORMAL(HostnameLabel {
                length: 7,
                label: "service".to_string(),
            }),
            Label::COMPRESSED(CompressedHostnameLabel {
                pointer: compressed_pointer,
            }),
        ]);

        let result = Hostname::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.hostname);
        assert_eq!(hostname_length, result.parsed_bytes as usize);
    }
}
