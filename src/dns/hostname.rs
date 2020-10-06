#[derive(PartialEq, Debug)]
/// Hostname format as specified in IETF RFC 1035
///
/// This format is used for the *NAME fields
pub(crate) struct Hostname(Vec<HostnameLabel>);

#[derive(PartialEq, Debug)]
struct HostnameLabel {
    length: u8,
    label: String,
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

impl Hostname {
    pub(crate) fn from_string(hostname: &str) -> Result<Hostname, String> {
        if !valid_hostname(hostname) {
            return Err("Invalid hostname".to_string());
        }
        return Ok(Hostname(
            hostname
                .split('.')
                .map(|label| {
                    // TODO: labels are restricted to 63 octets or less as per RFC 1035
                    return HostnameLabel {
                        length: label.len() as u8,
                        label: String::from(label),
                    };
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
        let mut labels: Vec<HostnameLabel> = Vec::new();
        let mut i: usize = 0;

        // TODO: add bounds check for a more friendly error than rust's panic
        while buffer[i] != 0 {
            let label_size = buffer[i];
            i += 1;
            // TODO: should use errors instead of relying on panic here
            let label = String::from_utf8(buffer[i..i + (label_size as usize)].to_vec()).unwrap();
            labels.push(HostnameLabel {
                length: label_size,
                label,
            });
            i += label_size as usize;
        }

        let parsed_bytes: u8 = (i + 1) as u8;
        if parsed_bytes as usize != i + 1 {
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
    use crate::dns::hostname::{Hostname, HostnameLabel};

    #[test]
    fn test_hostname_from_hostname() {
        let expected = Hostname(vec![
            HostnameLabel {
                length: 3,
                label: "www".to_string(),
            },
            HostnameLabel {
                length: 7,
                label: "example".to_string(),
            },
            HostnameLabel {
                length: 3,
                label: "com".to_string(),
            },
        ]);
        assert_eq!(expected, Hostname::from_string("www.example.com").unwrap());
    }

    #[test]
    fn simple_hostname_to_bytes() {
        let hostname = Hostname(vec![
            HostnameLabel {
                length: 3,
                label: "www".to_string(),
            },
            HostnameLabel {
                length: 7,
                label: "example".to_string(),
            },
            HostnameLabel {
                length: 3,
                label: "com".to_string(),
            },
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
            HostnameLabel {
                length: 3,
                label: "www".to_string(),
            },
            HostnameLabel {
                length: 7,
                label: "example".to_string(),
            },
            HostnameLabel {
                length: 3,
                label: "com".to_string(),
            },
        ]);

        let result = Hostname::parse(bytes.as_slice()).unwrap();

        assert_eq!(expected, result.hostname);
        assert_eq!(hostname_length, result.parsed_bytes as usize);
    }
}
