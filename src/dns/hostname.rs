#[derive(PartialEq, Debug)]
/// Hostname format as specified in IETF RFC 1035
///
/// This format is used for the *NAME fields
pub struct Hostname<'hostname>(Vec<HostnameLabel<'hostname>>);

#[derive(PartialEq, Debug)]
struct HostnameLabel<'label> {
    length: u8,
    label: &'label str,
}

impl HostnameLabel<'_> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.length);
        bytes.extend(self.label.bytes());
        return bytes;
    }
}

impl Hostname<'_> {
    pub fn from_string(hostname: &str) -> Result<Hostname, String> {
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
                        label,
                    };
                })
                .collect(),
        ));
    }

    pub fn to_bytes(&self) -> Vec<u8> {
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
    use crate::dns::hostname::{Hostname, HostnameLabel};

    #[test]
    fn test_hostname_from_hostname() {
        let expected = Hostname(vec![
            HostnameLabel {
                length: 3,
                label: "www",
            },
            HostnameLabel {
                length: 7,
                label: "example",
            },
            HostnameLabel {
                length: 3,
                label: "com",
            },
        ]);
        assert_eq!(expected, Hostname::from_string("www.example.com").unwrap());
    }
}
