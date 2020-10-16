# Kaminsky DNS Cache Poisoning Attack Lab

This repository contains the code and executables used to launch a Kaminsky DNS cache poisoning attack. This code was
written as a homework assignment based on the ["Remote DNS Attack" SEED lab](
https://seedsecuritylabs.org/Labs_16.04/Networking/DNS_Remote/). 

The attack works by submitting a DNS query for a non-existent subdomain of the target domain (e.g. `ksdgb.example.com`
if trying to control resolution for the `example.com` domain), and then subsequently spoofing DNS responses with an
authoritative NS record. If successful, the target DNS resolver will cache the incorrect NS entry for the target
domain. This effectively allows the attacker to redirect any traffic (that relies on the poisoned resolver) meant for
the target domain, to an IP chosen by the attacker.

## Installation Instructions

The easiest way to install this binary is simply to download it. You can then run it at your leisure. Releases are
hosted on the github repo. Note that the releases are currently only built for Linux systems and have only been tested
to work on the Ubuntu 16.04 SEED lab vm.  


## Run Instructions

Command format: `./kaminsky_attack -m <mode> [options]`

Run `./kaminsky_attack --help` to see the help information.

The program has three different modes that it can run in:
- `query` -- run a DNS query for an A record
- `spoof` -- spoof a DNS response for an A record along with an NS record in the Authority section
- `attack` -- run a Kaminsky DNS cache poisoning attack

### query mode:    

##### Required args:
- hostname -- FQDN to query an A record for (e.g. `www.example.com`)
- dns-server -- IP address or hostname of DNS server to query

##### Example:
`./kaminsky_attack --mode query --hostname ns.definitelynotkirby.com --dns-server 10.37.132.7`

### spoof mode:    

##### Required args:
- target-addr -- IP address to send spoofed replies to
- spoofed-addrs -- IP addresses to spoof responses from, only the first IP will be used
- hostname -- FQDN to spoof a response for
- attacker-ns -- nameserver to advertise as authoritative for the target domain
- spoofed-response -- IP address that will be returned as an A record for the spoofed hostname

##### Example:
`./kaminsky_attack --mode spoof --target-addr 10.37.132.6 --spoofed-addrs 10.2.2.2 --hostname www.example.com --attacker-ns 192.168.3.3 --spoofed-response 10.5.5.5`

### attack mode:

##### Required args:
- target-addr -- IP address of the DNS server whose cache will be poisoned
- spoofed-addrs -- IP addresses of the nameservers for the domain you are trying to attack
- attacker-ns -- nameserver to advertise as authoritative for the target domain
- target-domain -- domain to target, this is the domain you want to provide an authoritative NS record for

##### Optional args:
- duration -- how long to run the attack for in seconds, defaults to 5 seconds

##### Example:
`./kaminsky_attack --mode attack --target-addr 10.37.132.7 --spoofed-addrs 10.1.1.1 10.2.2.2 10.3.3.3 --attacker-ns ns.definitelynotkirby.com --target-domain example.com`


## Build Instructions

You can build the executable yourself instead of using the release binaries. This can be done using Rust's package
manager Cargo. `cargo build --release` will build the binary in release mode (which compiles with optimizations). If
you want to build an executable for a different platform, you can use cargo build's `--target` flag to specify the
target. For this assignment, I used the `x86_64-unknown-linux-musl` target. This target results in a statically linked
linux binary that "just works"&trade; on linux systems.
 