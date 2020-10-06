use crate::dns::message::{Message, ResponseMessage};
use crate::dns::query::Query;
use std::net::UdpSocket;

// Max size of a DNS UDP packet as specified in IETF RFC 1035
const DNS_MAX_UDP_SIZE: usize = 512;

pub struct Client {
    local_host: String,
    local_port: u16,
    server: String,
    port: u16,
}

impl Client {
    pub fn new(server: String) -> Client {
        return Client {
            local_host: "0.0.0.0".to_string(),
            local_port: 0,
            server,
            port: 53,
        };
    }

    // TODO: make sure to use an error type that encompasses the IO errors
    pub fn query(&self, request: Query) -> Result<ResponseMessage, String> {
        let mut buffer = [0; DNS_MAX_UDP_SIZE];
        let local_address = format!("{}:{}", self.local_host, self.local_port);
        let socket = match UdpSocket::bind(local_address) {
            Err(e) => return Err(e.to_string()),
            Ok(sock) => sock,
        };

        println!("Bound to local address {}", socket.local_addr().unwrap());

        let server_address = format!("{}:{}", self.server, self.port);
        match socket.connect(server_address) {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        println!(
            "Connected to remote address {}",
            socket.peer_addr().unwrap()
        );

        let request_payload = request.to_message()?.to_bytes();
        match socket.send(request_payload.as_slice()) {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        let size = match socket.recv(&mut buffer) {
            Err(e) => return Err(e.to_string()),
            Ok(sz) => sz,
        };
        return ResponseMessage::parse(&buffer[..size]);
    }
}
