use crate::dns::message::Message;
use crate::dns::query::Query;
use std::net::UdpSocket;
use std::time::Duration;

// Max size of a DNS UDP packet as specified in IETF RFC 1035
const DNS_MAX_UDP_SIZE: usize = 512;

pub struct Client {
    local_host: String,
    local_port: u16,
    server: String,
    port: u16,
    timeout: Duration,
}

impl Client {
    pub fn new(server: String) -> Client {
        return Client {
            local_host: "0.0.0.0".to_string(),
            local_port: 0,
            server,
            port: 53,
            timeout: Duration::new(10, 0),
        };
    }

    // TODO: make sure to use an error type that encompasses the IO errors
    pub fn query(&self, request: Query) -> Result<Message, String> {
        return self.send_message(&request.to_message()?);
    }

    pub fn send_message(&self, message: &Message) -> Result<Message, String> {
        let mut buffer = [0; DNS_MAX_UDP_SIZE];
        let socket = self.connect()?;

        let message_payload = message.to_bytes();
        match socket.send(message_payload.as_slice()) {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        let size = match socket.recv(&mut buffer) {
            Err(e) => return Err(e.to_string()),
            Ok(sz) => sz,
        };

        return Message::parse(&buffer[..size]);
    }

    pub fn send_message_no_recv(&self, message: &Message) -> Result<(), String> {
        let socket = self.connect()?;

        let message_payload = message.to_bytes();
        match socket.send(message_payload.as_slice()) {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        return Ok(());
    }

    pub fn connect(&self) -> Result<UdpSocket, String> {
        let local_address = format!("{}:{}", self.local_host, self.local_port);
        let socket = match UdpSocket::bind(local_address) {
            Err(e) => return Err(e.to_string()),
            Ok(sock) => sock,
        };
        match socket.set_write_timeout(Some(self.timeout)) {
            Err(e) => return Err(e.to_string()),
            _ => (),
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

        return Ok(socket);
    }
}
