use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4, MutableIpv4Packet};
use pnet::packet::udp;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr};

pub struct Spoofer<'spoof> {
    sender: TransportSender,
    spoofed_port: u16,
    target_port: u16,
    ip_template: MutableIpv4Packet<'spoof>,
}

const IP_HEADER_BYTES: usize = 20;
const UDP_HEADER_BYTES: usize = 8;

impl Spoofer<'_> {
    pub fn new<'spoof>(
        spoofed_addr: &Ipv4Addr,
        target_addr: &Ipv4Addr,
        payload_size: usize,
    ) -> Result<Spoofer<'spoof>, Error> {
        // it looks like pnet modifies the initial buffer allocated for the IP packet, as a result we need to pre-allocate a large enough chunk of memory to hold the entire IP packet
        let ip_payload_size = payload_size + IP_HEADER_BYTES + UDP_HEADER_BYTES;
        let data = vec![0u8; ip_payload_size];
        let mut ip_template = MutableIpv4Packet::owned(data).unwrap();
        ip_template.populate(&Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 0, // to be filled in just before sending
            identification: 0,
            flags: 0x02, // don't fragment
            fragment_offset: 0,
            ttl: 64,
            next_level_protocol: IpNextHeaderProtocols::Udp,
            checksum: 0, // to be calculated just before sending
            source: *spoofed_addr,
            destination: *target_addr,
            options: Vec::new(),
            payload: Vec::new(), // to be filled in just before sending
        });

        let (sender, _) =
            transport_channel(0, TransportChannelType::Layer3(IpNextHeaderProtocols::Udp))?;

        return Ok(Spoofer {
            sender,
            spoofed_port: 53,
            target_port: 33333,
            ip_template,
        });
    }

    pub fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut data: Vec<u8> = Vec::new();
        data.extend(&[0u8; UDP_HEADER_BYTES]);
        data.extend(bytes);

        let length: u16 = data.len() as u16;

        let mut udp_packet = MutableUdpPacket::new(&mut data).unwrap();
        udp_packet.set_source(self.spoofed_port);
        udp_packet.set_destination(self.target_port);
        udp_packet.set_length(length);
        udp_packet.set_checksum(udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &self.ip_template.get_source(),
            &self.ip_template.get_destination(),
        ));

        self.ip_template
            .set_total_length(IP_HEADER_BYTES as u16 + length);
        self.ip_template.set_payload(udp_packet.packet());
        self.ip_template
            .set_checksum(ipv4::checksum(&self.ip_template.to_immutable()));

        self.sender.send_to(
            self.ip_template.to_immutable(),
            IpAddr::from(self.ip_template.get_destination()),
        )?;

        return Ok(());
    }
}
