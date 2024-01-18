use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmp::{IcmpTypes, IcmpPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::transport::ipv4_packet_iter;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::io::{ErrorKind, Error};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, Instant};


use get_if_addrs::{get_if_addrs, IfAddr};

use clap::Parser;


const ICMP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;


#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Name of the wireguard interface
    #[arg(short, long)]
    name: String,

    /// IP of target to test with (Optional)
    #[arg(short, long)]
    target: Option<String>,
}

#[tokio::main]
async fn main() {
    let  cli = Args::parse();

    let (interface, source, mut target) = if let Ok(ifaces) = get_if_addrs() {
        let mut interface = String::from("");
        let mut source = Ipv4Addr::new(0,0,0,0);
        let mut target = Ipv4Addr::new(0,0,0,0);
        for iface in ifaces {
            if iface.name == cli.name {
                match iface.addr {
                    IfAddr::V4(addr) => {
                        interface = iface.name;
                        source = addr.ip;
                        target = first_host_address(addr.ip, addr.netmask);
                        println!("Source: {} | Gateway: {}", addr.ip, addr.netmask);
                    },
                    IfAddr::V6(_) => {}
                }
                
            }
        }
        (interface, source, target)
    } else {
        println!("Cannot get interfaces from system. Exiting,");
        return;
    };


    if let Some(ip) = cli.target {
        match Ipv4Addr::from_str(&ip) {
            Ok(addr) => {
                target = addr;
            }
            Err(e) => {
                println!("Invalid IP address provided: {}", e);
                return;
            }
        };
    }

    println!("Running :: Interface: {}, Target: {}", interface, target);
    let start_mtu = 1500;
    
    for offset in 0..200 {
        let current_mtu = start_mtu - offset;
        let source = source.clone();
        let target = target.clone();

        match send_icmp_packet(source, target, current_mtu) {
            Ok(mtu) => {
                println!("MTU SUCCESS: {}", mtu);
                return;
            }
            Err(_) => {}
        }
    }
    println!("No suitable MTU found...");
}

fn first_host_address(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let netmask_u32 = u32::from(netmask);
    let network_address = ip_u32 & netmask_u32;
    let first_host_address = network_address + 1;
    Ipv4Addr::from(first_host_address)
}


fn send_icmp_packet(source: Ipv4Addr, destination: Ipv4Addr, icmp_payload_size: usize) -> Result<usize, Box<dyn std::error::Error>> {

    let (mut tx, mut rx) = transport_channel(1500, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();

    let packet_size = IPV4_HEADER_LEN + ICMP_HEADER_LEN + icmp_payload_size;
    let mut buffer = vec![0u8; packet_size];

    let payload_byte = icmp_payload_size as u8;

    // Construct ICMP Packet
    let mut icmp_packet = MutableIcmpPacket::new(&mut buffer[IPV4_HEADER_LEN..]).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let icmp_payload = vec![payload_byte; icmp_payload_size];
    icmp_packet.set_payload(&icmp_payload);
    let icmp_checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
    icmp_packet.set_checksum(icmp_checksum);

    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
    
    // Set IPv4 Header
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(packet_size as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);
    ipv4_packet.set_source(source);
    ipv4_packet.set_flags(2); // Set DF flag

    // Calculate the checksum for the IPv4 packet
    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);


    // Send the packet
    tx.send_to(ipv4_packet, std::net::IpAddr::V4(destination))?;

    // Wait for a response
    let timeout = Duration::from_secs(1);
    let start = Instant::now();
    let mut iter = ipv4_packet_iter(&mut rx);

    while start.elapsed() < timeout {
        match iter.next_with_timeout(timeout)? {
            Some((packet, _)) => {
                let next = packet.get_next_level_protocol();
                if next == IpNextHeaderProtocols::Icmp {
                    let payload = packet.payload();
                    if let Some(icmp_packet) = IcmpPacket::new(payload) {
                        if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                            return Ok(packet_size);
                        }
                    }
                }
            }
            _ => {} // Ignore other packets
        }
    }
    
    Err(Box::new(Error::new(ErrorKind::Other, "NO REPLY")))
}