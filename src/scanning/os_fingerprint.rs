use pnet::packet::tcp::{TcpFlags, MutableTcpPacket, TcpOptionNumbers};
use pnet::packet::{Packet};
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol};
use pnet::util::checksum;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use std::net::{IpAddr, Ipv4Addr};
use chrono::Local;
use colored::Colorize;
use tokio::sync::mpsc;
use std::time::Duration;
use tokio::time::timeout;

fn create_syn_package(source_port: u16, destination_port: u16, ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Vec<u8> {
    let mut buffer = vec![0u8; 60];

    let (ip_buffer, tcp_buffer) = buffer.split_at_mut(20);

    let mut ip_packet = MutableIpv4Packet::new(ip_buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(ip);
    ip_packet.set_destination(dest_ip);
    ip_packet.set_checksum(checksum(&ip_packet.packet(), 2));

    let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(destination_port);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_checksum(compute_tcp_checksum(&ip_packet.to_immutable(), &tcp_packet));

    buffer
}

fn compute_tcp_checksum(ip_packet: &Ipv4Packet, tcp_packet: &MutableTcpPacket) -> u16 {
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&ip_packet.get_source().octets());
    pseudo_header.extend_from_slice(&ip_packet.get_destination().octets());
    pseudo_header.push(0);
    pseudo_header.push(6);
    pseudo_header.extend_from_slice(&(tcp_packet.packet().len() as u16).to_be_bytes());

    let mut checksum_data = Vec::new();
    checksum_data.extend_from_slice(&pseudo_header);
    checksum_data.extend_from_slice(tcp_packet.packet());

    checksum(&checksum_data, 0)
}

pub async fn send_syn_packet(source_port: u16, destination_port: u16, ip: Ipv4Addr, dest_ip: Ipv4Addr) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    let tcp_package_bytes = create_syn_package(source_port, destination_port, ip, dest_ip);
    let tcp_packet = MutableTcpPacket::owned(tcp_package_bytes).unwrap();

    let time = Local::now().format("%H:%M:%S").to_string();
    let (mut sender, _) = transport_channel(1024, Layer4(
        TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Tcp)
    )).unwrap();

    sender.send_to(tcp_packet, IpAddr::V4(dest_ip)).unwrap();
    if let Ok(size) = timeout(Duration::from_secs(50), rx.recv()).await {
        println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "Packet received, processing...".green());

        let cloned_size = size.unwrap();

        let ip_packet = Ipv4Packet::new(&cloned_size).unwrap();
        let tcp_buffer = &mut cloned_size[20..].to_vec();
        let syn_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        if syn_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
            println!("{}{} {} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "SYN-ACK packet received from: ".green(), ip_packet.get_source());
        }
        else if syn_packet.get_flags() == TcpFlags::RST {
            println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "RST packet received".green());
        }

        let ttl = ip_packet.get_ttl();
        let window_size = syn_packet.get_window();

        println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), format!("TTL: {}", ttl).green());
        println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), format!("Window Size: {}", window_size).green());

        for option in syn_packet.get_options_iter() {
            match option.get_number() {
                TcpOptionNumbers::MSS => {
                    println!("{}{} MSS Option: {:?}", format!("[{}]", time).yellow(), "[INFO]".blue(), option);
                }
                TcpOptionNumbers::WSCALE => {
                    println!("{}{} Window Scale Option: {:?}", format!("[{}]", time).yellow(), "[INFO]".blue(), option);
                }
                _ => {
                    println!("{}{} Unknown Option: {:?}", format!("[{}]", time).yellow(), "[INFO]".blue(), option);
                }
            }
        }


        match (ttl, window_size) {
            (64, 5840) => println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "OS Information Likely Linux".green()),
            (128, 8192) => println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "OS Information Likely Windows".green()),
            (255, 4128) => println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "OS Information Likely BSD".green()),
            _ => println!("{}{} {}", format!("[{}]", time).yellow(), "[WARN]".yellow(), "No OS Information Found".green())
        }
    }
    else {
        println!("{}{} {}", format!("[{}]", time).yellow(), "[WARN]".yellow(), "No response received within the timeout period".yellow());
    }
}
