use std::env;
use std::net::Ipv4Addr;
use std::sync::{Arc};
use std::time::Duration;
use colored::{ColoredString, Colorize};
use cli_table::{ Cell, Style, Table};
use tokio::sync::{mpsc, Mutex};
use crate::scanning::tcp::{get_user_agents, scan_tcp, scan_udp};
use crate::scanning::os_fingerprint::send_syn_packet;
use chrono::Local;

mod scanning;

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 2 {
        println!("{}", "Command not found. Use --help for more information".red());
        eprintln!("{}", "Usage: [params] (<ip> || <url>) <port>".red());
        return;
    }

    if args[1] == "--help" {
        let table = vec![
            vec!["--help".green(), ColoredString::from("Show this help message")],
            vec!["<ip> | <url>".green(), ColoredString::from("IP address to scan or URL")],
            vec!["<port>".green(), ColoredString::from("Port to scan (e.g. 80) default: 1-9999")],
            vec!["--all".green(), ColoredString::from("Scan all ports (1-65535)")],
            vec!["--tcp".green(), ColoredString::from("Scan only TCP ports")],
            vec!["--udp".green(), ColoredString::from("Scan only UDP ports")],
            vec!["--random-agent".green(), ColoredString::from("Use a random user agent")],
            vec!["--ipv6".green(), ColoredString::from("Scan for IPv6 addresses")],
            vec!["--ipv4".green(), ColoredString::from("Scan for IPv4 addresses (default)")],
        ]
            .table()
            .title(vec![
                "Command".cell().bold(true),
                "Description".cell().bold(true),
            ]);

        let table_display = table.display().unwrap();
        println!("{}", table_display);
        println!("{}", "Example Usages".bold());
        println!("{}", "webshot 192.168.1.1 80-443 --all".green());
        println!("{}", "webshot 192.168.1.1 80-443".green());
        println!("{}", "webshot 192.168.1.1 --tcp".green());
        return;
    }

    let time = Local::now().format("%H:%M:%S").to_string();

    let mut ip = String::new();
    println!("{}{} {}", format!("[{}]", time).yellow(), "[WARN]".bright_yellow(), "Webshot 0.1.0. Webshot must not be used for illegal purposes. Webshot developers are not responsible for any illegal activity.".yellow());
    println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "Webshot is open source to support: https://github.com/yasinldev/webshot".blue());
    println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "Webshot uses different user agents to scan. Using a random user agent...".blue());

    let ip_type = scanning::dns::resolve_domain(&args[1]).await;

    let mut ports: Vec<u16> = Vec::new();
    if args.len() > 2 {
        if args[2].contains("-") {
            ports = args[2].split('-').map(|s| s.parse().unwrap()).collect();

            if ports.len() != 2 || ports[0] > ports[1] {
                eprintln!("{}{} {}", format!("[{}]", time), "[ERROR]".on_red(), "Invalid Port Range".red());
                return;
            }
        } else {
            ports.push(args[2].parse().unwrap());
        }
    }

    if args.contains(&"--ipv6".to_string()) {
        if let Some(ipv6) = ip_type.ipv6 {
            ip = match ipv6 {
                scanning::dns::IpType::V6(ip) => ip,
                _ => String::new(),
            };
        }
    } else {
        if let Some(ipv4) = ip_type.ipv4 {
            ip = match ipv4 {
                scanning::dns::IpType::V4(ip) => ip,
                _ => String::new(),
            };
        }
    }

    if ports.is_empty() {
        ports = vec![1, 443];
        println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "No port specified. Scanning default ports 1-443".blue());
    }

    let user_agents = Arc::new(Mutex::new(get_user_agents().await));

    let protocol = if args.contains(&"--udp".to_string()) {
        "UDP"
    } else {
        "TCP"
    };

    let mut target_port: Option<u16> = None;
    if args.contains(&"--search-os".to_string()) {
        if let Some(pos) = args.iter().position(|arg| arg == "--target-port") {
            if pos + 1 < args.len() {
                target_port = Some(args[pos + 1].parse().unwrap());
                println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), format!("OS search will be performed on port: {}", target_port.unwrap()).blue());

                let local_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
                let dest_ip: Ipv4Addr = ip.parse().unwrap();
                let source_port: u16 = 12345;
                send_syn_packet(source_port, target_port.unwrap(), local_ip, dest_ip).await;
            }
        } else {
            eprintln!("{}{} {}", format!("[{}]", time), "[ERROR]".on_red(), "Target port not specified".red());
            return;
        }
    }

    let (tx, mut rx) = mpsc::channel(100);

    println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(), "Scanning... (This process may take time depending on connection speed)".blue());

    for port in ports[0]..=ports[1] {
        let tx = tx.clone();
        let ip = ip.clone();

        tokio::spawn(async move {
            match protocol {
                "TCP" => {
                    if let Some((open_port, banner, is_open)) = scan_tcp(&ip, port, Duration::from_secs(100)).await {
                        tx.send((open_port, banner, is_open)).await.unwrap();
                    }
                }
                "UDP" => {
                    if let Some((open_port, banner, is_open)) = scan_udp(&ip, port, Duration::from_secs(100)).await {
                        tx.send((open_port, banner, is_open)).await.unwrap();
                    }
                }
                _ => {}
            }
        });
    }

    drop(tx);

    let mut results: Vec<(u16, String, String)> = Vec::new();

    while let Some((open_port, banner, service)) = rx.recv().await {
        results.push((open_port, banner, service));
    }

    println!("{}{} {}", format!("[{}]", time).yellow(), "[INFO]".blue(),"Scan completed".green());
}