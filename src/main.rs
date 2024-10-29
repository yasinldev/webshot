use std::env;
use std::sync::Arc;
use colored::{ColoredString, Colorize};
use cli_table::{ Cell, Style, Table};
use tokio::sync::{mpsc, Mutex};
use crate::scanning::tcp::{get_user_agents, scan_tcp};

mod scanning

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 3 {
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

    let mut ip = String::new();
    println!("{}", "webshot 0.1.0. Webshot must not be used for illegal purposes. Webshot developers are not responsible for any illegal activity".yellow());
    println!("{}", "webshot uses different user agents to scan. Using a random user agent...".yellow());
    println!("{}: {}", "INFO: If you do not want to use a different user-agent, you must specify this in the parameters".blue(), "--no-agent".on_blue());

    let mut ip_type: scanning::dns::IpAddresses =
        scanning::dns::IpAddresses {
            ipv4: None,
            ipv6: None,
        };
    if args[1].contains("http") || args[1].contains("https") {
        println!("{}", "URI detected. Resolving domain...".green());
        ip_type = scanning::dns::resolve_domain(&args[1]).await;
    }

    let mut ports: Vec<u16> = Vec::new();
    if args[2].contains("-") {
        ports = args[2]
            .split('-')
            .map(|s| s.parse().unwrap())
            .collect();

        if ports.len() != 2 {
            println!("{}", "Invalid port range format".red());
            return;
        }

        if ports[0] > ports[1] {
            println!("{}", "Invalid port range".red());
            return;
        }
    } else {
        ports.push(args[2].parse().unwrap());
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

    // tcp scan
    if ports.is_empty() {
        ports = vec![1, 9999];
        println!("{}", "No port specified. Scanning default ports 1-9999".green());
    }

    let (tx, mut rx) = mpsc::channel(100);

    // live scanning status
    println!("{}", "Scanning...".green());

    let user_agents = Arc::new(Mutex::new(get_user_agents().await));

    let mut protocols = None;
    if args.contains(&"--udp".to_string()) {
        protocols = Some("UDP");
    } else {
        protocols = Some("TCP");
    }

    if ports.len() == 1 {
        ports.push(ports[0]);
    }

    for port in ports[0]..=ports[1] {
        let tx = tx.clone();
        let ip = ip.clone();
        let cloned_user_agent = user_agents.clone();
        tokio::spawn(async move {
            if let Some((open_port, banner, is_open)) = scan_tcp(&ip, port, cloned_user_agent, protocols.unwrap()).await {
                tx.send((open_port, banner, is_open)).await.unwrap();
            }
        });
    }

    drop(tx);

    while let Some((open_port, banner, is_open)) = rx.recv().await {}

    println!("{}", "Scan completed".green());
}
