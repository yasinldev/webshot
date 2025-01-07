use std::process::exit;
use colored::Colorize;
use url::Url;
use chrono::Local;
use tokio::net::lookup_host;

#[derive(Debug)]
pub(crate) enum IpType {
    V4(String),
    V6(String),
}

pub struct IpAddresses {
    pub(crate) ipv4: Option<IpType>,
    pub(crate) ipv6: Option<IpType>,
}

pub async fn resolve_domain(domain: &str) -> IpAddresses {
    let time = Local::now().format("%H:%M:%S").to_string();

    let host_str = Url::parse(domain).ok().and_then(|url| url.host_str().map(String::from));

    let addr_iter = match lookup_host((host_str.unwrap().as_str(), 0)).await {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => {
            eprintln!(
                "{}{} {}: {} ({})",
                format!("[{}]", time).yellow(),
                "[ERROR]".on_red(),
                "Failed to resolve domain".red(),
                domain,
                e
            );
            exit(1);
        }
    };

    let mut ipv4 = None;
    let mut ipv6 = None;

    for socket_addr in &addr_iter {
        match socket_addr {
            std::net::SocketAddr::V4(ipv4_addr) => {
                ipv4 = Some(IpType::V4(ipv4_addr.ip().to_string()));
            },
            std::net::SocketAddr::V6(ipv6_addr) => {
                ipv6 = Some(IpType::V6(ipv6_addr.ip().to_string()));
            },
        }
    }

    if let Some(ip) = &ipv4 {
        println!(
            "{}{} {}: {:?}",
            format!("[{}]", time).yellow(),
            "[INFO]".blue(),
            "IPv4 address found".green(),
            ip
        );
    } else {
        println!(
            "{}{} {}: No IPv4 address found",
            format!("[{}]", time).yellow(),
            "[INFO]".blue(),
            "IPv4 address not found".blue()
        );
    }

    if let Some(ip) = &ipv6 {
        println!(
            "{}{} {}: {:?}",
            format!("[{}]", time).yellow(),
            "[INFO]".blue(),
            "IPv6 address found".green(),
            ip
        );
    } else {
        println!(
            "{}{} {}: No IPv6 address found",
            format!("[{}]", time).yellow(),
            "[INFO]".blue(),
            "IPv6 address not found".blue()
        );
    }

    IpAddresses { ipv4, ipv6 }
}