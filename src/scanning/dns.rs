use std::net::ToSocketAddrs;
use std::process::exit;
use colored::Colorize;
use url::Url;

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
    let url = Url::parse(domain);

    let mut ipv4 = None;
    let mut ipv6 = None;

    if let Some(host_str) = url.unwrap().host_str() {
        let addr_iter: Vec<_> = match (host_str, 0).to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            #[warn(unused_variables)]
            Err(e) => {
                eprintln!("{}: {}", "No IP addresses found for domain".red(), domain);
                exit(1);
            }
        };

        let mut ipv4_addr = None;
        let mut ipv6_addr = None;

        for socket_addr in &addr_iter {
            match socket_addr {
                std::net::SocketAddr::V4(ipv4) => {
                    ipv4_addr = Some(IpType::V4(ipv4.ip().to_string()));
                }
                std::net::SocketAddr::V6(ipv6) => {
                    ipv6_addr = Some(IpType::V6(ipv6.ip().to_string()));
                }
            }
        }

        let ipv4_result = if let Some(ipv4) = ipv4_addr {
            println!("{}: {:?}", "IPv4 address found".green(), ipv4);
            Some(ipv4)
        } else {
            None
        };

        let ipv6_result = if let Some(ipv6) = ipv6_addr {
            println!("{}: {:?}", "IPv6 address found".green(), ipv6);
            Some(ipv6)
        } else {
            None
        };

        if !ipv4_result.is_none() && !ipv6_result.is_none() {
            println!("{}", "webshot captured both IPv4 and IPv6 addresses".blue());
        }

        ipv4 = ipv4_result;
        ipv6 = ipv6_result;
    }

    IpAddresses {
        ipv4,
        ipv6,
    }
}