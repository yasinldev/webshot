use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt};
use std::sync::{Arc};
use std::time::Duration;
use std::{fs, io};
use colored::Colorize;
use futures::AsyncBufReadExt;
use reqwest::Client;
use reqwest::header::USER_AGENT;
use tokio::sync::Mutex;

pub(crate) async fn get_user_agents() -> Vec<String> {
    let user_path = "user-agents.txt".to_string();
    let user_agents = fs::read_to_string(user_path).unwrap_or("Mozilla/5.0".to_string());
    user_agents.lines().map(|x| x.to_string()).collect()
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP (Data Transfer)",
        21 => "FTP (File Transfer Protocol)",
        22 => "SSH (Secure Shell)",
        23 => "Telnet",
        25 => "SMTP (Simple Mail Transfer Protocol)",
        53 => "DNS (Domain Name System)",
        67 => "DHCP (Server)",
        68 => "DHCP (Client)",
        69 => "TFTP (Trivial File Transfer Protocol)",
        80 => "HTTP (Hypertext Transfer Protocol)",
        110 => "POP3 (Post Office Protocol v3)",
        111 => "RPC (Remote Procedure Call)",
        119 => "NNTP (Network News Transfer Protocol)",
        123 => "NTP (Network Time Protocol)",
        135 => "MSRPC (Microsoft RPC)",
        137 => "NetBIOS (Name Service)",
        138 => "NetBIOS (Datagram Service)",
        139 => "NetBIOS (Session Service)",
        143 => "IMAP (Internet Message Access Protocol)",
        161 => "SNMP (Simple Network Management Protocol)",
        179 => "BGP (Border Gateway Protocol)",
        194 => "IRC (Internet Relay Chat)",
        389 => "LDAP (Lightweight Directory Access Protocol)",
        443 => "HTTPS (HTTP Secure)",
        445 => "SMB (Server Message Block)",
        465 => "SMTPS (Secure SMTP)",
        514 => "Syslog (System Logging Protocol)",
        546 => "DHCPv6 (Client)",
        547 => "DHCPv6 (Server)",
        993 => "IMAPS (IMAP Secure)",
        995 => "POP3S (POP3 Secure)",
        1080 => "SOCKS (SOCKS Proxy)",
        1194 => "OpenVPN",
        1433 => "MSSQL (Microsoft SQL Server)",
        1521 => "Oracle Database",
        1723 => "PPTP (Point-to-Point Tunneling Protocol)",
        1883 => "MQTT (Message Queuing Telemetry Transport)",
        2049 => "NFS (Network File System)",
        2082 => "cPanel (HTTP)",
        2083 => "cPanel (HTTPS)",
        2086 => "WHM (HTTP)",
        2087 => "WHM (HTTPS)",
        2181 => "ZooKeeper",
        2222 => "DirectAdmin (HTTP)",
        3306 => "MySQL/MariaDB",
        3389 => "RDP (Remote Desktop Protocol)",
        5000 => "UPnP (Universal Plug and Play)",
        5060 => "SIP (Session Initiation Protocol)",
        5222 => "XMPP (Extensible Messaging and Presence Protocol)",
        5432 => "PostgreSQL",
        5900 => "VNC (Virtual Network Computing)",
        6379 => "Redis",
        8080 => "HTTP (Alternate HTTP)",
        9090 => "HTTP (Alternate HTTP)",
        9091 => "HTTP (Alternate HTTP)",
        9200 => "Elasticsearch",
        27017 => "MongoDB (NoSQL Database)",
        27018 => "MongoDB (Shard Server)",
        27019 => "MongoDB (Config Server)",
        28017 => "MongoDB (HTTP Interface)",
        50000 => "SAP (Systems, Applications, and Products)",
        50070 => "Hadoop (NameNode Web UI)",
        60000 => "Hadoop (IPC)",
        _ => "Unknown",
    }
}

pub async fn scan_tcp(ip: &str, port: u16, user_agents: Arc<Mutex<Vec<String>>>, protocol: &str) -> Option<(u16, String, bool)> {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buffer = [0u8; 1024];

            if let Ok(n) = stream.read(&mut buffer).await {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();

                let default_user_agent = "Mozilla/5.0".to_string();

                let user_agents = user_agents.lock().await.clone();
                let user_agent = user_agents.get(0).unwrap_or(&default_user_agent);

                let client = Client::new();
                let response = client
                    .get(format!("http://{}:{}", ip, port))
                    .header(USER_AGENT, user_agent)
                    .send()
                    .await;


                match response {
                    Ok(resp) => {
                        println!(
                            "{} [{}]: {} => {}: {} => {}: {}",
                            "OPEN".green(),
                            protocol.on_yellow(),
                            port.to_string().yellow(),
                            "HTTP Response".green(),
                            resp.status(),
                            "Service".green(),
                            get_service_name(port)
                        );

                    }
                    Err(e) => println!(
                        "{} [{}]: {} => {}: {} => {}: {}",
                        "OPEN".green(),
                        protocol.on_yellow(),
                        port.to_string().yellow(),
                        "HTTP Response".red(),
                        e.to_string().red(),
                        "Service".green(),
                        get_service_name(port)
                    ),
                }

                Some((port, banner, true))
            } else {
                None
            }
        }
        _ => Some((port, String::new(), false)),
    }
}
