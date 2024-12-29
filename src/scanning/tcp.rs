use tokio::io::{AsyncReadExt};
use std::time::Duration;
use std::{fs};
use colored::Colorize;
use futures::AsyncBufReadExt;
use regex::Regex;
use tokio::net::{TcpStream, UdpSocket};

pub(crate) async fn get_user_agents() -> Vec<String> {
    let user_path = "user-agents.txt".to_string();
    let user_agents = fs::read_to_string(user_path).unwrap_or("Mozilla/5.0".to_string());
    user_agents.lines().map(|x| x.to_string()).collect()
}

fn get_service_name(server_response: &str) -> String {
    let probe_path = "../service-probe/nmap-service-probe.txt".to_string();
    let probe = fs::read_to_string(probe_path).unwrap_or("".to_string());

    let probe_regex = Regex::new(r"Probe ([A-Z]+) ([^\s]+) q\|(.+?)\|").unwrap();
    let match_regex = Regex::new(r"match (\w+) m\|(.+?)\| p/(.+)/").unwrap();

    for cap in probe_regex.captures_iter(&probe) {
        let protocol = &cap[1];

        if protocol == "TCP" {
            for match_cap in match_regex.captures_iter(&probe) {
                let service_name = &match_cap[1];
                let pattern = &match_cap[2];

                if Regex::new(pattern).unwrap().is_match(server_response) {
                    return service_name.to_string();
                }
            }
        }
    }

    "Unknown".to_string()
}

pub async fn scan_tcp(ip: &str, port: u16, duration: Duration) ->  Option<(u16, String, String)> {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(duration, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buffer = [0u8; 1024];

            if let Ok(n) = stream.read(&mut buffer).await {
                let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                let service_name = get_service_name(&response);

                println!(
                    "{}{}: {} => {}: {} => {}: {}",
                    "[OPEN]".green(),
                    "[TCP]".on_yellow(),
                    port.to_string().yellow(),
                    "Response".green(),
                    response,
                    "Service".green(),
                    service_name
                );

                Some((port, response, service_name))
            } else {
                println!(
                    "{}{}: {} => {}",
                    "[CLOSED]".red(),
                    "[TCP]".on_yellow(),
                    port.to_string().yellow(),
                    "No Response".red()
                );
                None
            }
        }
        Ok(Err(_)) => {
            println!(
                "{}{}: {} => {}",
                "[FILTERED/CLOSED]".red(),
                "[TCP]".on_yellow(),
                port.to_string().yellow(),
                "Connection Error".red()
            );
            None
        }
        Err(e) => {
            eprintln!("{}", e);
            None
        }
    }
}

pub async fn scan_udp(ip: &str, port: u16, duration: Duration) -> Option<(u16, String, String)> {
    let addr = format!("{}:{}", ip, port);
    let local_addr = "0.0.0.0:0";

    match UdpSocket::bind(local_addr).await {
        Ok(socket) => {
            let message = b"Ping";
            if let Err(e) = socket.send_to(message, &addr).await {
                println!(
                    "{}{}: {} => {}: {}",
                    "[ERROR]".red(),
                    "[UDP]".on_yellow(),
                    port.to_string().yellow(),
                    "Send Error".red(),
                    e.to_string().red()
                );
                return None;
            }

            let mut buffer = [0u8; 1024];
            match tokio::time::timeout(duration, socket.recv_from(&mut buffer)).await {
                Ok(Ok((n, _))) => {
                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                    let service_name = get_service_name(&response);

                    println!(
                        "{}{}: {} => {}: {} => {}: {}",
                        "[OPEN]".green(),
                        "[UDP]".on_yellow(),
                        port.to_string().yellow(),
                        "Response".green(),
                        response,
                        "Service".green(),
                        service_name
                    );

                    Some((port, response, service_name))
                }
                _ => {
                    println!(
                        "{}{}: {} => {}",
                        "[FILTERED/CLOSED]".red(),
                        "[UDP]".on_yellow(),
                        port.to_string().yellow(),
                        "No Response".red()
                    );
                    None
                }
            }
        }
        Err(e) => {
            println!(
                "{}{}: {} => {}: {}",
                "[ERROR]".red(),
                "[UDP]".on_yellow(),
                port.to_string().yellow(),
                "Bind Error".red(),
                e.to_string().red()
            );
            None
        }
    }
}
