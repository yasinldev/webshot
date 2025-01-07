use tokio::io::{AsyncReadExt};
use std::time::Duration;
use std::{fs};
use std::error::Error;
use colored::Colorize;
use futures::AsyncBufReadExt;
use regex::Regex;
use tokio::net::{TcpStream, UdpSocket};

pub(crate) async fn get_user_agents() -> Vec<String> {
    let user_path = "user-agents.txt".to_string();
    let user_agents = fs::read_to_string(user_path).unwrap_or("Mozilla/5.0".to_string());
    user_agents.lines().map(|x| x.to_string()).collect()
}

async fn get_service_name(server_response: &str) -> Result<String, Box<dyn Error>> {
    let url = "https://svn.nmap.org/nmap/nmap-service-probes?view=co&rev=HEAD&pathrev=HEAD";

    let response = reqwest::get(url).await.map_err(|e| {
        println!("{}{}", "[ERROR]".on_red(), e);
        e
    })?;

    let probe = response.text().await.map_err(|e| {
        println!("{}{}", "[ERROR]".on_red(), e);
        e
    })?;

    let match_regex = Regex::new(r"match (\S+) m\|([^|]+?)\| p/([^/]+?)/")?;

    for match_cap in match_regex.captures_iter(&probe) {
        let service_name = &match_cap[1];
        let pattern = &match_cap[2];

        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(server_response) {
                return Ok(format!("{} {}", service_name, &match_cap[3]));
            }
        }
    }

    Ok("Unknown".to_string())
}

pub async fn scan_tcp(ip: &str, port: u16, duration: Duration) ->  Option<(u16, String, String)> {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(duration, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buffer = [0u8; 1024];

            if let Ok(n) = stream.read(&mut buffer).await {
                let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                let res_clone = response.clone();

                let service_name = get_service_name(res_clone.as_str());
                let service_name_result = service_name.await.unwrap().to_string();

                println!(
                    "{}{} {} \n => {}:  {}  \n => {}: {}",
                    "[OPEN]".green(),
                    "[TCP]".yellow(),
                    port.to_string().yellow(),
                    "Response".green(),
                    response.clone().to_string(),
                    "Service".green(),
                    service_name_result
                );

                Some((port, response, service_name_result))
            } else {
                println!(
                    "{}{} {} => {}",
                    "[CLOSED]".red(),
                    "[TCP]".yellow(),
                    port.to_string().yellow(),
                    "No Response".red()
                );
                None
            }
        }
        Ok(Err(_)) => {
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
                    "{}{} {} => {}: {}",
                    "[ERROR]".red(),
                    "[UDP]".yellow(),
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
                    let res_clone = response.clone();

                    let service_name = get_service_name(res_clone.as_str());
                    let ser_clone = service_name.await.unwrap().to_string();

                    println!(
                        "{}{} {} => {}: {} => {}: {}",
                        "[OPEN]".green(),
                        "[UDP]".yellow(),
                        port.to_string().yellow(),
                        "Response".green(),
                        response,
                        "Service".green(),
                        ser_clone
                    );

                    Some((port, response, ser_clone))
                }
                _ => {
                    None
                }
            }
        }
        Err(e) => {
            println!(
                "{}{} {} => {}: {}",
                "[ERROR]".red(),
                "[UDP]".yellow(),
                port.to_string().yellow(),
                "Bind Error".red(),
                e.to_string().red()
            );
            None
        }
    }
}
