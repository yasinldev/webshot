use tokio::io::AsyncReadExt;
use std::time::Duration;
use std::fs;
use std::error::Error;
use colored::Colorize;
use regex::Regex;
use tokio::net::{TcpStream, UdpSocket};
use anyhow::Result;
use tracing::{debug, info, warn};
use crate::scanning::types::ServiceFingerprint;

/// Get user agents from the user-agents.txt file
pub(crate) async fn get_user_agents() -> Vec<String> {
    let user_path = "src/scanning/user-agents.txt";
    match fs::read_to_string(user_path) {
        Ok(content) => {
            let agents: Vec<String> = content.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
                .collect();
            
            if agents.is_empty() {
                warn!("No user agents found in file, using default");
                vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()]
            } else {
                info!("Loaded {} user agents", agents.len());
                agents
            }
        }
        Err(e) => {
            warn!("Failed to read user agents file: {}, using default", e);
            vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()]
        }
    }
}

/// Get a random user agent from the list
pub fn get_random_user_agent() -> String {
    use rand::Rng;
    let agents = tokio::runtime::Handle::current()
        .block_on(get_user_agents());
    
    if agents.is_empty() {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()
    } else {
        let mut rng = rand::thread_rng();
        agents[rng.gen_range(0..agents.len())].clone()
    }
}

/// Get service name from server response using NMAP service probes
async fn get_service_name(server_response: &str) -> Result<String, Box<dyn Error>> {
    // For now, use a simplified service detection
    // In a production version, you'd want to load and cache the NMAP service probes
    let response_lower = server_response.to_lowercase();
    
    // Common service patterns
    if response_lower.contains("http") || response_lower.contains("apache") || response_lower.contains("nginx") {
        return Ok("HTTP Server".to_string());
    }
    
    if response_lower.contains("ssh") {
        return Ok("SSH".to_string());
    }
    
    if response_lower.contains("ftp") {
        return Ok("FTP".to_string());
    }
    
    if response_lower.contains("smtp") {
        return Ok("SMTP".to_string());
    }
    
    if response_lower.contains("pop3") {
        return Ok("POP3".to_string());
    }
    
    if response_lower.contains("imap") {
        return Ok("IMAP".to_string());
    }
    
    if response_lower.contains("mysql") {
        return Ok("MySQL".to_string());
    }
    
    if response_lower.contains("postgresql") || response_lower.contains("postgres") {
        return Ok("PostgreSQL".to_string());
    }
    
    if response_lower.contains("redis") {
        return Ok("Redis".to_string());
    }
    
    if response_lower.contains("mongodb") {
        return Ok("MongoDB".to_string());
    }
    
    if response_lower.contains("telnet") {
        return Ok("Telnet".to_string());
    }
    
    if response_lower.contains("dns") {
        return Ok("DNS".to_string());
    }
    
    // If no specific service is detected, try to extract version info
    if !server_response.trim().is_empty() {
        return Ok(format!("Unknown Service ({})", server_response.chars().take(50).collect::<String>()));
    }
    
    Ok("Unknown Service".to_string())
}

/// Detect service by port number for ports that accept connections but don't send banners
fn detect_service_by_port(port: u16) -> String {
    match port {
        21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        80 => "HTTP".to_string(),
        81 => "HTTP Alternative".to_string(),
        110 => "POP3".to_string(),
        143 => "IMAP".to_string(),
        443 => "HTTPS".to_string(),
        993 => "IMAPS".to_string(),
        995 => "POP3S".to_string(),
        3306 => "MySQL".to_string(),
        5432 => "PostgreSQL".to_string(),
        6379 => "Redis".to_string(),
        27017 => "MongoDB".to_string(),
        8080 => "HTTP Proxy".to_string(),
        8443 => "HTTPS Alternative".to_string(),
        9200 => "Elasticsearch".to_string(),
        11211 => "Memcached".to_string(),
        _ => "Unknown Service".to_string(),
    }
}

/// Scan a TCP port
pub async fn scan_tcp(ip: &str, port: u16, duration: Duration) -> Option<(u16, String, String)> {
    let addr = format!("{}:{}", ip, port);
    debug!("Scanning TCP port {} on {}", port, ip);

    // First, try to establish a connection
    let stream_result = tokio::time::timeout(duration, TcpStream::connect(&addr)).await;
    
    match stream_result {
        Ok(Ok(mut stream)) => {
            debug!("TCP connection established to {}", addr);
            
            // Set a shorter timeout for reading to avoid hanging
            let read_timeout = Duration::from_millis(500);
            
            // Try to read from the connection
            let mut buffer = [0u8; 1024];
            let read_result = tokio::time::timeout(read_timeout, stream.read(&mut buffer)).await;
            
            match read_result {
                Ok(Ok(n)) => {
                    if n > 0 {
                        // Successfully read data - port is truly open with service
                        let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                        
                        let service_name = match get_service_name(&response).await {
                            Ok(service) => service,
                            Err(e) => {
                                warn!("Failed to detect service for port {}: {}", port, e);
                                "Unknown Service".to_string()
                            }
                        };

                        debug!(
                            "{} {} {} => {}: {} => {}: {}",
                            "[OPEN]".green(),
                            "[TCP]".yellow(),
                            port.to_string().yellow(),
                            "Response".green(),
                            response.chars().take(100).collect::<String>(),
                            "Service".green(),
                            service_name
                        );

                        Some((port, response, service_name))
                    } else { // n == 0
                        // Connection established but no data - try to detect service by port number
                        let service_name = detect_service_by_port(port);
                        
                        debug!(
                            "{} {} {} => {} => {}: {}",
                            "[OPEN]".green(),
                            "[TCP]".yellow(),
                            port.to_string().yellow(),
                            "Accepts Connections".blue(),
                            "Service".green(),
                            service_name
                        );
                        
                        Some((port, "Accepts Connections".to_string(), service_name))
                    }
                }
                Ok(Err(_)) => {
                    // Connection established but read failed - try to detect service by port number
                    let service_name = detect_service_by_port(port);
                    
                    debug!(
                        "{} {} {} => {} => {}: {}",
                        "[OPEN]".green(),
                        "[TCP]".yellow(),
                        port.to_string().yellow(),
                        "Accepts Connections".blue(),
                        "Service".green(),
                        service_name
                    );
                    
                    Some((port, "Accepts Connections".to_string(), service_name))
                }
                Err(_) => {
                    // Connection established but read timeout - try to detect service by port number
                    let service_name = detect_service_by_port(port);
                    
                    debug!(
                        "{} {} {} => {} => {}: {}",
                        "[OPEN]".green(),
                        "[TCP]".yellow(),
                        port.to_string().yellow(),
                        "Accepts Connections (Timeout)".blue(),
                        "Service".green(),
                        service_name
                    );
                    
                    Some((port, "Accepts Connections (Timeout)".to_string(), service_name))
                }
            }
        }
        Ok(Err(e)) => {
            debug!("TCP connection failed to {}: {}", addr, e);
            // Port is closed or filtered
            None
        }
        Err(_) => {
            debug!("TCP connection timeout to {}", addr);
            // Port is filtered or timeout occurred
            None
        }
    }
}

/// Scan a UDP port
pub async fn scan_udp(ip: &str, port: u16, duration: Duration) -> Option<(u16, String, String)> {
    let addr = format!("{}:{}", ip, port);
    let local_addr = "0.0.0.0:0";
    debug!("Scanning UDP port {} on {}", port, ip);

    match UdpSocket::bind(local_addr).await {
        Ok(socket) => {
            let message = b"Ping";
            
            if let Err(e) = socket.send_to(message, &addr).await {
                debug!("UDP send failed to {}: {}", addr, e);
                return None;
            }

            let mut buffer = [0u8; 1024];
            
            match tokio::time::timeout(duration, socket.recv_from(&mut buffer)).await {
                Ok(Ok((n, _))) => {
                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                    
                    let service_name = match get_service_name(&response).await {
                        Ok(service) => service,
                        Err(e) => {
                            warn!("Failed to detect service for UDP port {}: {}", port, e);
                            "Unknown Service".to_string()
                        }
                    };

                    info!(
                        "{} {} {} => {}: {} => {}: {}",
                        "[OPEN]".green(),
                        "[UDP]".yellow(),
                        port.to_string().yellow(),
                        "Response".green(),
                        response.chars().take(100).collect::<String>(),
                        "Service".green(),
                        service_name
                    );

                    Some((port, response, service_name))
                }
                _ => {
                    debug!("UDP port {} appears to be closed/filtered", port);
                    None
                }
            }
        }
        Err(e) => {
            debug!("UDP socket bind failed: {}", e);
            None
        }
    }
}

/// Enhanced service fingerprinting
pub async fn fingerprint_service(ip: &str, port: u16, protocol: &str) -> Result<ServiceFingerprint, Box<dyn Error>> {
    let addr = format!("{}:{}", ip, port);
    let timeout = Duration::from_secs(5);
    
    let response = if protocol == "TCP" {
        match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buffer = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buffer).await {
                    String::from_utf8_lossy(&buffer[..n]).to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    } else {
        // UDP fingerprinting
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                let message = b"FINGERPRINT";
                if socket.send_to(message, &addr).await.is_ok() {
                    let mut buffer = [0u8; 1024];
                    match tokio::time::timeout(timeout, socket.recv_from(&mut buffer)).await {
                        Ok(Ok((n, _))) => {
                            String::from_utf8_lossy(&buffer[..n]).to_string()
                        }
                        _ => String::new(),
                    }
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    };

    let service_name = get_service_name(&response).await.unwrap_or_else(|_| "Unknown".to_string());
    
    // Try to extract version information
    let version = extract_version(&response);
    let vendor = extract_vendor(&response);
    let product = extract_product(&response);
    
    Ok(ServiceFingerprint::new(service_name)
        .with_version(version.unwrap_or_default())
        .with_vendor(vendor.unwrap_or_default())
        .with_product(product.unwrap_or_default())
        .with_extra_info(response.chars().take(200).collect()))
}

/// Extract version information from service response
fn extract_version(response: &str) -> Option<String> {
    let version_patterns = [
        r"(\d+\.\d+\.\d+)",
        r"(\d+\.\d+)",
        r"version[:\s]+([^\s\r\n]+)",
        r"v(\d+\.\d+\.\d+)",
    ];
    
    for pattern in &version_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(response) {
                if let Some(version) = captures.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }
    }
    
    None
}

/// Extract vendor information from service response
fn extract_vendor(response: &str) -> Option<String> {
    let vendor_patterns = [
        r"(Apache|Nginx|Microsoft|Oracle|IBM|Cisco|Juniper|F5|Citrix|VMware)",
        r"([A-Z][a-z]+)\s+Software",
        r"([A-Z][a-z]+)\s+Corporation",
    ];
    
    for pattern in &vendor_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(response) {
                if let Some(vendor) = captures.get(1) {
                    return Some(vendor.as_str().to_string());
                }
            }
        }
    }
    
    None
}

/// Extract product information from service response
fn extract_product(response: &str) -> Option<String> {
    let product_patterns = [
        r"(IIS|Apache|Nginx|MySQL|PostgreSQL|Redis|MongoDB|SSH|FTP|SMTP|POP3|IMAP)",
        r"([A-Z][a-z]+)\s+Server",
        r"([A-Z][a-z]+)\s+Service",
    ];
    
    for pattern in &product_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(response) {
                if let Some(product) = captures.get(1) {
                    return Some(product.as_str().to_string());
                }
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("Apache/2.4.41"), Some("2.4.41".to_string()));
        assert_eq!(extract_version("nginx version 1.18.0"), Some("1.18.0".to_string()));
        assert_eq!(extract_version("MySQL 8.0.26"), Some("8.0.26".to_string()));
    }

    #[test]
    fn test_extract_vendor() {
        assert_eq!(extract_vendor("Apache Software Foundation"), Some("Apache".to_string()));
        assert_eq!(extract_vendor("Microsoft Corporation"), Some("Microsoft".to_string()));
    }

    #[test]
    fn test_extract_product() {
        assert_eq!(extract_product("Apache HTTP Server"), Some("Apache".to_string()));
        assert_eq!(extract_product("MySQL Server"), Some("MySQL".to_string()));
    }
}
