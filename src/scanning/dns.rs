use colored::Colorize;
use url::Url;
use chrono::Local;
use tokio::net::lookup_host;
use anyhow::{Context, Result};
use tracing::{info, warn};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(crate) enum IpType {
    V4(String),
    V6(String),
}

impl IpType {
    /// Get the IP address as a string
    pub fn to_string(&self) -> String {
        match self {
            IpType::V4(ip) => ip.clone(),
            IpType::V6(ip) => ip.clone(),
        }
    }

    /// Get the IP address as an IpAddr
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self {
            IpType::V4(ip) => ip.parse().ok(),
            IpType::V6(ip) => ip.parse().ok(),
        }
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpType::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpType::V6(_))
    }
}

pub struct IpAddresses {
    pub(crate) ipv4: Option<IpType>,
    pub(crate) ipv6: Option<IpType>,
}

impl IpAddresses {
    /// Get the first available IP address (IPv4 preferred)
    pub fn get_primary_ip(&self) -> Option<&IpType> {
        self.ipv4.as_ref().or(self.ipv6.as_ref())
    }

    /// Get all IP addresses as strings
    pub fn get_all_ips(&self) -> Vec<String> {
        let mut ips = Vec::new();
        if let Some(ip) = &self.ipv4 {
            ips.push(ip.to_string());
        }
        if let Some(ip) = &self.ipv6 {
            ips.push(ip.to_string());
        }
        ips
    }

    /// Check if any IP addresses were found
    pub fn has_ips(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    /// Get the count of available IP addresses
    pub fn count(&self) -> usize {
        let mut count = 0;
        if self.ipv4.is_some() { count += 1; }
        if self.ipv6.is_some() { count += 1; }
        count
    }
}

/// Resolve a domain name to IP addresses
pub async fn resolve_domain(domain: &str) -> Result<IpAddresses> {
    let time = Local::now().format("%H:%M:%S").to_string();
    
    info!("Resolving domain: {}", domain);

    // Try to parse as URL first
    let host_str = if domain.starts_with("http://") || domain.starts_with("https://") {
        Url::parse(domain)
            .ok()
            .and_then(|url| url.host_str().map(String::from))
    } else {
        Some(domain.to_string())
    };

    let host_str = host_str.ok_or_else(|| {
        anyhow::anyhow!("Invalid domain format: {}", domain)
    })?;

    // Perform DNS lookup
    let addr_iter = lookup_host((host_str.as_str(), 0))
        .await
        .context(format!("Failed to resolve domain: {}", domain))?;

    let addresses: Vec<_> = addr_iter.collect();
    
    if addresses.is_empty() {
        return Err(anyhow::anyhow!("No IP addresses found for domain: {}", domain));
    }

    let mut ipv4 = None;
    let mut ipv6 = None;

    for socket_addr in &addresses {
        match socket_addr {
            std::net::SocketAddr::V4(ipv4_addr) => {
                let ip = ipv4_addr.ip().to_string();
                if ipv4.is_none() {
                    ipv4 = Some(IpType::V4(ip.clone()));
                    info!(
                        "{} {} {}: {}",
                        format!("[{}]", time).yellow(),
                        "[INFO]".blue(),
                        "IPv4 address found".blue(),
                        ip
                    );
                }
            }
            std::net::SocketAddr::V6(ipv6_addr) => {
                let ip = ipv6_addr.ip().to_string();
                if ipv6.is_none() {
                    ipv6 = Some(IpType::V6(ip.clone()));
                    info!(
                        "{} {} {}: {}",
                        format!("[{}]", time).yellow(),
                        "[INFO]".blue(),
                        "IPv6 address found".blue(),
                        ip
                    );
                }
            }
        }
    }

    let result = IpAddresses { ipv4, ipv6 };
    
    info!(
        "Domain resolution completed: {} IP addresses found",
        result.count()
    );

    Ok(result)
}

/// Resolve a domain to a specific IP type
pub async fn resolve_domain_to_ip(domain: &str, prefer_ipv6: bool) -> Result<String> {
    let addresses = resolve_domain(domain).await?;
    
    if prefer_ipv6 {
        if let Some(ipv6) = addresses.ipv6 {
            return Ok(ipv6.to_string());
        }
        if let Some(ipv4) = addresses.ipv4 {
            warn!("IPv6 not available for {}, using IPv4: {}", domain, ipv4.to_string());
            return Ok(ipv4.to_string());
        }
    } else {
        if let Some(ipv4) = addresses.ipv4 {
            return Ok(ipv4.to_string());
        }
        if let Some(ipv6) = addresses.ipv6 {
            warn!("IPv6 not available for {}, using IPv4: {}", domain, ipv6.to_string());
            return Ok(ipv6.to_string());
        }
    }
    
    Err(anyhow::anyhow!("No IP addresses found for domain: {}", domain))
}

/// Check if a string is a valid IP address
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Check if a string is a valid domain name
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    
    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        
        if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }
    
    true
}

/// Reverse DNS lookup - get hostname from IP address
pub async fn reverse_dns_lookup(ip: &str) -> Result<Option<String>> {
    let ip_addr: IpAddr = ip.parse()
        .context(format!("Invalid IP address: {}", ip))?;
    
    let socket_addr = std::net::SocketAddr::new(ip_addr, 0);
    
    match lookup_host(socket_addr).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                let hostname = addr.to_string().split(':').next().unwrap_or("").to_string();
                if !hostname.is_empty() && hostname != ip {
                    Ok(Some(hostname))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("127.0.0.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("192.168.1.1"));
        assert!(!is_valid_ip("invalid"));
        assert!(!is_valid_ip("256.256.256.256"));
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("invalid"));
        assert!(!is_valid_domain("a".repeat(64) + ".com"));
    }

    #[test]
    fn test_ip_type_methods() {
        let ipv4 = IpType::V4("127.0.0.1".to_string());
        let ipv6 = IpType::V6("::1".to_string());
        
        assert!(ipv4.is_ipv4());
        assert!(!ipv4.is_ipv6());
        assert!(ipv6.is_ipv6());
        assert!(!ipv6.is_ipv4());
        
        assert_eq!(ipv4.to_string(), "127.0.0.1");
        assert_eq!(ipv6.to_string(), "::1");
    }
}