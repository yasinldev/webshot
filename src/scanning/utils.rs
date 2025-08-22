use std::time::Duration;
use colored::*;
use chrono::Local;

/// Format duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    if duration.as_secs() < 60 {
        format!("{:.2}s", duration.as_secs_f64())
    } else if duration.as_secs() < 3600 {
        let minutes = duration.as_secs() / 60;
        let seconds = duration.as_secs() % 60;
        format!("{}m {}s", minutes, seconds)
    } else {
        let hours = duration.as_secs() / 3600;
        let minutes = (duration.as_secs() % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    }
}

/// Format bytes in a human-readable way
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Get current timestamp in a formatted string
pub fn get_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Colorize log level
pub fn colorize_log_level(level: &str) -> ColoredString {
    match level {
        "ERROR" => level.red().bold(),
        "WARN" => level.yellow().bold(),
        "INFO" => level.blue().bold(),
        "DEBUG" => level.green().bold(),
        "TRACE" => level.cyan(),
        _ => level.white(),
    }
}

/// Validate port number
pub fn is_valid_port(port: u16) -> bool {
    port > 0 && port <= 65535
}

/// Validate IP address format
pub fn is_valid_ip_format(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Validate domain name format
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

/// Parse port range string (e.g., "80-443")
pub fn parse_port_range(range: &str) -> Result<Vec<u16>, String> {
    if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid port range format. Use: start-end (e.g., 80-443)".to_string());
        }
        
        let start: u16 = parts[0].parse()
            .map_err(|_| "Invalid start port".to_string())?;
        let end: u16 = parts[1].parse()
            .map_err(|_| "Invalid end port".to_string())?;
        
        if !is_valid_port(start) || !is_valid_port(end) {
            return Err("Ports must be between 1 and 65535".to_string());
        }
        
        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }
        
        Ok((start..=end).collect())
    } else {
        let port: u16 = range.parse()
            .map_err(|_| "Invalid port number".to_string())?;
        
        if !is_valid_port(port) {
            return Err("Port must be between 1 and 65535".to_string());
        }
        
        Ok(vec![port])
    }
}

/// Generate a random string of specified length
pub fn random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Calculate percentage
pub fn calculate_percentage(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30.00s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_is_valid_port() {
        assert!(is_valid_port(80));
        assert!(is_valid_port(443));
        assert!(is_valid_port(65535));
        assert!(!is_valid_port(0));
        assert!(!is_valid_port(65536));
    }

    #[test]
    fn test_is_valid_ip_format() {
        assert!(is_valid_ip_format("127.0.0.1"));
        assert!(is_valid_ip_format("::1"));
        assert!(is_valid_ip_format("192.168.1.1"));
        assert!(!is_valid_ip_format("invalid"));
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("invalid"));
    }

    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("80").unwrap(), vec![80]);
        assert_eq!(parse_port_range("80-443").unwrap(), (80..=443).collect::<Vec<u16>>());
        assert!(parse_port_range("invalid").is_err());
        assert!(parse_port_range("80-").is_err());
        assert!(parse_port_range("-443").is_err());
    }

    #[test]
    fn test_calculate_percentage() {
        assert_eq!(calculate_percentage(50, 100), 50.0);
        assert_eq!(calculate_percentage(0, 100), 0.0);
        assert_eq!(calculate_percentage(100, 100), 100.0);
        assert_eq!(calculate_percentage(0, 0), 0.0);
    }
}
