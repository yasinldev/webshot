use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents the result of a port scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// The port that was scanned
    pub port: u16,
    /// The protocol used (TCP or UDP)
    pub protocol: String,
    /// Whether the port is open
    pub is_open: bool,
    /// The service running on the port
    pub service: String,
    /// The banner/response from the service
    pub banner: String,
    /// The IP address of the target
    pub target_ip: Option<IpAddr>,
    /// The hostname if a domain was provided
    pub hostname: Option<String>,
    /// Timestamp when the scan was performed
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(
        port: u16,
        protocol: String,
        is_open: bool,
        service: String,
        banner: String,
        target_ip: Option<IpAddr>,
        hostname: Option<String>,
    ) -> Self {
        Self {
            port,
            protocol,
            is_open,
            service,
            banner,
            target_ip,
            hostname,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a new open port result
    pub fn open(
        port: u16,
        protocol: String,
        service: String,
        banner: String,
        target_ip: Option<IpAddr>,
        hostname: Option<String>,
    ) -> Self {
        Self::new(port, protocol, true, service, banner, target_ip, hostname)
    }

    /// Create a new closed port result
    pub fn closed(
        port: u16,
        protocol: String,
        target_ip: Option<IpAddr>,
        hostname: Option<String>,
    ) -> Self {
        Self::new(
            port,
            protocol,
            false,
            "Closed".to_string(),
            "".to_string(),
            target_ip,
            hostname,
        )
    }
}

/// Represents a service fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    /// The name of the service
    pub name: String,
    /// The version of the service
    pub version: Option<String>,
    /// The vendor of the service
    pub vendor: Option<String>,
    /// The product name
    pub product: Option<String>,
    /// Additional information about the service
    pub extra_info: Option<String>,
}

impl ServiceFingerprint {
    /// Create a new service fingerprint
    pub fn new(name: String) -> Self {
        Self {
            name,
            version: None,
            vendor: None,
            product: None,
            extra_info: None,
        }
    }

    /// Set the version
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the vendor
    pub fn with_vendor(mut self, vendor: String) -> Self {
        self.vendor = Some(vendor);
        self
    }

    /// Set the product
    pub fn with_product(mut self, product: String) -> Self {
        self.product = Some(product);
        self
    }

    /// Set extra information
    pub fn with_extra_info(mut self, extra_info: String) -> Self {
        self.extra_info = Some(extra_info);
        self
    }
}

/// Represents a scan summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total number of ports scanned
    pub total_ports: usize,
    /// Number of open ports found
    pub open_ports: usize,
    /// Number of closed ports
    pub closed_ports: usize,
    /// Number of filtered ports
    pub filtered_ports: usize,
    /// Scan duration
    pub duration: std::time::Duration,
    /// Target information
    pub target: String,
    /// Protocol used
    pub protocol: String,
    /// Timestamp when scan started
    pub start_time: chrono::DateTime<chrono::Utc>,
    /// Timestamp when scan completed
    pub end_time: chrono::DateTime<chrono::Utc>,
}

impl ScanSummary {
    /// Create a new scan summary
    pub fn new(target: String, protocol: String, total_ports: usize) -> Self {
        let now = chrono::Utc::now();
        Self {
            total_ports,
            open_ports: 0,
            closed_ports: 0,
            filtered_ports: 0,
            duration: std::time::Duration::ZERO,
            target,
            protocol,
            start_time: now,
            end_time: now,
        }
    }

    /// Mark scan as completed
    pub fn complete(mut self, open_ports: usize, closed_ports: usize, filtered_ports: usize) -> Self {
        self.open_ports = open_ports;
        self.closed_ports = closed_ports;
        self.filtered_ports = filtered_ports;
        self.end_time = chrono::Utc::now();
        self.duration = self.end_time.signed_duration_since(self.start_time).to_std().unwrap_or_default();
        self
    }

    /// Get the scan success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_ports == 0 {
            0.0
        } else {
            (self.open_ports as f64 / self.total_ports as f64) * 100.0
        }
    }
}
