use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub protocol: &'static str,
    /// Connection timeout
    pub timeout: Duration,
    /// Number of concurrent connections
    pub concurrency: usize,
    /// Whether to use random user agents
    pub random_agent: bool,
    /// Whether to output results in JSON format
    pub json_output: bool,

    /// Whether to show closed ports in results
    pub show_closed: bool,
}

impl ScanConfig {
    /// Create a new scan configuration with default values
    pub fn new(target: String) -> Self {
        Self {
            target,
            ports: vec![80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 27017],
            protocol: "TCP",
            timeout: Duration::from_secs(5),
            concurrency: 100,
            random_agent: false,
            json_output: false,
            show_closed: false,
        }
    }

    /// Set the ports to scan
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    /// Set the protocol
    pub fn with_protocol(mut self, protocol: &'static str) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the concurrency level
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Enable random user agents
    pub fn with_random_agent(mut self, random_agent: bool) -> Self {
        self.random_agent = random_agent;
        self
    }

    /// Enable JSON output
    pub fn with_json_output(mut self, json_output: bool) -> Self {
        self.json_output = json_output;
        self
    }

    /// Get the total number of ports to scan
    pub fn total_ports(&self) -> usize {
        self.ports.len()
    }

    /// Check if this is a TCP scan
    pub fn is_tcp(&self) -> bool {
        self.protocol == "TCP"
    }

    /// Check if this is a UDP scan
    pub fn is_udp(&self) -> bool {
        self.protocol == "UDP"
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::new("127.0.0.1".to_string())
    }
}
