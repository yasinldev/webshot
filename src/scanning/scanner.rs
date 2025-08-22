use crate::scanning::{
    config::ScanConfig,
    dns::resolve_domain,
    tcp::{scan_tcp, scan_udp},
    types::{ScanResult, ScanSummary},
};
use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{error, info};

/// Main network scanner that orchestrates port scanning
pub struct NetworkScanner {
    config: ScanConfig,
    target_ip: Option<String>,
    hostname: Option<String>,
}

impl NetworkScanner {
    /// Create a new network scanner
    pub async fn new(config: ScanConfig) -> Result<Self> {
        info!("Initializing scanner for target: {}", config.target);
        
        // Resolve domain to IP if needed
        let (target_ip, hostname) = if is_ip_address(&config.target) {
            (Some(config.target.clone()), None)
        } else {
            let addresses = resolve_domain(&config.target).await?;
            let ip = if config.is_tcp() {
                addresses.ipv4.map(|ip| match ip {
                    crate::scanning::dns::IpType::V4(ip) => ip,
                    _ => String::new(),
                })
            } else {
                addresses.ipv6.map(|ip| match ip {
                    crate::scanning::dns::IpType::V6(ip) => ip,
                    _ => String::new(),
                })
            };
            (ip, Some(config.target.clone()))
        };

        if target_ip.is_none() {
            return Err(anyhow::anyhow!("Failed to resolve target: {}", config.target));
        }

        info!("Target resolved to: {}", target_ip.as_ref().unwrap());
        
        Ok(Self {
            config,
            target_ip,
            hostname,
        })
    }

    /// Run the network scan
    pub async fn run(&self) -> Result<Vec<ScanResult>> {
        let start_time = std::time::Instant::now();
        let total_ports = self.config.total_ports();
        
        info!(
            "Starting {} scan of {} ports on {}",
            self.config.protocol,
            total_ports,
            self.config.target
        );

        // Create progress bar
        let progress_bar = if !self.config.json_output {
            let pb = ProgressBar::new(total_ports as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) | {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb.set_message("Scanning ports...");
            Some(pb)
        } else {
            None
        };

        // Create semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        
        // Create channel for results
        let (tx, mut rx) = mpsc::channel(1000);
        
        // Spawn scanning tasks
        let mut handles = Vec::new();
        
        for &port in &self.config.ports {
            let tx = tx.clone();
            let semaphore = semaphore.clone();
            let target_ip = self.target_ip.clone().unwrap();
            let hostname = self.hostname.clone();
            let protocol = self.config.protocol.to_string();
            let timeout = self.config.timeout;
            let progress_bar = progress_bar.clone();
            let show_closed = self.config.show_closed;

            let handle = tokio::spawn(async move {
                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();
                
                let result = if protocol == "TCP" {
                    scan_tcp(&target_ip, port, timeout).await
                } else {
                    scan_udp(&target_ip, port, timeout).await
                };

                if let Some((open_port, banner, service)) = result {
                    let scan_result = ScanResult::open(
                        open_port,
                        protocol.clone(),
                        service,
                        banner,
                        None, // TODO: Parse IP address
                        hostname,
                    );
                    tx.send(scan_result).await.unwrap();
                } else if show_closed {
                    // Send closed port result if requested
                    let scan_result = ScanResult::closed(
                        port,
                        protocol.clone(),
                        None,
                        None,
                    );
                    tx.send(scan_result).await.unwrap();
                }
                // If result is None and show_closed is false, we don't send anything

                // Update progress bar
                if let Some(pb) = progress_bar {
                    pb.inc(1);
                    // Update message with current progress
                    let progress_percent = (pb.position() as f64 / pb.length().unwrap() as f64 * 100.0) as u32;
                    pb.set_message(format!("Scanning... {}% complete", progress_percent));
                }

                // Permit is automatically released when dropped
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Task failed: {}", e);
            }
        }

        // Close sender and collect results
        drop(tx);
        
        let mut results = Vec::new();
        while let Some(result) = rx.recv().await {
            results.push(result);
        }

        // Complete progress bar
        if let Some(pb) = progress_bar {
            pb.finish_with_message("Scan completed successfully!");
        }

        let duration = start_time.elapsed();
        let open_ports = results.len();
        let closed_ports = total_ports - open_ports;

        // Show completion message
        if !self.config.json_output {
            println!("\n{}", "Scan Completed Successfully!".bold().green());
            println!("{}", "─".repeat(50));
        }

        info!(
            "Scan completed in {:.2?}. Found {} open ports out of {} total ports",
            duration, open_ports, total_ports
        );

        // Create and log summary
        let summary = ScanSummary::new(
            self.config.target.clone(),
            self.config.protocol.to_string(),
            total_ports,
        ).complete(open_ports, closed_ports, 0);

        info!(
            "Scan Summary: {} open ports ({}%), {} closed ports, {} filtered ports",
            summary.open_ports,
            summary.success_rate(),
            summary.closed_ports,
            summary.filtered_ports
        );

        Ok(results)
    }

    /// Get scan configuration
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Get target IP
    pub fn target_ip(&self) -> Option<&String> {
        self.target_ip.as_ref()
    }

    /// Get hostname
    pub fn hostname(&self) -> Option<&String> {
        self.hostname.as_ref()
    }
}

/// Check if a string is a valid IP address
fn is_ip_address(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("127.0.0.1"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("192.168.1.1"));
        assert!(!is_ip_address("localhost"));
        assert!(!is_ip_address("example.com"));
    }
}
