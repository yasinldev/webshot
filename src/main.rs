use clap::{Parser, Subcommand};
use colored::*;
use tracing::{info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::scanning::{
    config::ScanConfig,
    scanner::NetworkScanner,
    types::ScanResult,
};

mod scanning;

#[derive(Parser)]
#[command(
    name = "webshot",
    about = "Professional network port scanner and service detector",
    version,
    long_about = "Webshot is a high-performance network scanner that can detect open ports, 
identify services, and provide detailed information about network hosts. 
It supports both TCP and UDP scanning with configurable timeouts and user agents."
)]
struct Cli {
    /// Target IP address or domain name
    #[arg(value_name = "TARGET")]
    target: String,

    /// Port range to scan (e.g., 80, 80-443, 1-65535)
    #[arg(value_name = "PORTS", default_value = "1-1024")]
    ports: String,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Scan only TCP ports
    #[arg(long, conflicts_with = "udp")]
    tcp: bool,

    /// Scan only UDP ports
    #[arg(long, conflicts_with = "tcp")]
    udp: bool,

    /// Use random user agents for each request
    #[arg(long)]
    random_agent: bool,

    /// Scan all ports (1-65535)
    #[arg(long, conflicts_with = "ports")]
    all: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value = "5")]
    timeout: u64,

    /// Number of concurrent connections
    #[arg(long, default_value = "100")]
    concurrency: usize,

    /// Output results in JSON format
    #[arg(long)]
    json: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long)]
    quiet: bool,

    /// Show closed ports in results
    #[arg(long)]
    show_closed: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for common web services
    Web {
        /// Target URL
        #[arg(value_name = "URL")]
        url: String,
    },
    /// Scan for database services
    Database {
        /// Database type (mysql, postgres, redis, mongodb)
        #[arg(value_name = "TYPE")]
        db_type: String,
    },
    /// Scan for specific service
    Service {
        /// Service name to scan for
        #[arg(value_name = "SERVICE")]
        service: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Set log level based on verbosity
    if cli.quiet {
        std::env::set_var("RUST_LOG", "error");
    } else if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }

    // Display banner
    if !cli.quiet {
        display_banner();
    }

    // Handle subcommands
    if let Some(command) = cli.command {
        match command {
            Commands::Web { url } => {
                info!("Starting web service scan for: {}", url);
                // TODO: Implement web service scanning
                return Ok(());
            }
            Commands::Database { db_type } => {
                info!("Starting database scan for: {}", db_type);
                // TODO: Implement database scanning
                return Ok(());
            }
            Commands::Service { service } => {
                info!("Starting service scan for: {}", service);
                // TODO: Implement specific service scanning
                return Ok(());
            }
        }
    }

    // Parse port range
    let ports = parse_port_range(&cli.ports, cli.all)?;

    // Create scan configuration
    let config = ScanConfig {
        target: cli.target.clone(),
        ports,
        protocol: if cli.udp { "UDP" } else { "TCP" },
        timeout: std::time::Duration::from_secs(cli.timeout),
        concurrency: cli.concurrency,
        random_agent: cli.random_agent,
        json_output: cli.json,
        show_closed: cli.show_closed,
    };

    if !cli.quiet {
        println!("\n{}", "Scan Configuration:".bold().cyan());
        println!("{}", "─".repeat(50));
        println!("{} {}", "Target:".bold(), config.target.cyan());
        println!("{} {}", "Protocol:".bold(), config.protocol.yellow());
        println!("{} {}", "Ports:".bold(), config.ports.len().to_string().green());
        println!("{} {}", "Timeout:".bold(), format!("{}s", config.timeout.as_secs()).blue());
        println!("{} {}", "Concurrency:".bold(), config.concurrency.to_string().magenta());
        println!("{}", "─".repeat(50));
        println!();
    }

    // Create scanner
    let scanner = NetworkScanner::new(config.clone()).await?;

    if !cli.quiet {
        println!("{}", "Starting scan...".bold().green());
        println!();
    }
    
    let results = scanner.run().await?;

    if !cli.quiet {
        println!();
        display_results(&results, &config)?;
    } else {
        let open_count = results.iter().filter(|r| r.is_open).count();
        let closed_count = results.iter().filter(|r| !r.is_open).count();
        println!("Open: {}, Closed: {}, Total: {}", open_count, closed_count, results.len());
    }

    Ok(())
}

fn display_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".blue());
    println!("{}", "║                        WEBSHOT                               ║".blue().bold());
    println!("{}", "║                                                              ║".blue());
    println!("{}", "║  Version: 0.1.0 | Author: yasinldev                          ║".blue());
    println!("{}", "║  Repository: https://github.com/yasinldev/webshot            ║".blue());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".blue());
    println!();
    
    println!("{}", "Legal Notice:".bold().yellow());
    println!("{}", "   WebShot must not be used for illegal purposes.".yellow());
    println!("{}", "   Developers are not responsible for any illegal activity.".yellow());
    println!();
}

fn parse_port_range(ports: &str, all: bool) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    if all {
        return Ok((1..=65535).collect());
    }

    // Handle comma-separated ports
    if ports.contains(',') {
        let mut port_list = Vec::new();
        for port_str in ports.split(',') {
            let port_str = port_str.trim();
            if port_str.contains('-') {
                // Handle ranges within comma-separated list
                let parts: Vec<&str> = port_str.split('-').collect();
                if parts.len() != 2 {
                    return Err("Invalid port range format. Use: start-end (e.g., 80-443)".into());
                }
                
                let start: u16 = parts[0].trim().parse()?;
                let end: u16 = parts[1].trim().parse()?;
                
                if start > end {
                    return Err("Start port must be less than or equal to end port".into());
                }
                
                if start == 0 || end > 65535 {
                    return Err("Ports must be between 1 and 65535".into());
                }
                
                port_list.extend(start..=end);
            } else {
                // Single port
                let port: u16 = port_str.parse()?;
                if port == 0 || port > 65535 {
                    return Err("Port must be between 1 and 65535".into());
                }
                port_list.push(port);
            }
        }
        return Ok(port_list);
    }

    // Handle simple range (e.g., "80-443")
    if ports.contains('-') {
        let parts: Vec<&str> = ports.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid port range format. Use: start-end (e.g., 80-443)".into());
        }
        
        let start: u16 = parts[0].trim().parse()?;
        let end: u16 = parts[1].trim().parse()?;
        
        if start > end {
            return Err("Start port must be less than or equal to end port".into());
        }
        
        if start == 0 || end > 65535 {
            return Err("Ports must be between 1 and 65535".into());
        }
        
        Ok((start..=end).collect())
    } else {
        // Single port
        let port: u16 = ports.trim().parse()?;
        if port == 0 || port > 65535 {
            return Err("Port must be between 1 and 65535".into());
        }
        Ok(vec![port])
    }
}

fn display_results(results: &[ScanResult], config: &ScanConfig) -> Result<(), Box<dyn std::error::Error>> {
    if results.is_empty() {
        println!("{}", "No open ports found".bold().yellow());
        return Ok(());
    }

    if config.json_output {
        let json = serde_json::to_string_pretty(&results)?;
        println!("{}", json);
    } else {
        let open_results: Vec<_> = results.iter().filter(|r| r.is_open).collect();
        let closed_results: Vec<_> = results.iter().filter(|r| !r.is_open).collect();
        if !open_results.is_empty() {
            println!("{}", "OPEN PORTS:".bold().green());
            println!("{}", "═".repeat(80));
            
            for result in &open_results {
                println!(
                    "{} {} {} {} {} {}",
                    format!("[{}]", result.protocol).yellow(),
                    format!("Port {}", result.port).cyan().bold(),
                    "->".white(),
                    format!("{}", result.service).blue().bold(),
                    "|".white(),
                    format!("{}", result.banner.chars().take(60).collect::<String>()).white()
                );
            }
            println!("{}", "═".repeat(80));
            println!("{} {} {}", "Total open ports:".bold(), open_results.len().to_string().green().bold(), "found".bold());
        }
        if config.show_closed && !closed_results.is_empty() {
            println!();
            println!("{}", "CLOSED/FILTERED PORTS:".bold().red());
            println!("{}", "═".repeat(80));
            
            for result in &closed_results {
                println!(
                    "{} {} {} {}",
                    format!("[{}]", result.protocol).yellow(),
                    format!("Port {}", result.port).cyan(),
                    "->".white(),
                    "Port is closed or filtered".red()
                );
            }
            println!("{}", "═".repeat(80));
            println!("{} {} {}", "Total closed ports:".bold(), closed_results.len().to_string().red().bold(), "found".bold());
        }
        println!();
        println!("{}", "SCAN SUMMARY:".bold().magenta());
        println!("{}", "─".repeat(50));
        println!("{} {} {}", "Open ports:".bold(), open_results.len().to_string().green().bold(), "".bold());
        println!("{} {} {}", "Closed ports:".bold(), closed_results.len().to_string().red().bold(), "".bold());
        println!("{} {} {}", "Total ports:".bold(), results.len().to_string().cyan().bold(), "".bold());
        
        if !open_results.is_empty() {
            let success_rate = (open_results.len() as f64 / results.len() as f64 * 100.0) as u32;
            println!("{} {} {}", "Success rate:".bold(), format!("{}%", success_rate).yellow().bold(), "".bold());
        }
        println!("{}", "─".repeat(50));
    }

    Ok(())
}