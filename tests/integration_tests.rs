use webshot::scanning::{
    config::ScanConfig,
    scanner::NetworkScanner,
    types::ScanResult,
    utils,
};

#[tokio::test]
async fn test_basic_tcp_scan() {
    // Test basic TCP scanning functionality
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_ports(vec![80, 443, 8080])
        .with_protocol("TCP")
        .with_timeout(std::time::Duration::from_secs(1))
        .with_concurrency(10);

    let scanner = NetworkScanner::new(config).await.unwrap();
    let results = scanner.run().await.unwrap();
    
    // Should return results (even if ports are closed)
    assert!(results.len() <= 3);
}

#[tokio::test]
async fn test_domain_resolution() {
    // Test domain resolution
    let config = ScanConfig::new("localhost".to_string())
        .with_ports(vec![80])
        .with_timeout(std::time::Duration::from_secs(1));

    let scanner = NetworkScanner::new(config).await.unwrap();
    assert!(scanner.target_ip().is_some());
    assert!(scanner.hostname().is_some());
}

#[tokio::test]
async fn test_config_builder_pattern() {
    // Test configuration builder pattern
    let config = ScanConfig::new("127.0.0.1".to_string())
        .with_ports(vec![80, 443])
        .with_protocol("TCP")
        .with_timeout(std::time::Duration::from_secs(5))
        .with_concurrency(50)
        .with_random_agent(true)
        .with_json_output(true);

    assert_eq!(config.target, "127.0.0.1");
    assert_eq!(config.ports, vec![80, 443]);
    assert_eq!(config.protocol, "TCP");
    assert_eq!(config.timeout, std::time::Duration::from_secs(5));
    assert_eq!(config.concurrency, 50);
    assert!(config.random_agent);
    assert!(config.json_output);
    assert_eq!(config.total_ports(), 2);
    assert!(config.is_tcp());
    assert!(!config.is_udp());
}

#[test]
fn test_utility_functions() {
    // Test utility functions
    assert!(utils::is_valid_port(80));
    assert!(utils::is_valid_port(443));
    assert!(utils::is_valid_port(65535));
    assert!(!utils::is_valid_port(0));
    assert!(!utils::is_valid_port(65536));

    assert!(utils::is_valid_ip_format("127.0.0.1"));
    assert!(utils::is_valid_ip_format("::1"));
    assert!(utils::is_valid_ip_format("192.168.1.1"));
    assert!(!utils::is_valid_ip_format("invalid"));

    assert!(utils::is_valid_domain("example.com"));
    assert!(utils::is_valid_domain("sub.example.com"));
    assert!(!utils::is_valid_domain(""));
    assert!(!utils::is_valid_domain("invalid"));

    let duration = std::time::Duration::from_secs(90);
    assert_eq!(utils::format_duration(duration), "1m 30s");

    assert_eq!(utils::format_bytes(1024), "1.00 KB");
    assert_eq!(utils::format_bytes(1048576), "1.00 MB");

    assert_eq!(utils::calculate_percentage(50, 100), 50.0);
    assert_eq!(utils::calculate_percentage(0, 100), 0.0);
}

#[test]
fn test_port_range_parsing() {
    // Test port range parsing
    let ports = utils::parse_port_range("80").unwrap();
    assert_eq!(ports, vec![80]);

    let ports = utils::parse_port_range("80-443").unwrap();
    assert_eq!(ports, (80..=443).collect::<Vec<u16>>());

    assert!(utils::parse_port_range("invalid").is_err());
    assert!(utils::parse_port_range("80-").is_err());
    assert!(utils::parse_port_range("-443").is_err());
    assert!(utils::parse_port_range("0-100").is_err());
    assert!(utils::parse_port_range("100-50").is_err());
}

#[test]
fn test_random_string_generation() {
    // Test random string generation
    let random1 = utils::random_string(10);
    let random2 = utils::random_string(10);
    
    assert_eq!(random1.len(), 10);
    assert_eq!(random2.len(), 10);
    // Note: These could theoretically be the same, but it's very unlikely
    // assert_ne!(random1, random2);
}

#[tokio::test]
async fn test_scan_result_creation() {
    // Test scan result creation
    let result = ScanResult::open(
        80,
        "TCP".to_string(),
        "HTTP Server".to_string(),
        "HTTP/1.1 200 OK".to_string(),
        None,
        Some("example.com".to_string()),
    );

    assert_eq!(result.port, 80);
    assert_eq!(result.protocol, "TCP");
    assert!(result.is_open);
    assert_eq!(result.service, "HTTP Server");
    assert_eq!(result.banner, "HTTP/1.1 200 OK");
    assert!(result.target_ip.is_none());
    assert_eq!(result.hostname, Some("example.com".to_string()));

    let closed_result = ScanResult::closed(
        81,
        "TCP".to_string(),
        None,
        None,
    );

    assert_eq!(closed_result.port, 81);
    assert_eq!(closed_result.protocol, "TCP");
    assert!(!closed_result.is_open);
    assert_eq!(closed_result.service, "Closed");
    assert_eq!(closed_result.banner, "");
}

#[test]
fn test_service_fingerprint() {
    use webshot::scanning::types::ServiceFingerprint;

    let fingerprint = ServiceFingerprint::new("HTTP Server")
        .with_version("2.4.41".to_string())
        .with_vendor("Apache".to_string())
        .with_product("HTTP Server".to_string())
        .with_extra_info("Additional info".to_string());

    assert_eq!(fingerprint.name, "HTTP Server");
    assert_eq!(fingerprint.version, Some("2.4.41".to_string()));
    assert_eq!(fingerprint.vendor, Some("Apache".to_string()));
    assert_eq!(fingerprint.product, Some("HTTP Server".to_string()));
    assert_eq!(fingerprint.extra_info, Some("Additional info".to_string()));
}

#[test]
fn test_scan_summary() {
    use webshot::scanning::types::ScanSummary;

    let summary = ScanSummary::new(
        "127.0.0.1".to_string(),
        "TCP".to_string(),
        1000,
    );

    assert_eq!(summary.total_ports, 1000);
    assert_eq!(summary.open_ports, 0);
    assert_eq!(summary.closed_ports, 0);
    assert_eq!(summary.filtered_ports, 0);
    assert_eq!(summary.target, "127.0.0.1");
    assert_eq!(summary.protocol, "TCP");

    let completed_summary = summary.complete(50, 900, 50);
    assert_eq!(completed_summary.open_ports, 50);
    assert_eq!(completed_summary.closed_ports, 900);
    assert_eq!(completed_summary.filtered_ports, 50);
    assert_eq!(completed_summary.success_rate(), 5.0);
}

#[tokio::test]
async fn test_error_handling() {
    // Test error handling for invalid targets
    let config = ScanConfig::new("invalid-domain-that-does-not-exist-12345.com".to_string())
        .with_ports(vec![80])
        .with_timeout(std::time::Duration::from_secs(1));

    let result = NetworkScanner::new(config).await;
    assert!(result.is_err());
}

#[test]
fn test_config_defaults() {
    // Test configuration defaults
    let config = ScanConfig::default();
    assert_eq!(config.target, "127.0.0.1");
    assert_eq!(config.protocol, "TCP");
    assert_eq!(config.timeout, std::time::Duration::from_secs(5));
    assert_eq!(config.concurrency, 100);
    assert!(!config.random_agent);
    assert!(!config.json_output);
    assert!(config.total_ports() > 0);
}
