pub mod classification;
pub mod service_detection;

pub use classification::{
    classify_device, ClassificationSignals, DeviceCategory, DeviceClassification,
};

pub use service_detection::{
    detect_tcp_services, detect_tcp_services_with_options, DetectedService,
};

mod vendor;

pub use vendor::{classify_mac, lookup_mac_vendor, MacAddressType, VendorInfo};

use ipnet::IpNet;
use std::{net::IpAddr, process::Stdio, str::FromStr, sync::Arc, time::Duration};

use tokio::{process::Command, sync::Semaphore, task::JoinSet, time::timeout};

const MAX_SCAN_ADDRESSES: usize = 4096;
const DEFAULT_CONCURRENCY: usize = 64;
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Represents a discovered network device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredDevice {
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub mac_address_type: Option<MacAddressType>,

    // TCP service detection
    pub open_ports: Vec<u16>,
    pub detected_services: Vec<DetectedService>,

    // Device classification
    pub device_category: DeviceCategory,
    pub classification_confidence: f32,
    pub classification_evidence: Vec<String>,

    pub status: String,
}

/// Errors returned by network discovery.
#[derive(Debug)]
pub enum DiscoveryError {
    InvalidNetwork(String),
    NetworkTooLarge(usize),
    InvalidConcurrency,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetwork(message) => {
                write!(f, "{message}")
            }
            Self::NetworkTooLarge(size) => {
                write!(f, "Network contains too many addresses: {size}")
            }
            Self::InvalidConcurrency => {
                write!(f, "Concurrency must be greater than zero")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Discovers devices that respond to ICMP on an IPv4 network.
pub async fn scan_network(cidr: &str) -> Result<Vec<IpAddr>, DiscoveryError> {
    scan_network_with_options(cidr, DEFAULT_CONCURRENCY, DEFAULT_PROBE_TIMEOUT).await
}

/// Discovers responsive IPv4 addresses with configurable concurrency.
pub async fn scan_network_with_options(
    cidr: &str,
    concurrency: usize,
    probe_timeout: Duration,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    if concurrency == 0 {
        return Err(DiscoveryError::InvalidConcurrency);
    }

    let network =
        IpNet::from_str(cidr).map_err(|error| DiscoveryError::InvalidNetwork(error.to_string()))?;

    if !network.addr().is_ipv4() {
        return Err(DiscoveryError::InvalidNetwork(
            "Only IPv4 networks are supported currently".to_string(),
        ));
    }

    let addresses: Vec<IpAddr> = network.hosts().take(MAX_SCAN_ADDRESSES + 1).collect();

    if addresses.len() > MAX_SCAN_ADDRESSES {
        return Err(DiscoveryError::NetworkTooLarge(addresses.len()));
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for ip in addresses {
        let semaphore = Arc::clone(&semaphore);

        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok()?;

            if ping_host(ip, probe_timeout).await {
                Some(ip)
            } else {
                None
            }
        });
    }

    let mut discovered = Vec::new();

    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(ip)) = result {
            discovered.push(ip);
        }
    }

    discovered.sort();

    Ok(discovered)
}

pub mod snmp;
/// Performs detailed discovery and classifies responsive devices.
pub async fn scan_network_detailed(cidr: &str) -> Result<Vec<DiscoveredDevice>, DiscoveryError> {
    let discovered_ips = scan_network(cidr).await?;

    let default_gateway = lookup_default_gateway().await;

    let mut tasks = JoinSet::new();

    for ip in discovered_ips {
        let is_default_gateway = default_gateway == Some(ip);

        tasks.spawn(async move {
            // Collect device information concurrently.
            let (mac_address, hostname, detected_services) = tokio::join!(
                lookup_mac_address(ip),
                lookup_hostname(ip),
                detect_tcp_services(ip),
            );

            // Identify MAC address type.
            let mac_address_type = mac_address.as_deref().map(classify_mac);

            // Identify manufacturer using IEEE registry.
            let manufacturer = match mac_address.as_deref() {
                Some(mac) => lookup_mac_vendor(mac)
                    .ok()
                    .flatten()
                    .map(|vendor| vendor.manufacturer),
                None => None,
            };

            // Extract open TCP ports for classification.
            let open_ports: Vec<u16> = detected_services
                .iter()
                .map(|service| service.port)
                .collect();

            // Build classification signals.
            // SNMP, LLDP and endpoint-agent collectors
            // are not implemented yet.
            let signals = ClassificationSignals {
                hostname: hostname.clone(),
                manufacturer: manufacturer.clone(),
                is_default_gateway,
                open_ports: open_ports.clone(),
                snmp_detected: false,
                lldp_detected: false,
                endpoint_agent_detected: false,
            };

            let classification = classify_device(&signals);

            DiscoveredDevice {
                ip_address: ip,
                mac_address,
                hostname,
                manufacturer,
                mac_address_type,

                open_ports,
                detected_services,

                device_category: classification.category,
                classification_confidence: classification.confidence,
                classification_evidence: classification.evidence,

                status: "online".to_string(),
            }
        });
    }

    let mut devices = Vec::new();

    while let Some(result) = tasks.join_next().await {
        if let Ok(device) = result {
            devices.push(device);
        }
    }

    devices.sort_by_key(|device| device.ip_address);

    Ok(devices)
}

/// Retrieves the default IPv4 gateway on Linux.
async fn lookup_default_gateway() -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let result = String::from_utf8_lossy(&output.stdout);

        for line in result.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if let Some(index) = parts.iter().position(|part| *part == "via") {
                if let Some(gateway) = parts.get(index + 1) {
                    if let Ok(ip) = gateway.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    None
}

/// Checks whether a host responds to ICMP ping.
async fn ping_host(ip: IpAddr, probe_timeout: Duration) -> bool {
    let mut command = Command::new("ping");

    command.kill_on_drop(true);
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    command.args(["-n", "1", "-w", "1000"]);

    #[cfg(target_os = "linux")]
    command.args(["-c", "1", "-W", "1"]);

    #[cfg(target_os = "macos")]
    command.args(["-c", "1", "-W", "1000"]);

    command.arg(ip.to_string());

    matches!(
        timeout(probe_timeout, command.status()).await,
        Ok(Ok(status)) if status.success()
    )
}

/// Retrieves a MAC address from the Linux neighbour table.
async fn lookup_mac_address(ip: IpAddr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["neigh", "show", &ip.to_string()])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let result = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = result.split_whitespace().collect();

        if let Some(index) = parts.iter().position(|part| *part == "lladdr") {
            return parts.get(index + 1).map(|mac| mac.to_string());
        }
    }

    None
}

/// Resolves a hostname using the operating system resolver.
async fn lookup_hostname(ip: IpAddr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("getent")
            .args(["hosts", &ip.to_string()])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let result = String::from_utf8_lossy(&output.stdout);

        return result
            .split_whitespace()
            .nth(1)
            .map(|hostname| hostname.to_string());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ip;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_invalid_network() {
        let result = scan_network("not-a-network").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_for_now() {
        let result = scan_network("2001:db8::/64").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_zero_concurrency() {
        let result = scan_network_with_options("192.168.1.0/24", 0, Duration::from_secs(1)).await;

        assert!(matches!(result, Err(DiscoveryError::InvalidConcurrency)));
    }

    #[tokio::test]
    async fn detailed_scan_returns_structured_devices() {
        let device = DiscoveredDevice {
            ip_address: "192.168.1.1".parse().unwrap(),
            mac_address: Some("60:3d:29:78:13:f0".to_string()),
            hostname: Some("router".to_string()),
            manufacturer: None,
            mac_address_type: None,

            open_ports: vec![22, 80, 443],
            detected_services: vec![
                DetectedService {
                    port: 22,
                    name: "SSH".to_string(),
                },
                DetectedService {
                    port: 80,
                    name: "HTTP".to_string(),
                },
            ],

            device_category: DeviceCategory::Router,
            classification_confidence: 0.8,
            classification_evidence: vec!["Identified as the default network gateway".to_string()],
            status: "online".to_string(),
        };

        assert_eq!(device.ip_address, "192.168.1.1".parse::<IpAddr>().unwrap());

        assert_eq!(device.mac_address.as_deref(), Some("60:3d:29:78:13:f0"));

        assert_eq!(device.open_ports.len(), 3);
        assert_eq!(device.detected_services.len(), 2);
        assert_eq!(device.status, "online");
    }

    #[test]
    fn identifies_locally_administered_mac() {
        let result = classify_mac("CA:9E:14:BF:FC:30");

        assert!(matches!(result, MacAddressType::LocallyAdministered));
    }

    #[test]
    fn identifies_globally_administered_mac() {
        let result = classify_mac("60:3D:29:78:13:F0");

        assert!(matches!(result, MacAddressType::GloballyAdministered));
    }

    #[test]
    fn identifies_multicast_mac() {
        let result = classify_mac("01:00:5E:00:00:01");

        assert!(matches!(result, MacAddressType::Multicast));
    }
}
