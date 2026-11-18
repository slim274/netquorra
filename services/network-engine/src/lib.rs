use ipnet::IpNet;
use std::{
    net::IpAddr,
    process::Stdio,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    process::Command,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

const MAX_SCAN_ADDRESSES: usize = 4096;
const DEFAULT_CONCURRENCY: usize = 64;

#[derive(Debug)]
pub enum DiscoveryError {
    InvalidNetwork(String),
    NetworkTooLarge(usize),
    InvalidConcurrency,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetwork(message) => write!(f, "{message}"),
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
///
/// Only scan networks you own or are authorized to administer.
pub async fn scan_network(
    cidr: &str,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    scan_network_with_options(
        cidr,
        DEFAULT_CONCURRENCY,
        Duration::from_secs(2),
    )
    .await
}

pub async fn scan_network_with_options(
    cidr: &str,
    concurrency: usize,
    probe_timeout: Duration,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    if concurrency == 0 {
        return Err(DiscoveryError::InvalidConcurrency);
    }

    let network = IpNet::from_str(cidr)
        .map_err(|error| DiscoveryError::InvalidNetwork(error.to_string()))?;

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
        let result = scan_network_with_options(
            "192.168.1.0/24",
            0,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(
            result,
            Err(DiscoveryError::InvalidConcurrency)
        ));
    }
}
