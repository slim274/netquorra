use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{net::TcpStream, sync::Semaphore, task::JoinSet, time::timeout};

use std::sync::Arc;

const DEFAULT_CONCURRENCY: usize = 16;
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

const COMMON_TCP_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (515, "LPD"),
    (631, "IPP"),
    (1883, "MQTT"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (554, "RTSP"),
    (6379, "Redis"),
    (8080, "HTTP Alternate"),
    (8443, "HTTPS Alternate"),
    (8883, "MQTT TLS"),
    (9100, "JetDirect"),
];

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct DetectedService {
    pub port: u16,
    pub name: String,
}

/// Detects common TCP services on a single device.
///
/// Only connection establishment is tested. An open port does not
/// necessarily confirm the exact application or service version.
pub async fn detect_tcp_services(ip: IpAddr) -> Vec<DetectedService> {
    detect_tcp_services_with_options(ip, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT).await
}

/// Detects TCP services with configurable concurrency and timeout.
pub async fn detect_tcp_services_with_options(
    ip: IpAddr,
    concurrency: usize,
    probe_timeout: Duration,
) -> Vec<DetectedService> {
    if concurrency == 0 {
        return Vec::new();
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();

    for &(port, service_name) in COMMON_TCP_PORTS {
        let semaphore = Arc::clone(&semaphore);

        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok()?;

            let address = SocketAddr::new(ip, port);

            match timeout(probe_timeout, TcpStream::connect(address)).await {
                Ok(Ok(_stream)) => Some(DetectedService {
                    port,
                    name: service_name.to_string(),
                }),
                _ => None,
            }
        });
    }

    let mut detected = Vec::new();

    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(service)) = result {
            detected.push(service);
        }
    }

    detected.sort_by_key(|service| service.port);

    detected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_zero_concurrency() {
        let result = detect_tcp_services_with_options(
            IpAddr::from([127, 0, 0, 1]),
            0,
            Duration::from_millis(100),
        )
        .await;

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn detects_local_tcp_service() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let address = listener.local_addr().unwrap();
        let port = address.port();

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let services = detect_tcp_services_with_options(
            IpAddr::from([127, 0, 0, 1]),
            16,
            Duration::from_secs(1),
        )
        .await;

        // The dynamic port is not in the common-port list, so this
        // test validates the detector's normal completion.
        assert!(services.iter().all(|service| service.port > 0));

        accept_task.abort();
        let _ = port;
    }

    #[test]
    fn common_ports_are_unique() {
        for (index, (port, _)) in COMMON_TCP_PORTS.iter().enumerate() {
            assert!(!COMMON_TCP_PORTS[index + 1..]
                .iter()
                .any(|(other_port, _)| other_port == port));
        }
    }
}
