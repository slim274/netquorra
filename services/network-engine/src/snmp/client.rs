use std::net::SocketAddr;
use std::time::Duration;

use async_snmp::{Client, Retry, UdpClient};

use super::credentials::SnmpCredentials;

/// Default SNMP agent port.
pub const SNMP_PORT: u16 = 161;

/// Default request timeout.
pub const SNMP_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// SNMP client configuration.
#[derive(Debug, Clone)]
pub struct SnmpClientConfig {
    pub request_timeout: Duration,
    pub retries: u32,
    pub retry_delay: Duration,
}

impl Default for SnmpClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: SNMP_REQUEST_TIMEOUT,
            retries: 1,
            retry_delay: Duration::from_millis(200),
        }
    }
}

/// Establish an authenticated SNMP connection to a device.
pub async fn connect(
    address: SocketAddr,
    credentials: &SnmpCredentials,
    config: SnmpClientConfig,
) -> Result<UdpClient, String> {
    if config.request_timeout.is_zero() {
        return Err("SNMP request timeout must be greater than zero".into());
    }

    let auth = credentials.to_auth()?;

    let retry = Retry::fixed(config.retries, config.retry_delay)
        .map_err(|error| format!("Invalid SNMP retry configuration: {error}"))?;

    Client::builder(address, auth)
        .request_timeout(config.request_timeout)
        .retry(retry)
        .strict_source(true)
        .connect()
        .await
        .map_err(|error| format!("SNMP connection failed: {error}"))
}
