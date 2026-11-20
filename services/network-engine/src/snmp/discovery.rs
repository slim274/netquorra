use std::net::{IpAddr, SocketAddr};

use super::{
    client::{connect, SnmpClientConfig, SNMP_PORT},
    credentials::SnmpCredentials,
    interfaces::{get_interfaces, SnmpInterface},
    system::{get_system_info, SnmpSystemInfo},
};

/// Combined SNMP discovery information for a network device.
#[derive(Debug, Clone, Default)]
pub struct SnmpDiscoveryResult {
    pub detected: bool,
    pub version: Option<String>,
    pub system: SnmpSystemInfo,
    pub interfaces: Vec<SnmpInterface>,
}

/// Discover a device using SNMP.
///
/// A successful connection alone is not enough to mark a device as detected.
/// The device must also respond to its system description request.
pub async fn discover_device(
    ip: IpAddr,
    credentials: &SnmpCredentials,
    config: SnmpClientConfig,
) -> Result<SnmpDiscoveryResult, String> {
    let address = SocketAddr::new(ip, SNMP_PORT);

    let client = connect(address, credentials, config).await?;

    let system = get_system_info(&client).await?;

    if system.description.is_none() {
        return Err("SNMP agent did not return its system description".into());
    }

    let interfaces = get_interfaces(&client).await.unwrap_or_default();

    Ok(SnmpDiscoveryResult {
        detected: true,
        version: Some(credentials.version_name().to_string()),
        system,
        interfaces,
    })
}
