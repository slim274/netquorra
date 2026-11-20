use async_snmp::{oid, Oid, UdpClient};

/// Standard SNMP system information.
#[derive(Debug, Clone, Default)]
pub struct SnmpSystemInfo {
    pub description: Option<String>,
    pub object_id: Option<String>,
    pub uptime: Option<String>,
    pub name: Option<String>,
    pub contact: Option<String>,
    pub location: Option<String>,
}

/// Retrieve one optional SNMP value.
///
/// A failed request or unsupported OID returns None rather than
/// preventing collection of the remaining system information.
async fn get_value(client: &UdpClient, object_id: &Oid) -> Option<String> {
    let response = client.get(object_id).await.ok()?;

    response.single().map(|binding| {
        binding
            .value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| binding.value.to_string())
    })
}

/// Retrieve standard MIB-II system information.
pub async fn get_system_info(client: &UdpClient) -> Result<SnmpSystemInfo, String> {
    let description_oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
    let object_id_oid = oid!(1, 3, 6, 1, 2, 1, 1, 2, 0);
    let uptime_oid = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
    let name_oid = oid!(1, 3, 6, 1, 2, 1, 1, 5, 0);
    let contact_oid = oid!(1, 3, 6, 1, 2, 1, 1, 4, 0);
    let location_oid = oid!(1, 3, 6, 1, 2, 1, 1, 6, 0);

    let (description, object_id, uptime, name, contact, location) = tokio::join!(
        get_value(client, &description_oid),
        get_value(client, &object_id_oid),
        get_value(client, &uptime_oid),
        get_value(client, &name_oid),
        get_value(client, &contact_oid),
        get_value(client, &location_oid),
    );

    Ok(SnmpSystemInfo {
        description,
        object_id,
        uptime,
        name,
        contact,
        location,
    })
}
