use std::collections::HashMap;

use async_snmp::{oid, Oid, UdpClient, Value, VarBind};

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SnmpInterface {
    pub index: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub mac_address: Option<String>,
    pub mtu: Option<u32>,
    pub speed_bps: Option<u64>,
    pub admin_status: Option<String>,
    pub oper_status: Option<String>,
    pub in_octets: Option<u64>,
    pub out_octets: Option<u64>,
    pub in_octets_64: Option<u64>,
    pub out_octets_64: Option<u64>,
}

fn interface_index(binding: &VarBind, base: &Oid) -> Option<u32> {
    let prefix = format!("{}.", base);
    binding.oid.to_string().strip_prefix(&prefix)?.parse().ok()
}

async fn walk_column(client: &UdpClient, base: Oid) -> Result<Vec<VarBind>, String> {
    let stream = client
        .bulk_walk(base, 25)
        .map_err(|error| format!("Could not start SNMP table walk: {error}"))?;

    stream
        .collect()
        .await
        .map_err(|error| format!("SNMP table walk failed: {error}"))
}

fn text_value(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

fn unsigned_value(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(value) if *value >= 0 => Some(*value as u64),
        Value::Counter32(value)
        | Value::Gauge32(value)
        | Value::UInteger32(value)
        | Value::TimeTicks(value) => Some(*value as u64),
        Value::Counter64(value) => Some(*value),
        _ => None,
    }
}

fn status_value(value: &Value) -> Option<String> {
    match value {
        Value::Integer(1) => Some("up".into()),
        Value::Integer(2) => Some("down".into()),
        Value::Integer(3) => Some("testing".into()),
        Value::Integer(value) => Some(format!("unknown({value})")),
        _ => None,
    }
}

fn mac_value(value: &Value) -> Option<String> {
    let bytes = value.as_bytes()?;

    if bytes.len() != 6 {
        return None;
    }

    Some(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Retrieve one IF-MIB column and associate values with interface indexes.
async fn collect_column(client: &UdpClient, base: Oid) -> Result<Vec<(u32, Value)>, String> {
    let bindings = walk_column(client, base.clone()).await?;

    Ok(bindings
        .into_iter()
        .filter_map(|binding| {
            let index = interface_index(&binding, &base)?;
            Some((index, binding.value))
        })
        .collect())
}

/// Discover network interfaces through the standard IF-MIB.
pub async fn get_interfaces(client: &UdpClient) -> Result<Vec<SnmpInterface>, String> {
    let descr_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2);
    let name_oid = oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1);
    let mtu_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 4);
    let speed_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5);
    let mac_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 6);
    let admin_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 7);
    let oper_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 8);
    let in_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10);
    let out_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 16);
    let in64_oid = oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6);
    let out64_oid = oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10);

    // ifDescr is the base table used to discover interface indexes.
    let descriptions = collect_column(client, descr_oid).await?;

    let mut interfaces: HashMap<u32, SnmpInterface> = descriptions
        .into_iter()
        .map(|(index, value)| {
            (
                index,
                SnmpInterface {
                    index,
                    description: text_value(&value),
                    ..Default::default()
                },
            )
        })
        .collect();

    // Optional columns: devices may not implement every IF-MIB object.
    let columns = [
        (name_oid, 0u8),
        (mtu_oid, 1),
        (speed_oid, 2),
        (mac_oid, 3),
        (admin_oid, 4),
        (oper_oid, 5),
        (in_oid, 6),
        (out_oid, 7),
        (in64_oid, 8),
        (out64_oid, 9),
    ];

    for (base, column) in columns {
        let values = match collect_column(client, base).await {
            Ok(values) => values,
            Err(_) => continue,
        };

        for (index, value) in values {
            let Some(interface) = interfaces.get_mut(&index) else {
                continue;
            };

            match column {
                0 => interface.name = text_value(&value),
                1 => interface.mtu = unsigned_value(&value).and_then(|v| u32::try_from(v).ok()),
                2 => interface.speed_bps = unsigned_value(&value),
                3 => interface.mac_address = mac_value(&value),
                4 => interface.admin_status = status_value(&value),
                5 => interface.oper_status = status_value(&value),
                6 => interface.in_octets = unsigned_value(&value),
                7 => interface.out_octets = unsigned_value(&value),
                8 => interface.in_octets_64 = unsigned_value(&value),
                9 => interface.out_octets_64 = unsigned_value(&value),
                _ => {}
            }
        }
    }

    let mut result: Vec<_> = interfaces.into_values().collect();

    // ifName is not implemented by every SNMP agent. Use ifDescr as a
    // readable fallback while preserving the original description field.
    for interface in &mut result {
        if interface.name.is_none() {
            interface.name = interface.description.clone();
        }
    }

    result.sort_by_key(|interface| interface.index);

    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::oid;

    #[test]
    fn parses_mac_address() {
        let value = Value::OctetString(vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E].into());

        assert_eq!(mac_value(&value), Some("00:1A:2B:3C:4D:5E".to_string()));
    }

    #[test]
    fn rejects_invalid_mac_length() {
        let value = Value::OctetString(vec![0x00, 0x1A, 0x2B].into());

        assert_eq!(mac_value(&value), None);
    }

    #[test]
    fn parses_interface_status() {
        assert_eq!(status_value(&Value::Integer(1)), Some("up".into()));
        assert_eq!(status_value(&Value::Integer(2)), Some("down".into()));
        assert_eq!(status_value(&Value::Integer(3)), Some("testing".into()));
    }

    #[test]
    fn parses_interface_counters() {
        assert_eq!(unsigned_value(&Value::Counter32(100)), Some(100));
        assert_eq!(
            unsigned_value(&Value::Counter64(5_000_000_000)),
            Some(5_000_000_000)
        );
        assert_eq!(unsigned_value(&Value::Gauge32(500)), Some(500));
    }

    #[test]
    fn rejects_negative_counter_values() {
        assert_eq!(unsigned_value(&Value::Integer(-1)), None);
    }

    #[test]
    fn extracts_interface_index() {
        let base = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2);
        let full = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 7);

        let binding = VarBind::new(full, Value::OctetString("Ethernet0".into()));

        assert_eq!(interface_index(&binding, &base), Some(7));
    }
}
