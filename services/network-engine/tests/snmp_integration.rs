use std::net::IpAddr;
use std::time::Duration;

use network_engine::snmp::{
    client::SnmpClientConfig, credentials::SnmpCredentials, discovery::discover_device,
};

#[tokio::test]
#[ignore = "requires the local SNMP test agent"]
async fn discovers_local_snmp_agent_and_interfaces() {
    let credentials = SnmpCredentials::V2c {
        community: "public".to_string(),
    };

    let config = SnmpClientConfig {
        request_timeout: Duration::from_secs(2),
        retries: 1,
        retry_delay: Duration::from_millis(200),
    };

    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let result = discover_device(ip, &credentials, config)
        .await
        .expect("SNMP discovery should succeed");

    assert!(result.detected);
    assert_eq!(result.version.as_deref(), Some("SNMPv2c"));
    assert!(result.system.description.is_some());

    assert_eq!(result.interfaces.len(), 2);

    assert!(result
        .interfaces
        .iter()
        .any(|interface| { interface.name.as_deref() == Some("lo") }));

    assert!(result
        .interfaces
        .iter()
        .any(|interface| { interface.name.as_deref() == Some("eth0") }));

    let eth0 = result
        .interfaces
        .iter()
        .find(|interface| interface.name.as_deref() == Some("eth0"))
        .expect("eth0 should exist");

    assert_eq!(eth0.mtu, Some(1500));
    assert_eq!(eth0.oper_status.as_deref(), Some("up"));
    assert!(eth0.mac_address.is_some());

    println!("SNMP version: {:?}", result.version);
    println!("System: {:#?}", result.system);
    println!("Interfaces: {:#?}", result.interfaces);
}
