use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCategory {
    Router,
    Switch,
    WirelessAccessPoint,
    Server,
    Workstation,
    Printer,
    Firewall,
    IoTDevice,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ClassificationSignals {
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub is_default_gateway: bool,
    pub open_ports: Vec<u16>,
    pub snmp_detected: bool,
    pub lldp_detected: bool,
    pub endpoint_agent_detected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceClassification {
    pub category: DeviceCategory,

    /// Heuristic confidence score, not a statistically calibrated probability.
    pub confidence: f32,

    /// Human-readable signals that contributed to the classification.
    pub evidence: Vec<String>,
}

struct Candidate {
    category: DeviceCategory,
    score: u32,
    evidence: Vec<String>,
}

impl Candidate {
    fn new(category: DeviceCategory) -> Self {
        Self {
            category,
            score: 0,
            evidence: Vec::new(),
        }
    }

    fn add(&mut self, points: u32, reason: impl Into<String>) {
        self.score = self.score.saturating_add(points);
        self.evidence.push(reason.into());
    }
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

/// Classifies a discovered device using the available network signals.
///
/// This is a deterministic, rule-based classifier. Manufacturer information
/// is supporting evidence only; it cannot classify a device by itself.
/// SNMP, LLDP and endpoint-agent evidence is only used when a collector
/// actually supplies those signals.
pub fn classify_device(signals: &ClassificationSignals) -> DeviceClassification {
    let hostname = signals
        .hostname
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let manufacturer = signals
        .manufacturer
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let has_port = |port: u16| signals.open_ports.contains(&port);

    let mut candidates = vec![
        Candidate::new(DeviceCategory::Router),
        Candidate::new(DeviceCategory::Switch),
        Candidate::new(DeviceCategory::WirelessAccessPoint),
        Candidate::new(DeviceCategory::Server),
        Candidate::new(DeviceCategory::Workstation),
        Candidate::new(DeviceCategory::Printer),
        Candidate::new(DeviceCategory::Firewall),
        Candidate::new(DeviceCategory::IoTDevice),
    ];

    // ROUTER / GATEWAY
    if signals.is_default_gateway {
        candidates[0].add(100, "Confirmed as the host's default network gateway");
    }

    if contains_any(
        &hostname,
        &["router", "gateway", "gw-", "openwrt", "opnsense", "pfsense"],
    ) {
        candidates[0].add(45, "Hostname identifies router or gateway equipment");
    }

    if has_port(53) && (has_port(67) || has_port(68)) {
        candidates[0].add(35, "DNS and DHCP services are both exposed");
    }

    // SWITCH
    if signals.lldp_detected {
        candidates[1].add(45, "LLDP neighbor information identifies network equipment");
    }

    if signals.snmp_detected {
        candidates[1].add(20, "SNMP management service detected");
    }

    if contains_any(&hostname, &["switch", "sw-", "core-sw", "access-sw"]) {
        candidates[1].add(40, "Hostname identifies switch equipment");
    }

    // WIRELESS ACCESS POINT
    if contains_any(
        &hostname,
        &[
            "access-point",
            "accesspoint",
            "wireless-ap",
            "wifi-ap",
            "wlan",
            "wap-",
        ],
    ) {
        candidates[2].add(50, "Hostname identifies wireless access-point equipment");
    }

    if has_port(5246) || has_port(5247) {
        candidates[2].add(35, "CAPWAP control or data port detected");
    }

    if signals.lldp_detected && signals.snmp_detected {
        candidates[2].add(10, "Both LLDP and SNMP indicate managed network equipment");
    }

    // SERVER
    if contains_any(
        &hostname,
        &["server", "srv-", "database", "db-", "nas", "storage"],
    ) {
        candidates[3].add(45, "Hostname identifies server or storage equipment");
    }

    let database_ports = [3306, 5432, 6379, 27017, 1433, 1521];
    let database_count = database_ports
        .iter()
        .filter(|port| has_port(**port))
        .count();

    if database_count > 0 {
        candidates[3].add(
            25 + (database_count.saturating_sub(1) as u32 * 10),
            "Database service port(s) detected",
        );
    }

    let mail_ports = [25, 110, 143, 465, 587, 993, 995];
    let mail_count = mail_ports.iter().filter(|port| has_port(**port)).count();

    if mail_count >= 2 {
        candidates[3].add(25, "Multiple mail-server service ports detected");
    }

    if has_port(445) && (has_port(3306) || has_port(5432) || has_port(6379)) {
        candidates[3].add(20, "File-sharing and database services detected together");
    }

    // WORKSTATION / ENDPOINT
    if contains_any(
        &hostname,
        &[
            "desktop",
            "workstation",
            "laptop",
            "pc-",
            "computer",
            "notebook",
        ],
    ) {
        candidates[4].add(45, "Hostname identifies a desktop or laptop endpoint");
    }

    if signals.endpoint_agent_detected {
        candidates[4].add(60, "Authenticated Netquorra endpoint agent detected");
    }

    if has_port(3389) {
        candidates[4].add(25, "Remote Desktop service detected");
    }

    if has_port(445) && !has_port(3306) && !has_port(5432) && !has_port(6379) {
        candidates[4].add(10, "SMB file-sharing service detected");
    }

    // PRINTER
    if contains_any(
        &hostname,
        &["printer", "print", "laserjet", "officejet", "deskjet"],
    ) {
        candidates[5].add(60, "Hostname identifies printer equipment");
    }

    let printer_ports = [515, 631, 9100];
    let printer_count = printer_ports.iter().filter(|port| has_port(**port)).count();

    if printer_count >= 2 {
        candidates[5].add(55, "Multiple printer-specific services detected");
    } else if printer_count == 1 {
        candidates[5].add(40, "A printer-specific service port detected");
    }

    // FIREWALL
    if contains_any(
        &hostname,
        &["firewall", "fortigate", "pfsense", "opnsense", "sophos-xg"],
    ) {
        candidates[6].add(
            55,
            "Hostname identifies firewall or security-gateway equipment",
        );
    }

    // IoT / EMBEDDED DEVICE
    if contains_any(
        &hostname,
        &[
            "iot",
            "sensor",
            "camera",
            "smart-",
            "embedded",
            "thermostat",
        ],
    ) {
        candidates[7].add(45, "Hostname identifies an IoT or embedded device");
    }

    if [1883, 5683, 8883, 554].iter().any(|port| has_port(*port)) {
        candidates[7].add(35, "IoT, messaging or camera-streaming service detected");
    }

    // Manufacturer is never sufficient by itself. It can only reinforce
    // a candidate that already has independent hostname/port/protocol evidence.
    if !manufacturer.is_empty() {
        let network_vendor = contains_any(
            &manufacturer,
            &[
                "cisco",
                "juniper",
                "aruba",
                "hewlett packard",
                "hpe",
                "hewlett-packard",
                "ubiquiti",
                "mikrotik",
                "tp-link",
                "tplink",
                "fortinet",
                "huawei",
                "zyxel",
                "netgear",
            ],
        );

        for candidate in &mut candidates {
            if candidate.score == 0 {
                continue;
            }

            match candidate.category {
                DeviceCategory::Router
                | DeviceCategory::Switch
                | DeviceCategory::WirelessAccessPoint
                | DeviceCategory::Firewall
                    if network_vendor =>
                {
                    candidate.add(
                        8,
                        "Network-equipment manufacturer supports this classification",
                    );
                }
                _ => {
                    candidate.add(
                        3,
                        "Manufacturer information provides limited supporting evidence",
                    );
                }
            }
        }
    }

    candidates.sort_by(|a, b| b.score.cmp(&a.score));

    let Some(best) = candidates.first() else {
        return unknown_classification();
    };

    let second_score = candidates.get(1).map_or(0, |candidate| candidate.score);
    let margin = best.score.saturating_sub(second_score);

    // Require meaningful evidence and a clear lead. If a competing category
    // has substantial independent evidence, do not force a classification.
    // This catches mixed signals such as printer-specific ports alongside
    // database-server ports and conflicting hostnames.
    let competing_evidence_is_strong =
        second_score >= 40 && (second_score as f32 / best.score.max(1) as f32) >= 0.65;

    if best.score < 40 || margin < 10 || competing_evidence_is_strong {
        return unknown_classification();
    }

    // A transparent heuristic indicator based on score and separation from
    // the runner-up. This is not a machine-learned probability.
    let score_component = (best.score.min(100) as f32 / 100.0) * 0.75;
    let margin_component = (margin.min(40) as f32 / 40.0) * 0.15;
    let evidence_component = (best.evidence.len().min(3) as f32 / 3.0) * 0.10;
    let confidence = (score_component + margin_component + evidence_component).clamp(0.40, 0.99);

    DeviceClassification {
        category: best.category.clone(),
        confidence,
        evidence: best.evidence.clone(),
    }
}

fn unknown_classification() -> DeviceClassification {
    DeviceClassification {
        category: DeviceCategory::Unknown,
        confidence: 0.0,
        evidence: vec!["Insufficient or ambiguous identification evidence".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_default_gateway_as_router() {
        let signals = ClassificationSignals {
            is_default_gateway: true,
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Router);
        assert!(result.confidence >= 0.75);
        assert!(result
            .evidence
            .iter()
            .any(|item| item.contains("default network gateway")));
    }

    #[test]
    fn identifies_switch_using_lldp_and_snmp() {
        let signals = ClassificationSignals {
            hostname: Some("core-switch".to_string()),
            snmp_detected: true,
            lldp_detected: true,
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Switch);
    }

    #[test]
    fn identifies_access_point_from_hostname() {
        let signals = ClassificationSignals {
            hostname: Some("office-wireless-ap".to_string()),
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::WirelessAccessPoint);
    }

    #[test]
    fn identifies_printer_using_multiple_print_services() {
        let signals = ClassificationSignals {
            hostname: Some("office-printer".to_string()),
            open_ports: vec![631, 9100],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Printer);
    }

    #[test]
    fn identifies_printer_from_a_printer_specific_port() {
        let signals = ClassificationSignals {
            open_ports: vec![9100],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Printer);
    }

    #[test]
    fn identifies_server_from_database_services() {
        let signals = ClassificationSignals {
            hostname: Some("database-server".to_string()),
            open_ports: vec![22, 3306, 5432],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Server);
    }

    #[test]
    fn identifies_workstation_using_endpoint_agent() {
        let signals = ClassificationSignals {
            hostname: Some("office-pc".to_string()),
            endpoint_agent_detected: true,
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Workstation);
    }

    #[test]
    fn identifies_iot_device_from_camera_services() {
        let signals = ClassificationSignals {
            hostname: Some("office-camera".to_string()),
            open_ports: vec![554],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::IoTDevice);
    }

    #[test]
    fn manufacturer_alone_does_not_classify_device() {
        let signals = ClassificationSignals {
            manufacturer: Some("HUAWEI TECHNOLOGIES CO., LTD".to_string()),
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Unknown);
    }

    #[test]
    fn generic_ssh_http_https_device_remains_unknown() {
        let signals = ClassificationSignals {
            open_ports: vec![22, 80, 443],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Unknown);
    }

    #[test]
    fn locally_administered_mac_is_not_a_classification_signal() {
        let signals = ClassificationSignals {
            manufacturer: None,
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Unknown);
    }

    #[test]
    fn unknown_device_remains_unknown() {
        let result = classify_device(&ClassificationSignals::default());

        assert_eq!(result.category, DeviceCategory::Unknown);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn conflicting_signals_remain_unknown() {
        let signals = ClassificationSignals {
            hostname: Some("printer-server".to_string()),
            open_ports: vec![9100, 3306, 5432],
            ..Default::default()
        };

        let result = classify_device(&signals);

        assert_eq!(result.category, DeviceCategory::Unknown);
    }
}
