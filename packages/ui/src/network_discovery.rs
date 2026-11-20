use dioxus::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize)]
struct ScanRequest {
    cidr: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Deserialize, PartialEq)]
struct DiscoveredDevice {
    ip_address: String,
    mac_address: Option<String>,
    hostname: Option<String>,
    manufacturer: Option<String>,
    mac_address_type: Option<String>,
    status: String,

    // TCP service detection
    open_ports: Vec<u16>,
    detected_services: Vec<DetectedService>,

    // Device classification
    device_category: String,
    classification_confidence: f32,
    classification_evidence: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Deserialize, PartialEq)]
struct DetectedService {
    port: u16,
    name: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ScanResponse {
    status: String,
    network: String,
    discovered_count: usize,
    discovered_devices: Vec<DiscoveredDevice>,
}

#[component]
pub fn NetworkDiscovery() -> Element {
    #[cfg(not(target_arch = "wasm32"))]
    {
        return NetworkDiscoveryDesktop();
    }

    #[cfg(target_arch = "wasm32")]
    {
        return NetworkDiscoveryWeb();
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[component]
fn NetworkDiscoveryDesktop() -> Element {
    let mut network_range = use_signal(|| "192.168.100.0/24".to_string());

    let scanning = use_signal(|| false);
    let error_message = use_signal(|| None::<String>);
    let scan_result = use_signal(|| None::<ScanResponse>);

    let current_result = scan_result();

    let online_count = current_result.as_ref().map_or(0, |data| {
        data.discovered_devices
            .iter()
            .filter(|device| device.status == "online")
            .count()
    });

    let identified_count = current_result.as_ref().map_or(0, |data| {
        data.discovered_devices
            .iter()
            .filter(|device| device.manufacturer.is_some())
            .count()
    });

    let classified_count = current_result.as_ref().map_or(0, |data| {
        data.discovered_devices
            .iter()
            .filter(|device| device.device_category != "unknown")
            .count()
    });

    let total_open_ports = current_result.as_ref().map_or(0, |data| {
        data.discovered_devices
            .iter()
            .map(|device| device.open_ports.len())
            .sum()
    });

    let detected_services_count = current_result.as_ref().map_or(0, |data| {
        data.discovered_devices
            .iter()
            .map(|device| device.detected_services.len())
            .sum()
    });

    rsx! {
        section {
            class: "discovery-page",

            // PAGE HEADER
            div {
                class: "discovery-heading",

                div {
                    span {
                        class: "eyebrow",
                        "NETWORK OPERATIONS"
                    }

                    h1 { "Network Discovery" }

                    p {
                        "Discover, identify and classify devices connected to your network."
                    }
                }

                span {
                    class: "discovery-status",
                    span {
                        class: "discovery-status-dot"
                    }
                    "Local Network Agent"
                }
            }

            // SCAN CONFIGURATION
            div {
                class: "discovery-panel",

                div {
                    class: "discovery-panel-heading",

                    div {
                        h3 { "Scan Configuration" }

                        p {
                            "Configure the IPv4 network you want to discover."
                        }
                    }

                    span {
                        class: "discovery-badge",
                        "IPv4"
                    }
                }

                div {
                    class: "discovery-form",

                    div {
                        class: "discovery-input-group",

                        label {
                            "Network range (CIDR)"
                        }

                        input {
                            class: "discovery-input",
                            placeholder: "192.168.100.0/24",
                            value: "{network_range}",
                            disabled: scanning(),

                            oninput: move |event| {
                                network_range.set(event.value());
                            }
                        }

                        small {
                            "Example: 192.168.100.0/24"
                        }
                    }

                    button {
                        class: "discovery-scan-button",
                        disabled: scanning() || network_range().trim().is_empty(),

                        onclick: move |_| {
                            let cidr = network_range().trim().to_string();

                            let mut scanning = scanning;
                            let mut error_message = error_message;
                            let mut scan_result = scan_result;

                            spawn(async move {
                                scanning.set(true);
                                error_message.set(None);
                                scan_result.set(None);

                                let result = async {
                                    let token = std::env::var(
                                        "NETQUORRA_AGENT_TOKEN"
                                    )
                                    .map_err(|_| {
                                        "Agent token is missing. Start the desktop application using scripts/dev-desktop.sh.".to_string()
                                    })?;

                                    let client = reqwest::Client::new();

                                    let response = client
                                        .post(
                                            "http://127.0.0.1:47821/v1/discovery/scan"
                                        )
                                        .bearer_auth(token)
                                        .json(&ScanRequest { cidr })
                                        .send()
                                        .await
                                        .map_err(|error| {
                                            format!(
                                                "Cannot connect to Network Agent: {error}"
                                            )
                                        })?;

                                    let response = response
                                        .error_for_status()
                                        .map_err(|error| error.to_string())?;

                                    response
                                        .json::<ScanResponse>()
                                        .await
                                        .map_err(|error| {
                                            format!(
                                                "Invalid agent response: {error}"
                                            )
                                        })
                                }
                                .await;

                                match result {
                                    Ok(data) => {
                                        scan_result.set(Some(data));
                                    }

                                    Err(message) => {
                                        error_message.set(Some(message));
                                    }
                                }

                                scanning.set(false);
                            });
                        },

                        if scanning() {
                            "◌  Scanning..."
                        } else {
                            "⌕  Start Discovery"
                        }
                    }
                }

                // ERROR / CONNECTION NOTICE
                if let Some(message) = error_message() {
                    div {
                        class: "discovery-error",

                        strong {
                            "Discovery failed"
                        }

                        p {
                            "{message}"
                        }
                    }
                } else {
                    div {
                        class: "discovery-notice",

                        span {
                            "ⓘ"
                        }

                        div {
                            strong {
                                "Network Agent connection"
                            }

                            p {
                                "Scans are processed by your local authenticated Rust Network Agent."
                            }
                        }
                    }
                }
            }

            // DISCOVERY METRICS
            div {
                class: "discovery-metrics",

                div {
                    class: "discovery-metric-card",

                    span {
                        "DISCOVERED DEVICES"
                    }

                    strong {
                        "{current_result.as_ref().map_or(0, |data| data.discovered_count)}"
                    }

                    small {
                        "Devices responding to ICMP"
                    }
                }

                div {
                    class: "discovery-metric-card",
                    span { "OPEN TCP PORTS" }
                    strong { "{total_open_ports}" }
                    small { "Detected listening ports" }
                }

                div {
                    class: "discovery-metric-card",
                    span { "DETECTED SERVICES" }
                    strong { "{detected_services_count}" }
                    small { "Identified TCP services" }
                }

                div {
                    class: "discovery-metric-card",

                    span {
                        "ONLINE DEVICES"
                    }

                    strong {
                        "{online_count}"
                    }

                    small {
                        "Responsive devices"
                    }
                }

                div {
                    class: "discovery-metric-card",

                    span {
                        "IDENTIFIED MANUFACTURERS"
                    }

                    strong {
                        "{identified_count}"
                    }

                    small {
                        "Matched against IEEE registry"
                    }
                }

                div {
                    class: "discovery-metric-card",

                    span {
                        "CLASSIFIED DEVICES"
                    }

                    strong {
                        "{classified_count}"
                    }

                    small {
                        "Devices with identified categories"
                    }
                }
            }

            // DISCOVERY RESULTS
            div {
                class: "discovery-panel discovery-results",

                div {
                    class: "discovery-panel-heading",

                    div {
                        h3 {
                            "Discovery Results"
                        }

                        p {
                            "Devices identified and classified during network discovery."
                        }
                    }

                    span {
                        class: "discovery-badge",

                        if scanning() {
                            "Scanning"
                        } else if current_result.is_some() {
                            "Scan completed"
                        } else {
                            "No scan yet"
                        }
                    }
                }

                if let Some(data) = current_result {

                    if data.discovered_devices.is_empty() {
                        div {
                            class: "discovery-empty",

                            div {
                                class: "discovery-empty-icon",
                                "⌕"
                            }

                            h3 {
                                "No responsive devices found"
                            }

                            p {
                                "The scan completed, but no devices responded to ICMP."
                            }
                        }
                    } else {

                        div {
                            class: "discovery-table-wrapper",

                            table {
                                class: "discovery-table",

                                thead {
                                    tr {
                                        th { "IP ADDRESS" }
                                        th { "HOSTNAME" }
                                        th { "MAC ADDRESS" }
                                        th { "MANUFACTURER" }
                                        th { "MAC TYPE" }
                                        th { "DEVICE CATEGORY" }
                                        th { "OPEN PORTS" }
                                        th { "DETECTED SERVICES" }
                                        th { "CONFIDENCE" }
                                        th { "CLASSIFICATION EVIDENCE" }
                                        th { "STATUS" }
                                    }
                                }

                                tbody {
                                    for device in data.discovered_devices.iter() {

                                        {
                                            let category = device
                                                .device_category
                                                .replace('_', " ");

                                            let category_class = format!(
                                                "device-category {}",
                                                device.device_category
                                            );

                                            let confidence = format!(
                                                "{:.0}%",
                                                device.classification_confidence * 100.0
                                            );

                                            let evidence = if device.classification_evidence.is_empty() {
                                                "Insufficient evidence".to_string()
                                            } else {
                                                device.classification_evidence.join(", ")
                                            };

                                            let mac_type_display = device
                                                .mac_address_type
                                                .as_deref()
                                                .map(|value| value.replace('_', " "));

                                            let open_ports_display = if device.open_ports.is_empty() {
                                                "None detected".to_string()
                                            } else {
                                                device.open_ports
                                                    .iter()
                                                    .map(|port| port.to_string())
                                                    .collect::<Vec<_>>()
                                                    .join(", ")
                                            };

                                            rsx! {
                                                tr {

                                                    // IP ADDRESS
                                                    td {
                                                        class: "discovery-ip",
                                                        "{device.ip_address}"
                                                    }

                                                    // HOSTNAME
                                                    td {
                                                        if let Some(hostname) = &device.hostname {
                                                            "{hostname}"
                                                        } else {
                                                            span {
                                                                class: "device-unknown",
                                                                "Unknown"
                                                            }
                                                        }
                                                    }

                                                    // MAC ADDRESS
                                                    td {
                                                        class: "discovery-mac",

                                                        if let Some(mac) = &device.mac_address {
                                                            "{mac}"
                                                        } else {
                                                            span {
                                                                class: "device-unknown",
                                                                "Unavailable"
                                                            }
                                                        }
                                                    }

                                                    // MANUFACTURER
                                                    td {
                                                        if let Some(manufacturer) = &device.manufacturer {
                                                            "{manufacturer}"
                                                        } else {
                                                            span {
                                                                class: "device-unknown",
                                                                "Unknown"
                                                            }
                                                        }
                                                    }

                                                    // MAC ADDRESS TYPE
                                                    td {
                                                        if let Some(mac_type) = &mac_type_display {
                                                            span {
                                                                class: "discovery-mac-type",
                                                                "{mac_type}"
                                                            }
                                                        } else {
                                                            span {
                                                                class: "device-unknown",
                                                                "Unknown"
                                                            }
                                                        }
                                                    }

                                                    // DEVICE CATEGORY
                                                    td {
                                                        span {
                                                            class: "{category_class}",
                                                            "{category}"
                                                        }
                                                    }

                                                    // OPEN TCP PORTS
                                                    td {
                                                        if device.open_ports.is_empty() {
                                                            span {
                                                                class: "device-unknown",
                                                                "None detected"
                                                            }
                                                        } else {
                                                            span {
                                                                class: "discovery-mac-type",
                                                                "{open_ports_display}"
                                                            }
                                                        }
                                                    }

                                                    // DETECTED SERVICES
                                                    td {
                                                        if device.detected_services.is_empty() {
                                                            span {
                                                                class: "device-unknown",
                                                                "None detected"
                                                            }
                                                        } else {
                                                            div {
                                                                class: "detected-services",
                                                                for service in device.detected_services.iter() {
                                                                    span {
                                                                        class: "service-badge",
                                                                        "{service.name} ({service.port})"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }

                                                    // CLASSIFICATION CONFIDENCE
                                                    td {
                                                        span {
                                                            class: "classification-confidence",
                                                            "{confidence}"
                                                        }
                                                    }

                                                    // CLASSIFICATION EVIDENCE
                                                    td {
                                                        span {
                                                            class: "classification-evidence",
                                                            "{evidence}"
                                                        }
                                                    }

                                                    // STATUS
                                                    td {
                                                        span {
                                                            class: if device.status == "online" {
                                                                "device-status online"
                                                            } else {
                                                                "device-status offline"
                                                            },

                                                            "{device.status}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                } else {

                    div {
                        class: "discovery-empty",

                        div {
                            class: "discovery-empty-icon",
                            "⌕"
                        }

                        h3 {
                            "No devices discovered yet"
                        }

                        p {
                            "Enter an authorised network range and start discovery."
                        }
                    }
                }
            }

            // INFORMATION CARDS
            div {
                class: "discovery-info-grid",

                div {
                    class: "discovery-info-card",

                    span { "01" }

                    h4 {
                        "Network Scanning"
                    }

                    p {
                        "Identify responsive devices using ICMP discovery."
                    }
                }

                div {
                    class: "discovery-info-card",

                    span { "02" }

                    h4 {
                        "Device Identification"
                    }

                    p {
                        "Collect IP addresses, MAC addresses, hostnames and manufacturers."
                    }
                }

                div {
                    class: "discovery-info-card",

                    span { "03" }

                    h4 {
                        "Device Classification"
                    }

                    p {
                        "Classify discovered devices using available network signals and identification evidence."
                    }
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[component]
fn NetworkDiscoveryWeb() -> Element {
    rsx! {
        section {
            class: "discovery-page",

            div {
                class: "discovery-heading",

                div {
                    span {
                        class: "eyebrow",
                        "NETWORK OPERATIONS"
                    }

                    h1 {
                        "Network Discovery"
                    }

                    p {
                        "Discover and identify devices connected to your network."
                    }
                }
            }

            div {
                class: "discovery-panel",

                h3 {
                    "Desktop Network Agent required"
                }

                p {
                    "Local network discovery is currently available through the Netquorra desktop application."
                }
            }
        }
    }
}
