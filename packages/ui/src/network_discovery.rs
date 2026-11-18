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
struct ScanResponse {
    status: String,
    network: String,
    discovered_count: usize,
    discovered_devices: Vec<String>,
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
    let mut network_range =
        use_signal(|| "192.168.100.0/24".to_string());

    let mut scanning = use_signal(|| false);
    let mut error_message = use_signal(|| None::<String>);
    let mut scan_result = use_signal(|| None::<ScanResponse>);

    let current_result = scan_result();

    rsx! {
        section { class: "discovery-page",

            div { class: "discovery-heading",
                div {
                    span { class: "eyebrow", "NETWORK OPERATIONS" }
                    h1 { "Network Discovery" }
                    p { "Discover and identify devices connected to your network." }
                }

                span { class: "discovery-status",
                    span { class: "discovery-status-dot" }
                    "Local Network Agent"
                }
            }

            div { class: "discovery-panel",
                div { class: "discovery-panel-heading",
                    div {
                        h3 { "Scan Configuration" }
                        p { "Configure the IPv4 network you want to discover." }
                    }
                    span { class: "discovery-badge", "IPv4" }
                }

                div { class: "discovery-form",
                    div { class: "discovery-input-group",
                        label { "Network range (CIDR)" }

                        input {
                            class: "discovery-input",
                            placeholder: "192.168.100.0/24",
                            value: "{network_range}",
                            disabled: scanning(),
                            oninput: move |event| {
                                network_range.set(event.value());
                            }
                        }

                        small { "Example: 192.168.100.0/24" }
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
                                    ).map_err(|_| {
                                        "Agent token is missing. Start the desktop application using scripts/dev-desktop.sh.".to_string()
                                    })?;

                                    let client = reqwest::Client::new();

                                    let response = client
                                        .post("http://127.0.0.1:47821/v1/discovery/scan")
                                        .bearer_auth(token)
                                        .json(&ScanRequest { cidr })
                                        .send()
                                        .await
                                        .map_err(|error| {
                                            format!("Cannot connect to Network Agent: {error}")
                                        })?;

                                    let response = response
                                        .error_for_status()
                                        .map_err(|error| error.to_string())?;

                                    response
                                        .json::<ScanResponse>()
                                        .await
                                        .map_err(|error| {
                                            format!("Invalid agent response: {error}")
                                        })
                                }.await;

                                match result {
                                    Ok(data) => scan_result.set(Some(data)),
                                    Err(message) => error_message.set(Some(message)),
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

                if let Some(message) = error_message() {
                    div { class: "discovery-error",
                        strong { "Discovery failed" }
                        p { "{message}" }
                    }
                } else {
                    div { class: "discovery-notice",
                        span { "ⓘ" }
                        div {
                            strong { "Network Agent connection" }
                            p {
                                "Scans are processed by your local authenticated Rust Network Agent."
                            }
                        }
                    }
                }
            }

            div { class: "discovery-metrics",
                div { class: "discovery-metric-card",
                    span { "DISCOVERED DEVICES" }
                    strong {
                        "{current_result.as_ref().map_or(0, |data| data.discovered_count)}"
                    }
                    small { "Devices responding to ICMP" }
                }

                div { class: "discovery-metric-card",
                    span { "ONLINE DEVICES" }
                    strong {
                        "{current_result.as_ref().map_or(0, |data| data.discovered_count)}"
                    }
                    small { "Responsive devices" }
                }

                div { class: "discovery-metric-card",
                    span { "NETWORK RANGE" }
                    strong { "IPv4" }
                    small {
                        "{current_result.as_ref().map_or_else(|| network_range(), |data| data.network.clone())}"
                    }
                }
            }

            div { class: "discovery-panel discovery-results",
                div { class: "discovery-panel-heading",
                    div {
                        h3 { "Discovery Results" }
                        p { "Devices identified during network discovery." }
                    }

                    span { class: "discovery-badge",
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
                        div { class: "discovery-empty",
                            div { class: "discovery-empty-icon", "⌕" }
                            h3 { "No responsive devices found" }
                            p {
                                "The scan completed, but no devices responded to ICMP."
                            }
                        }
                    } else {
                        div { class: "discovery-table-wrapper",
                            table { class: "discovery-table",
                                thead {
                                    tr {
                                        th { "IP ADDRESS" }
                                        th { "STATUS" }
                                        th { "DISCOVERY METHOD" }
                                    }
                                }

                                tbody {
                                    for ip in data.discovered_devices.iter() {
                                        tr {
                                            td { class: "discovery-ip", "{ip}" }
                                            td {
                                                span { class: "device-status online",
                                                    "Online"
                                                }
                                            }
                                            td { "ICMP" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    div { class: "discovery-empty",
                        div { class: "discovery-empty-icon", "⌕" }
                        h3 { "No devices discovered yet" }
                        p {
                            "Enter an authorised network range and start discovery."
                        }
                    }
                }
            }

            div { class: "discovery-info-grid",
                div { class: "discovery-info-card",
                    span { "01" }
                    h4 { "Network Scanning" }
                    p { "Identify responsive devices using ICMP discovery." }
                }

                div { class: "discovery-info-card",
                    span { "02" }
                    h4 { "Device Identification" }
                    p { "Collect IP addresses and progressively enrich device information." }
                }

                div { class: "discovery-info-card",
                    span { "03" }
                    h4 { "Inventory Integration" }
                    p { "Review discovered devices before adding them to Device Inventory." }
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[component]
fn NetworkDiscoveryWeb() -> Element {
    rsx! {
        section { class: "discovery-page",
            div { class: "discovery-heading",
                div {
                    span { class: "eyebrow", "NETWORK OPERATIONS" }
                    h1 { "Network Discovery" }
                    p { "Discover and identify devices connected to your network." }
                }
            }

            div { class: "discovery-panel",
                h3 { "Desktop Network Agent required" }
                p {
                    "Local network discovery is currently available through the Netquorra desktop application."
                }
            }
        }
    }
}