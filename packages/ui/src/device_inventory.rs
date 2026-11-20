use dioxus::prelude::*;

#[derive(Clone, PartialEq)]
struct Device {
    name: &'static str,
    hostname: &'static str,
    ip: &'static str,
    mac: &'static str,
    device_type: &'static str,
    manufacturer: &'static str,
    model: &'static str,
    os: &'static str,
    status: &'static str,
    last_seen: &'static str,
}

fn sample_devices() -> Vec<Device> {
    vec![
        Device {
            name: "Core Router",
            hostname: "router-core-01",
            ip: "192.168.1.1",
            mac: "A4:5E:60:12:34:01",
            device_type: "Router",
            manufacturer: "MikroTik",
            model: "RB4011",
            os: "RouterOS",
            status: "Online",
            last_seen: "Just now",
        },
        Device {
            name: "Main Switch",
            hostname: "switch-main-01",
            ip: "192.168.1.2",
            mac: "A4:5E:60:12:34:02",
            device_type: "Switch",
            manufacturer: "TP-Link",
            model: "TL-SG3428",
            os: "Switch OS",
            status: "Online",
            last_seen: "Just now",
        },
        Device {
            name: "Access Point Upstairs",
            hostname: "ap-upstairs-01",
            ip: "192.168.1.10",
            mac: "A4:5E:60:12:34:10",
            device_type: "Access Point",
            manufacturer: "Ubiquiti",
            model: "UniFi U6",
            os: "UniFi OS",
            status: "Online",
            last_seen: "2 minutes ago",
        },
        Device {
            name: "File Server",
            hostname: "server-file-01",
            ip: "192.168.1.20",
            mac: "A4:5E:60:12:34:20",
            device_type: "Server",
            manufacturer: "Dell",
            model: "PowerEdge R740",
            os: "Ubuntu Server",
            status: "Warning",
            last_seen: "1 minute ago",
        },
        Device {
            name: "Office Workstation",
            hostname: "office-pc-01",
            ip: "192.168.1.30",
            mac: "A4:5E:60:12:34:30",
            device_type: "Workstation",
            manufacturer: "HP",
            model: "EliteDesk",
            os: "Windows 11",
            status: "Offline",
            last_seen: "35 minutes ago",
        },
        Device {
            name: "Network Printer",
            hostname: "printer-office-01",
            ip: "192.168.1.40",
            mac: "A4:5E:60:12:34:40",
            device_type: "Printer",
            manufacturer: "HP",
            model: "LaserJet Pro",
            os: "Embedded",
            status: "Online",
            last_seen: "Just now",
        },
    ]
}

#[component]
pub fn DeviceInventory() -> Element {
    let devices = use_signal(sample_devices);
    let mut search = use_signal(String::new);
    let mut status_filter = use_signal(|| "All".to_string());
    let mut type_filter = use_signal(|| "All".to_string());
    let mut selected_device = use_signal(|| None::<usize>);

    let query = search().to_lowercase();

    let filtered: Vec<(usize, Device)> = devices()
        .into_iter()
        .enumerate()
        .filter(|(_, device)| {
            let matches_search = device.name.to_lowercase().contains(&query)
                || device.hostname.to_lowercase().contains(&query)
                || device.ip.to_lowercase().contains(&query);

            let matches_status = status_filter() == "All" || device.status == status_filter();

            let matches_type = type_filter() == "All" || device.device_type == type_filter();

            matches_search && matches_status && matches_type
        })
        .collect();

    let online = devices().iter().filter(|d| d.status == "Online").count();
    let offline = devices().iter().filter(|d| d.status == "Offline").count();
    let warning = devices().iter().filter(|d| d.status == "Warning").count();

    rsx! {
        div { class: "inventory-page",

            div { class: "inventory-heading",
                div {
                    span { class: "eyebrow", "NETWORK MANAGEMENT" }
                    h1 { "Device Inventory" }
                    p { "Discover, monitor and manage connected network devices." }
                }
                button { class: "refresh-button", "↻ Refresh inventory" }
            }

            div { class: "inventory-stats",
                div { class: "inventory-stat",
                    span { "TOTAL DEVICES" }
                    strong { "{devices().len()}" }
                }
                div { class: "inventory-stat",
                    span { "ONLINE" }
                    strong { class: "stat-green", "{online}" }
                }
                div { class: "inventory-stat",
                    span { "OFFLINE" }
                    strong { class: "stat-red", "{offline}" }
                }
                div { class: "inventory-stat",
                    span { "WARNING" }
                    strong { class: "stat-yellow", "{warning}" }
                }
            }

            div { class: "inventory-panel",

                div { class: "inventory-toolbar",
                    input {
                        class: "inventory-search",
                        placeholder: "Search device, hostname or IP address...",
                        value: "{search}",
                        oninput: move |event| search.set(event.value())
                    }

                    select {
                        class: "inventory-select",
                        value: "{status_filter}",
                        onchange: move |event| status_filter.set(event.value()),
                        option { value: "All", "All statuses" }
                        option { value: "Online", "Online" }
                        option { value: "Offline", "Offline" }
                        option { value: "Warning", "Warning" }
                    }

                    select {
                        class: "inventory-select",
                        value: "{type_filter}",
                        onchange: move |event| type_filter.set(event.value()),
                        option { value: "All", "All device types" }
                        option { value: "Router", "Router" }
                        option { value: "Switch", "Switch" }
                        option { value: "Access Point", "Access Point" }
                        option { value: "Server", "Server" }
                        option { value: "Workstation", "Workstation" }
                        option { value: "Printer", "Printer" }
                    }
                }

                div { class: "inventory-table-wrap",
                    table { class: "inventory-table",
                        thead {
                            tr {
                                th { "DEVICE" }
                                th { "IP ADDRESS" }
                                th { "TYPE" }
                                th { "MANUFACTURER" }
                                th { "STATUS" }
                                th { "LAST SEEN" }
                                th { "ACTION" }
                            }
                        }

                        tbody {
                            for (index, device) in filtered.iter() {
                                tr {
                                    td {
                                        strong { "{device.name}" }
                                        small { "{device.hostname}" }
                                    }
                                    td { "{device.ip}" }
                                    td { "{device.device_type}" }
                                    td { "{device.manufacturer}" }
                                    td {
                                        span {
                                            class: match device.status {
                                                "Online" => "device-status online",
                                                "Offline" => "device-status offline",
                                                _ => "device-status warning"
                                            },
                                            "● {device.status}"
                                        }
                                    }
                                    td { "{device.last_seen}" }
                                    td {
                                        button {
                                            class: "view-device",
                                            onclick: {
                                                let index = *index;
                                                move |_| selected_device.set(Some(index))
                                            },
                                            "View"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if filtered.is_empty() {
                    div { class: "inventory-empty",
                        "No devices match your search or filters."
                    }
                }

                div { class: "inventory-footer",
                    "Showing {filtered.len()} of {devices().len()} devices"
                }
            }

            if let Some(index) = selected_device() {
                if let Some(device) = devices().get(index) {
                    div {
                        class: "device-overlay",
                        onclick: move |_| selected_device.set(None),

                        div {
                            class: "device-detail",
                            onclick: move |event| event.stop_propagation(),

                            div { class: "device-detail-heading",
                                div {
                                    span { class: "eyebrow", "DEVICE DETAILS" }
                                    h2 { "{device.name}" }
                                }
                                button {
                                    class: "close-detail",
                                    onclick: move |_| selected_device.set(None),
                                    "×"
                                }
                            }

                            div {
                                class: match device.status {
                                    "Online" => "detail-status online",
                                    "Warning" => "detail-status warning",
                                    "Offline" => "detail-status offline",
                                    _ => "detail-status"
                                },
                                span { class: "detail-status-dot" }
                                "{device.status}"
                            }

                            div { class: "detail-grid",
                                div { span { "Hostname" } strong { "{device.hostname}" } }
                                div { span { "IP Address" } strong { "{device.ip}" } }
                                div { span { "MAC Address" } strong { "{device.mac}" } }
                                div { span { "Device Type" } strong { "{device.device_type}" } }
                                div { span { "Manufacturer" } strong { "{device.manufacturer}" } }
                                div { span { "Model" } strong { "{device.model}" } }
                                div { span { "Operating System" } strong { "{device.os}" } }
                                div { span { "Last Seen" } strong { "{device.last_seen}" } }
                            }
                        }
                    }
                }
            }
        }
    }
}
