use crate::{DeviceInventory, NetworkDiscovery};
use dioxus::prelude::*;

const DASHBOARD_CSS: Asset = asset!("/assets/dashboard.css");

#[component]
pub fn Dashboard() -> Element {
    let mut active_page = use_signal(|| "Overview".to_string());

    rsx! {
        document::Link {
            rel: "stylesheet",
            href: DASHBOARD_CSS
        }

        div { class: "app-shell",

            // Sidebar
            aside { class: "sidebar",
                div { class: "brand",
                    div { class: "brand-icon", "N" }
                    div {
                        h2 { "NETQUORRA" }
                        span { "NETWORK INTELLIGENCE" }
                    }
                }

                div { class: "nav-section",
                    span { class: "nav-label", "WORKSPACE" }

                    a {
                        class: if active_page() == "Overview" {
                            "nav-item active"
                        } else {
                            "nav-item"
                        },
                        onclick: move |_| active_page.set("Overview".to_string()),
                        "◈", "Overview"
                    }

                    a {
                        class: if active_page() == "Network Discovery" {
                            "nav-item active"
                        } else {
                            "nav-item"
                        },
                        onclick: move |_| active_page.set("Network Discovery".to_string()),
                        "⌘", "Network Discovery"
                    }

                    a {
                        class: if active_page() == "Devices" {
                            "nav-item active"
                        } else {
                            "nav-item"
                        },
                        onclick: move |_| active_page.set("Devices".to_string()),
                        "▣", "Devices"
                    }

                    a { class: "nav-item", "▤", "Infrastructure" }
                    a { class: "nav-item", "⇄", "WAN Management" }
                    a { class: "nav-item", "▥", "Traffic Analytics" }

                    span { class: "nav-label security-label", "SECURITY" }

                    a { class: "nav-item", "⬡", "Threat Detection" }
                    a { class: "nav-item", "◉", "Access Control" }
                    a { class: "nav-item", "⌬", "Network Topology" }
                    a { class: "nav-item", "⚑", "Alerts & Incidents" }

                    span { class: "nav-label security-label", "MANAGEMENT" }

                    a { class: "nav-item", "▧", "Reports" }
                    a { class: "nav-item", "⚙", "Settings" }
                }

                div { class: "sidebar-bottom",
                    div { class: "connection-indicator" }
                    span { "Agent connection active" }
                }
            }

            // Main content
            main { class: "main-content",

                header { class: "topbar",
                    div { class: "breadcrumb",
                        span { "Workspace" }
                        span { "/" }
                        strong {
                            if active_page() == "Network Discovery" {
                                "Network Discovery"
                            } else if active_page() == "Devices" {
                                "Devices"
                            } else {
                                "Overview"
                            }
                        }
                    }

                    div { class: "topbar-actions",
                        div { class: "search-box",
                            span { "⌕" }
                            input {
                                placeholder: "Search devices, IPs..."
                            }
                            kbd { "⌘ K" }
                        }

                        button { class: "icon-button", "♧" }
                        button { class: "profile-button", "IB" }
                    }
                }

                // Page content
                if active_page() == "Devices" {
                    DeviceInventory {}
                } else if active_page() == "Network Discovery" {
                    NetworkDiscovery {}
                } else {
                    section { class: "dashboard-content",

                        div { class: "welcome-row",
                            div {
                                span {
                                    class: "eyebrow",
                                    "NETWORK OPERATIONS CENTER"
                                }
                                h1 { "Network Overview" }
                                p {
                                    "Monitor your infrastructure, security and connectivity."
                                }
                            }

                            button {
                                class: "refresh-button",
                                "↻  Refresh data"
                            }
                        }

                        // Metrics
                        div { class: "metrics-grid",

                            div { class: "metric-card",
                                span { class: "metric-title", "TOTAL DEVICES" }
                                h2 { "248" }
                                span {
                                    class: "metric-caption",
                                    "Across monitored networks"
                                }
                            }

                            div { class: "metric-card",
                                span { class: "metric-title", "ONLINE DEVICES" }
                                h2 { "231" }
                                span {
                                    class: "metric-positive",
                                    "↑ 93.1% availability"
                                }
                            }

                            div { class: "metric-card",
                                span { class: "metric-title", "OFFLINE DEVICES" }
                                h2 { "17" }
                                span {
                                    class: "metric-warning",
                                    "Requires attention"
                                }
                            }

                            div { class: "metric-card",
                                span { class: "metric-title", "ACTIVE THREATS" }
                                h2 { "03" }
                                span {
                                    class: "metric-danger",
                                    "Security events detected"
                                }
                            }
                        }

                        // Network and WAN status
                        div { class: "section-grid",

                            div { class: "panel network-panel",
                                div { class: "panel-heading",
                                    h3 { "Network Health" }
                                    span {
                                        class: "status-badge healthy",
                                        "● Operational"
                                    }
                                }

                                div { class: "health-score",
                                    h2 { "98.6%" }
                                    span { "Overall network health" }
                                }

                                div { class: "health-bar",
                                    div { class: "health-progress" }
                                }

                                div { class: "health-details",
                                    div {
                                        span { "Latency" }
                                        strong { "12 ms" }
                                    }
                                    div {
                                        span { "Packet Loss" }
                                        strong { "0.02%" }
                                    }
                                    div {
                                        span { "Uptime" }
                                        strong { "99.98%" }
                                    }
                                }
                            }

                            div { class: "panel wan-panel",
                                div { class: "panel-heading",
                                    h3 { "WAN Connectivity" }
                                    span {
                                        class: "status-badge healthy",
                                        "● Connected"
                                    }
                                }

                                div { class: "wan-item",
                                    div { class: "wan-icon", "↗" }
                                    div {
                                        strong { "Primary WAN" }
                                        span { "Fiber connection" }
                                    }
                                    span { class: "wan-status", "Online" }
                                }

                                div { class: "wan-item",
                                    div { class: "wan-icon secondary", "↗" }
                                    div {
                                        strong { "Secondary WAN" }
                                        span { "Backup connection" }
                                    }
                                    span { class: "wan-status", "Online" }
                                }

                                div { class: "wan-footer",
                                    span { "Failover monitoring" }
                                    strong { "Enabled" }
                                }
                            }
                        }

                        // Activity and alerts
                        div { class: "section-grid bottom-grid",

                            div { class: "panel activity-panel",
                                div { class: "panel-heading",
                                    h3 { "Network Activity" }
                                    span {
                                        class: "muted-label",
                                        "Last 24 hours"
                                    }
                                }

                                div { class: "activity-placeholder",
                                    div { class: "activity-bars",
                                        div {
                                            class: "activity-bar",
                                            style: "height: 45%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 65%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 55%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 85%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 70%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 95%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 60%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 75%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 50%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 90%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 68%"
                                        }
                                        div {
                                            class: "activity-bar",
                                            style: "height: 80%"
                                        }
                                    }
                                }

                                div { class: "chart-legend",
                                    span { "● Inbound traffic" }
                                    span { "● Outbound traffic" }
                                }
                            }

                            div { class: "panel alerts-panel",
                                div { class: "panel-heading",
                                    h3 { "Recent Alerts" }
                                    span { class: "alert-count", "3 NEW" }
                                }

                                div { class: "alert-item",
                                    span { class: "alert-dot critical" }
                                    div {
                                        strong { "Suspicious traffic detected" }
                                        span {
                                            "Threat Detection · 5 min ago"
                                        }
                                    }
                                }

                                div { class: "alert-item",
                                    span { class: "alert-dot warning" }
                                    div {
                                        strong { "Device connection lost" }
                                        span {
                                            "Infrastructure · 18 min ago"
                                        }
                                    }
                                }

                                div { class: "alert-item",
                                    span { class: "alert-dot info" }
                                    div {
                                        strong { "High bandwidth usage" }
                                        span {
                                            "Traffic Analytics · 32 min ago"
                                        }
                                    }
                                }
                            }
                        }

                        footer { class: "dashboard-footer",
                            span { "NETQUORRA © 2026" }
                            span {
                                "Network Intelligence & Security Platform"
                            }
                        }
                    }
                }
            }
        }
    }
}
