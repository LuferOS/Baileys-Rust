use crate::wa_binary::{BinaryNode, BinaryNodeData};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub kind: String,
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub relay_id: Option<String>,
    pub latency_ms: Option<u32>,
    pub raw_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallTelemetry {
    pub event_type: String,
    pub call_id: Option<String>,
    pub from: Option<String>,
    pub call_creator: Option<String>,
    pub call_creator_lid: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub net_medium: Option<String>,
    pub is_video: bool,
    pub is_group: bool,
    pub timestamp: Option<u64>,
    pub endpoints: Vec<NetworkEndpoint>,
}

pub fn detect_platform_from_id(id: &str) -> &'static str {
    if id.starts_with("3EB0") {
        "web"
    } else if id.starts_with("BAE5") || id.starts_with("BAILEYS") {
        "baileys"
    } else if id.starts_with("3A") && id.len() == 20 {
        "ios"
    } else if id.starts_with("3F") {
        "desktop"
    } else if id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        "android"
    } else {
        "unknown"
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn decode_binary_endpoint(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    if bytes.len() == 6 {
        let ip = IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        return Some((ip, port));
    }
    if bytes.len() == 18 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[0..16]);
        let ip = IpAddr::V6(Ipv6Addr::from(octets));
        let port = u16::from_be_bytes([bytes[16], bytes[17]]);
        return Some((ip, port));
    }
    None
}

fn parse_ip_port_str(s: &str) -> Option<(String, Option<u16>)> {
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return Some((sock.ip().to_string(), Some(sock.port())));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some((ip.to_string(), None));
    }
    None
}

fn collect_endpoints_recursive(node: &BinaryNode, out: &mut Vec<NetworkEndpoint>) {
    let tag = node.tag.as_str();
    let is_endpoint_tag = matches!(
        tag,
        "te" | "te2" | "relay" | "endpoint" | "ip" | "candidate" | "net"
    );

    if is_endpoint_tag {
        let relay_id = node
            .attrs
            .get("relay_id")
            .or_else(|| node.attrs.get("id"))
            .cloned();
        let latency_ms = node
            .attrs
            .get("latency")
            .and_then(|v| v.parse::<u32>().ok());
        let protocol = node
            .attrs
            .get("proto")
            .or_else(|| node.attrs.get("protocol"))
            .or_else(|| node.attrs.get("type"))
            .cloned();

        let mut added = false;

        if let Some(ip_attr) = node
            .attrs
            .get("ip")
            .or_else(|| node.attrs.get("addr"))
            .or_else(|| node.attrs.get("endpoint"))
        {
            let port_attr = node.attrs.get("port").and_then(|p| p.parse::<u16>().ok());
            if let Some((ip, parsed_port)) = parse_ip_port_str(ip_attr) {
                out.push(NetworkEndpoint {
                    kind: tag.to_string(),
                    ip,
                    port: port_attr.or(parsed_port),
                    protocol: protocol.clone(),
                    relay_id: relay_id.clone(),
                    latency_ms,
                    raw_hex: None,
                });
                added = true;
            }
        }

        if !added {
            match &node.content {
                Some(BinaryNodeData::Bytes(bytes)) => {
                    if let Some((ip, port)) = decode_binary_endpoint(bytes) {
                        out.push(NetworkEndpoint {
                            kind: tag.to_string(),
                            ip: ip.to_string(),
                            port: Some(port),
                            protocol: protocol.clone(),
                            relay_id: relay_id.clone(),
                            latency_ms,
                            raw_hex: Some(bytes_to_hex(bytes)),
                        });
                    }
                }
                Some(BinaryNodeData::String(s)) => {
                    if let Some((ip, port)) = parse_ip_port_str(s.trim()) {
                        out.push(NetworkEndpoint {
                            kind: tag.to_string(),
                            ip,
                            port,
                            protocol: protocol.clone(),
                            relay_id: relay_id.clone(),
                            latency_ms,
                            raw_hex: None,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(BinaryNodeData::List(children)) = &node.content {
        for child in children {
            collect_endpoints_recursive(child, out);
        }
    }
}

pub fn extract_call_telemetry(node: &BinaryNode) -> Option<CallTelemetry> {
    if node.tag != "call" {
        return None;
    }

    let from = node.attrs.get("from").cloned();
    let timestamp = node.attrs.get("t").and_then(|v| v.parse::<u64>().ok());
    let platform_top = node.attrs.get("platform").cloned();
    let version_top = node.attrs.get("version").cloned();

    let children = match &node.content {
        Some(BinaryNodeData::List(list)) => list.as_slice(),
        _ => &[],
    };

    let primary = children.first();
    let event_type = primary
        .map(|c| c.tag.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let call_id = primary
        .and_then(|c| c.attrs.get("call-id"))
        .or_else(|| node.attrs.get("id"))
        .cloned();
    let call_creator = primary
        .and_then(|c| c.attrs.get("call-creator"))
        .or_else(|| node.attrs.get("from"))
        .cloned();
    let call_creator_lid = primary
        .and_then(|c| c.attrs.get("caller_lid"))
        .or_else(|| primary.and_then(|c| c.attrs.get("call-creator-lid")))
        .cloned();
    let platform = primary
        .and_then(|c| c.attrs.get("platform"))
        .cloned()
        .or(platform_top)
        .or_else(|| call_id.as_deref().map(|id| detect_platform_from_id(id).to_string()));
    let version = primary
        .and_then(|c| c.attrs.get("version"))
        .cloned()
        .or(version_top);

    let mut is_video = false;
    let mut is_group = primary
        .and_then(|c| c.attrs.get("group-jid"))
        .is_some();
    let mut net_medium = None;

    if let Some(p) = primary {
        if let Some(BinaryNodeData::List(sub)) = &p.content {
            for child in sub {
                match child.tag.as_str() {
                    "video" => is_video = true,
                    "group" => is_group = true,
                    "net" => {
                        net_medium = child.attrs.get("medium").cloned();
                    }
                    _ => {}
                }
            }
        }
    }

    let mut endpoints = Vec::new();
    collect_endpoints_recursive(node, &mut endpoints);

    Some(CallTelemetry {
        event_type,
        call_id,
        from,
        call_creator,
        call_creator_lid,
        platform,
        version,
        net_medium,
        is_video,
        is_group,
        timestamp,
        endpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wa_binary::BinaryNodeAttributes;

    #[test]
    fn test_extract_call_telemetry_ipv4_and_ipv6() {
        let mut ipv6_bytes = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        ipv6_bytes.extend_from_slice(&443u16.to_be_bytes());

        let call_node = BinaryNode {
            tag: "call".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), "573001112233@s.whatsapp.net".to_string()),
                ("t".to_string(), "1700000000".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "offer".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("call-id".to_string(), "3EB0AABBCCDD".to_string()),
                    (
                        "call-creator".to_string(),
                        "573001112233@s.whatsapp.net".to_string(),
                    ),
                ]),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "net".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "medium".to_string(),
                            "wifi".to_string(),
                        )]),
                        content: None,
                    },
                    BinaryNode {
                        tag: "te".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::Bytes(vec![190, 14, 22, 10, 0x88, 0xb8])),
                    },
                    BinaryNode {
                        tag: "te2".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "latency".to_string(),
                            "42".to_string(),
                        )]),
                        content: Some(BinaryNodeData::Bytes(ipv6_bytes)),
                    },
                ])),
            }])),
        };

        let tel = extract_call_telemetry(&call_node).unwrap();
        assert_eq!(tel.event_type, "offer");
        assert_eq!(tel.net_medium.as_deref(), Some("wifi"));
        assert_eq!(tel.platform.as_deref(), Some("web"));
        assert_eq!(tel.endpoints.len(), 2);
        assert_eq!(tel.endpoints[0].ip, "190.14.22.10");
        assert_eq!(tel.endpoints[0].port, Some(35000));
        assert_eq!(tel.endpoints[1].ip, "2001:db8::1");
        assert_eq!(tel.endpoints[1].port, Some(443));
        assert_eq!(tel.endpoints[1].latency_ms, Some(42));
    }
}
