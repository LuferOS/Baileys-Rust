use serde::{Deserialize, Serialize};
use std::fmt;

pub const S_WHATSAPP_NET: &str = "@s.whatsapp.net";
pub const OFFICIAL_BIZ_JID: &str = "16505361212@c.us";
pub const SERVER_JID: &str = "server@c.us";
pub const PSA_WID: &str = "0@c.us";
pub const STORIES_JID: &str = "status@broadcast";
pub const META_AI_JID: &str = "13135550002@c.us";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JidServer {
    CUs,
    GUs,
    Broadcast,
    SWhatsappNet,
    Call,
    Lid,
    Newsletter,
    Bot,
    Hosted,
    HostedLid,
    Other(String),
}

impl JidServer {
    pub fn as_str(&self) -> &str {
        match self {
            JidServer::CUs => "c.us",
            JidServer::GUs => "g.us",
            JidServer::Broadcast => "broadcast",
            JidServer::SWhatsappNet => "s.whatsapp.net",
            JidServer::Call => "call",
            JidServer::Lid => "lid",
            JidServer::Newsletter => "newsletter",
            JidServer::Bot => "bot",
            JidServer::Hosted => "hosted",
            JidServer::HostedLid => "hosted.lid",
            JidServer::Other(s) => s.as_str(),
        }
    }
}

impl From<&str> for JidServer {
    fn from(s: &str) -> Self {
        match s {
            "c.us" => JidServer::CUs,
            "g.us" => JidServer::GUs,
            "broadcast" => JidServer::Broadcast,
            "s.whatsapp.net" => JidServer::SWhatsappNet,
            "call" => JidServer::Call,
            "lid" => JidServer::Lid,
            "newsletter" => JidServer::Newsletter,
            "bot" => JidServer::Bot,
            "hosted" => JidServer::Hosted,
            "hosted.lid" => JidServer::HostedLid,
            other => JidServer::Other(other.to_string()),
        }
    }
}

impl fmt::Display for JidServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WaJidDomains {
    Whatsapp = 0,
    Lid = 1,
    Hosted = 128,
    HostedLid = 129,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JidWithDevice {
    pub user: String,
    pub device: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullJid {
    pub user: String,
    pub device: Option<u32>,
    pub server: JidServer,
    pub domain_type: Option<u32>,
}

pub fn get_server_from_domain_type(
    initial_server: &str,
    domain_type: Option<WaJidDomains>,
) -> JidServer {
    match domain_type {
        Some(WaJidDomains::Lid) => JidServer::Lid,
        Some(WaJidDomains::Hosted) => JidServer::Hosted,
        Some(WaJidDomains::HostedLid) => JidServer::HostedLid,
        Some(WaJidDomains::Whatsapp) | None => JidServer::from(initial_server),
    }
}

pub fn jid_encode(
    user: Option<&str>,
    server: &JidServer,
    device: Option<u32>,
    agent: Option<u32>,
) -> String {
    let user_part = user.unwrap_or("");
    let agent_part = match agent {
        Some(a) if a != 0 => format!("_{}", a),
        _ => String::new(),
    };
    let device_part = match device {
        Some(d) if d != 0 => format!(":{}", d),
        _ => String::new(),
    };
    format!("{}{}{}@{}", user_part, agent_part, device_part, server.as_str())
}

pub fn jid_decode(jid: &str) -> Option<FullJid> {
    let sep_idx = jid.find('@')?;
    let server_str = &jid[sep_idx + 1..];
    let user_combined = &jid[..sep_idx];

    let mut device_split = user_combined.split(':');
    let user_agent = device_split.next().unwrap_or("");
    let device_str = device_split.next();

    let mut agent_split = user_agent.split('_');
    let user = agent_split.next().unwrap_or("");
    let agent_str = agent_split.next();

    let domain_type = match server_str {
        "lid" => Some(WaJidDomains::Lid as u32),
        "hosted" => Some(WaJidDomains::Hosted as u32),
        "hosted.lid" => Some(WaJidDomains::HostedLid as u32),
        _ => match agent_str.filter(|s| !s.is_empty()) {
            Some(agent) => agent.parse::<u32>().ok(),
            None => Some(WaJidDomains::Whatsapp as u32),
        },
    };

    let device = device_str
        .filter(|s| !s.is_empty())
        .and_then(|d| d.parse::<u32>().ok());

    Some(FullJid {
        server: JidServer::from(server_str),
        user: user.to_string(),
        domain_type,
        device,
    })
}

pub fn are_jids_same_user(jid1: Option<&str>, jid2: Option<&str>) -> bool {
    jid1.and_then(jid_decode).map(|j| j.user) == jid2.and_then(jid_decode).map(|j| j.user)
}

pub fn is_jid_meta_ai(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@bot"))
}

pub fn is_pn_user(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@s.whatsapp.net"))
}

pub fn is_lid_user(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@lid"))
}

pub fn is_jid_broadcast(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@broadcast"))
}

pub fn is_jid_group(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@g.us"))
}

pub fn is_jid_status_broadcast(jid: &str) -> bool {
    jid == STORIES_JID
}

pub fn is_jid_newsletter(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@newsletter"))
}

pub fn is_hosted_pn_user(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@hosted"))
}

pub fn is_hosted_lid_user(jid: Option<&str>) -> bool {
    jid.is_some_and(|j| j.ends_with("@hosted.lid"))
}

pub fn is_jid_bot(jid: Option<&str>) -> bool {
    let Some(jid) = jid else {
        return false;
    };
    if !jid.ends_with("@c.us") {
        return false;
    }
    let user = jid.split('@').next().unwrap_or("");
    let matches_1313 = user.len() == 11
        && user.starts_with("1313555")
        && user[7..].bytes().all(|b| b.is_ascii_digit());
    let matches_1316 = user.len() == 11
        && user.starts_with("131655500")
        && user[9..].bytes().all(|b| b.is_ascii_digit());
    matches_1313 || matches_1316
}

pub fn jid_normalized_user(jid: Option<&str>) -> String {
    let Some(result) = jid.and_then(jid_decode) else {
        return String::new();
    };
    let server = match result.server {
        JidServer::CUs => JidServer::SWhatsappNet,
        other => other,
    };
    jid_encode(Some(&result.user), &server, None, None)
}

pub fn transfer_device(from_jid: &str, to_jid: &str) -> Option<String> {
    let from_decoded = jid_decode(from_jid);
    let device_id = from_decoded.and_then(|d| d.device).unwrap_or(0);
    let to_decoded = jid_decode(to_jid)?;
    Some(jid_encode(
        Some(&to_decoded.user),
        &to_decoded.server,
        Some(device_id),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jid_encode_decode() {
        let encoded = jid_encode(Some("573001234567"), &JidServer::SWhatsappNet, Some(2), Some(1));
        assert_eq!(encoded, "573001234567_1:2@s.whatsapp.net");

        let decoded = jid_decode(&encoded).unwrap();
        assert_eq!(decoded.user, "573001234567");
        assert_eq!(decoded.server, JidServer::SWhatsappNet);
        assert_eq!(decoded.device, Some(2));
        assert_eq!(decoded.domain_type, Some(1));
    }

    #[test]
    fn test_normalized_and_bot() {
        assert_eq!(
            jid_normalized_user(Some("573001234567:12@c.us")),
            "573001234567@s.whatsapp.net"
        );
        assert!(is_jid_bot(Some(META_AI_JID)));
        assert!(!is_jid_bot(Some("573001234567@c.us")));
    }

    #[test]
    fn test_transfer_device() {
        let transferred = transfer_device("573001234567:14@s.whatsapp.net", "12345@lid").unwrap();
        assert_eq!(transferred, "12345:14@lid");
    }
}
