use super::usync_bot_profile_protocol::BotProfileInfo;
use super::usync_device_protocol::USyncDeviceInfo;
use super::usync_disappearing_mode_protocol::DisappearingModeData;
use super::usync_status_protocol::StatusData;
use crate::wa_binary::{BinaryNode, BinaryNodeError};
use crate::wa_usync::USyncUser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum USyncProtocolData {
    Contact(bool),
    Devices(USyncDeviceInfo),
    DisappearingMode(DisappearingModeData),
    Status(StatusData),
    Username(String),
    BotProfile(BotProfileInfo),
    Lid(String),
}

pub trait USyncQueryProtocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn get_query_element(&self) -> BinaryNode;
    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode>;
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError>;
}
