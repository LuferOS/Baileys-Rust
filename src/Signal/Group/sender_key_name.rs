use crate::types::ProtocolAddress;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SenderKeyName {
    group_id: String,
    sender: ProtocolAddress,
}

impl SenderKeyName {
    pub fn new(group_id: impl Into<String>, sender: ProtocolAddress) -> Self {
        Self {
            group_id: group_id.into(),
            sender,
        }
    }

    pub fn get_group_id(&self) -> &str {
        &self.group_id
    }

    pub fn get_sender(&self) -> &ProtocolAddress {
        &self.sender
    }

    pub fn serialize(&self) -> String {
        format!(
            "{}::{}::{}",
            self.group_id, self.sender.name, self.sender.device_id
        )
    }
}

impl fmt::Display for SenderKeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.serialize())
    }
}
