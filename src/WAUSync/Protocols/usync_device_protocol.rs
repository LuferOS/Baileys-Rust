use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::types::{DeviceListData, ParsedDeviceInfo};
use crate::wa_binary::{
    assert_node_error_free, get_binary_node_child, BinaryNode, BinaryNodeAttributes,
    BinaryNodeData, BinaryNodeError,
};
use crate::wa_usync::USyncUser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyIndexData {
    pub timestamp: u64,
    pub signed_key_index: Option<Vec<u8>>,
    pub expected_timestamp: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct USyncDeviceInfo {
    pub device_list: Vec<DeviceListData>,
    pub key_index: Option<KeyIndexData>,
}

impl USyncDeviceInfo {
    pub fn to_parsed_device_info(&self) -> ParsedDeviceInfo {
        ParsedDeviceInfo {
            device_list: self.device_list.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncDeviceProtocol;

impl USyncQueryProtocol for USyncDeviceProtocol {
    fn name(&self) -> &'static str {
        "devices"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "devices".to_string(),
            attrs: BinaryNodeAttributes::from([("version".to_string(), "2".to_string())]),
            content: None,
        }
    }

    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        let mut device_list = Vec::new();
        let mut key_index = None;

        if node.tag == "devices" {
            assert_node_error_free(node)?;
            let device_list_node = get_binary_node_child(Some(node), "device-list");
            let key_index_node = get_binary_node_child(Some(node), "key-index-list");

            if let Some(BinaryNodeData::List(items)) = device_list_node.and_then(|n| n.content.as_ref()) {
                for item in items {
                    if item.tag == "device" {
                        if let Some(id) = item.attrs.get("id").and_then(|v| v.parse::<u32>().ok()) {
                            let key_idx = item
                                .attrs
                                .get("key-index")
                                .and_then(|v| v.parse::<u32>().ok());
                            let is_hosted = item
                                .attrs
                                .get("is_hosted")
                                .is_some_and(|v| v == "true");
                            device_list.push(DeviceListData {
                                id,
                                key_index: key_idx,
                                is_hosted,
                            });
                        }
                    }
                }
            }

            if let Some(ki_node) = key_index_node {
                let timestamp = ki_node
                    .attrs
                    .get("ts")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                let expected_timestamp = ki_node
                    .attrs
                    .get("expected_ts")
                    .and_then(|v| v.parse::<u64>().ok());
                let signed_key_index = match &ki_node.content {
                    Some(BinaryNodeData::Bytes(b)) => Some(b.clone()),
                    _ => None,
                };
                key_index = Some(KeyIndexData {
                    timestamp,
                    signed_key_index,
                    expected_timestamp,
                });
            }
        }

        Ok(Some(USyncProtocolData::Devices(USyncDeviceInfo {
            device_list,
            key_index,
        })))
    }
}
