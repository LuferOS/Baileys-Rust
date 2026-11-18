use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{
    assert_node_error_free, BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError,
};
use crate::wa_usync::USyncUser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusData {
    pub status: Option<String>,
    pub set_at_ms: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncStatusProtocol;

impl USyncQueryProtocol for USyncStatusProtocol {
    fn name(&self) -> &'static str {
        "status"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "status".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }
    }

    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        if node.tag == "status" {
            assert_node_error_free(node)?;
            let raw_status = match &node.content {
                Some(BinaryNodeData::String(s)) => Some(s.clone()),
                Some(BinaryNodeData::Bytes(b)) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            };

            let set_at_ms = node
                .attrs
                .get("t")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(1000);

            let status = match raw_status {
                Some(s) if !s.is_empty() => Some(s),
                _ => {
                    if node.attrs.get("code").and_then(|c| c.parse::<u16>().ok()) == Some(401) {
                        Some(String::new())
                    } else {
                        None
                    }
                }
            };

            return Ok(Some(USyncProtocolData::Status(StatusData {
                status,
                set_at_ms,
            })));
        }
        Ok(None)
    }
}
