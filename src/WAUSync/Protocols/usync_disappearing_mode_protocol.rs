use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{assert_node_error_free, BinaryNode, BinaryNodeAttributes, BinaryNodeError};
use crate::wa_usync::USyncUser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisappearingModeData {
    pub duration: u32,
    pub set_at_ms: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncDisappearingModeProtocol;

impl USyncQueryProtocol for USyncDisappearingModeProtocol {
    fn name(&self) -> &'static str {
        "disappearing_mode"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "disappearing_mode".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }
    }

    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        if node.tag == "disappearing_mode" {
            assert_node_error_free(node)?;
            let duration = node
                .attrs
                .get("duration")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let set_at_ms = node
                .attrs
                .get("t")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(1000);

            return Ok(Some(USyncProtocolData::DisappearingMode(
                DisappearingModeData {
                    duration,
                    set_at_ms,
                },
            )));
        }
        Ok(None)
    }
}
