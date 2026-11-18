use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{BinaryNode, BinaryNodeAttributes, BinaryNodeError};
use crate::wa_usync::USyncUser;

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncLidProtocol;

impl USyncQueryProtocol for USyncLidProtocol {
    fn name(&self) -> &'static str {
        "lid"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "lid".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }
    }

    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        let lid = user.lid.as_ref()?;
        Some(BinaryNode {
            tag: "lid".to_string(),
            attrs: BinaryNodeAttributes::from([("jid".to_string(), lid.clone())]),
            content: None,
        })
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        if node.tag == "lid" {
            if let Some(val) = node.attrs.get("val") {
                return Ok(Some(USyncProtocolData::Lid(val.clone())));
            }
        }
        Ok(None)
    }
}
