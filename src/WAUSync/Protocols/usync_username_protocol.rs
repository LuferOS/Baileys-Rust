use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{
    assert_node_error_free, BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError,
};
use crate::wa_usync::USyncUser;

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncUsernameProtocol;

impl USyncQueryProtocol for USyncUsernameProtocol {
    fn name(&self) -> &'static str {
        "username"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "username".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }
    }

    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        if node.tag == "username" {
            assert_node_error_free(node)?;
            if let Some(BinaryNodeData::String(username)) = &node.content {
                return Ok(Some(USyncProtocolData::Username(username.clone())));
            }
        }
        Ok(None)
    }
}
