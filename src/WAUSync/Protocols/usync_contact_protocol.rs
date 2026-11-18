use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{
    assert_node_error_free, BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError,
};
use crate::wa_usync::USyncUser;

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncContactProtocol;

impl USyncQueryProtocol for USyncContactProtocol {
    fn name(&self) -> &'static str {
        "contact"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "contact".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        }
    }

    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        if let Some(phone) = &user.phone {
            return Some(BinaryNode {
                tag: "contact".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(phone.clone())),
            });
        }

        if let Some(username) = &user.username {
            let mut attrs = BinaryNodeAttributes::new();
            attrs.insert("username".to_string(), username.clone());
            if let Some(pin) = &user.username_key {
                attrs.insert("pin".to_string(), pin.clone());
            }
            if let Some(lid) = &user.lid {
                attrs.insert("lid".to_string(), lid.clone());
            }
            return Some(BinaryNode {
                tag: "contact".to_string(),
                attrs,
                content: None,
            });
        }

        if let Some(user_type) = &user.r#type {
            return Some(BinaryNode {
                tag: "contact".to_string(),
                attrs: BinaryNodeAttributes::from([("type".to_string(), user_type.clone())]),
                content: None,
            });
        }

        Some(BinaryNode {
            tag: "contact".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: None,
        })
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        if node.tag == "contact" {
            assert_node_error_free(node)?;
            let exists = node.attrs.get("type").map(|s| s.as_str()) == Some("in");
            return Ok(Some(USyncProtocolData::Contact(exists)));
        }
        Ok(Some(USyncProtocolData::Contact(false)))
    }
}
