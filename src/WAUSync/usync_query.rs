use super::protocols::{
    BotProfileInfo, DisappearingModeData, StatusData, USyncBotProfileProtocol,
    USyncContactProtocol, USyncDeviceInfo, USyncDeviceProtocol, USyncDisappearingModeProtocol,
    USyncLidProtocol, USyncProtocolData, USyncQueryProtocol, USyncStatusProtocol,
    USyncUsernameProtocol,
};
use super::usync_user::USyncUser;
use crate::wa_binary::{
    get_binary_node_child, BinaryNode, BinaryNodeAttributes, BinaryNodeData, BinaryNodeError,
    S_WHATSAPP_NET,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct USyncQueryResultList {
    pub id: String,
    pub data: HashMap<String, USyncProtocolData>,
}

impl USyncQueryResultList {
    pub fn contact(&self) -> Option<bool> {
        match self.data.get("contact") {
            Some(USyncProtocolData::Contact(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn devices(&self) -> Option<&USyncDeviceInfo> {
        match self.data.get("devices") {
            Some(USyncProtocolData::Devices(v)) => Some(v),
            _ => None,
        }
    }

    pub fn disappearing_mode(&self) -> Option<&DisappearingModeData> {
        match self.data.get("disappearing_mode") {
            Some(USyncProtocolData::DisappearingMode(v)) => Some(v),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<&StatusData> {
        match self.data.get("status") {
            Some(USyncProtocolData::Status(v)) => Some(v),
            _ => None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self.data.get("username") {
            Some(USyncProtocolData::Username(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    pub fn bot_profile(&self) -> Option<&BotProfileInfo> {
        match self.data.get("bot") {
            Some(USyncProtocolData::BotProfile(v)) => Some(v),
            _ => None,
        }
    }

    pub fn lid(&self) -> Option<&str> {
        match self.data.get("lid") {
            Some(USyncProtocolData::Lid(v)) => Some(v.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct USyncQueryResult {
    pub list: Vec<USyncQueryResultList>,
    pub side_list: Vec<USyncQueryResultList>,
}

pub struct USyncQuery {
    pub protocols: Vec<Box<dyn USyncQueryProtocol>>,
    pub users: Vec<USyncUser>,
    pub context: String,
    pub mode: String,
}

impl Default for USyncQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl USyncQuery {
    pub fn new() -> Self {
        Self {
            protocols: Vec::new(),
            users: Vec::new(),
            context: "interactive".to_string(),
            mode: "query".to_string(),
        }
    }

    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    pub fn with_user(mut self, user: USyncUser) -> Self {
        self.users.push(user);
        self
    }

    pub fn with_device_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncDeviceProtocol));
        self
    }

    pub fn with_contact_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncContactProtocol));
        self
    }

    pub fn with_status_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncStatusProtocol));
        self
    }

    pub fn with_disappearing_mode_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncDisappearingModeProtocol));
        self
    }

    pub fn with_bot_profile_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncBotProfileProtocol));
        self
    }

    pub fn with_lid_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncLidProtocol));
        self
    }

    pub fn with_username_protocol(mut self) -> Self {
        self.protocols.push(Box::new(USyncUsernameProtocol));
        self
    }

    pub fn build_iq_node(&self, sid: String) -> BinaryNode {
        let user_nodes: Vec<BinaryNode> = self
            .users
            .iter()
            .map(|user| {
                let mut attrs = BinaryNodeAttributes::new();
                if user.phone.is_none() {
                    if let Some(id) = &user.id {
                        attrs.insert("jid".to_string(), id.clone());
                    }
                }
                let content: Vec<BinaryNode> = self
                    .protocols
                    .iter()
                    .filter_map(|p| p.get_user_element(user))
                    .collect();
                BinaryNode {
                    tag: "user".to_string(),
                    attrs,
                    content: Some(BinaryNodeData::List(content)),
                }
            })
            .collect();

        let query_node = BinaryNode {
            tag: "query".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(
                self.protocols.iter().map(|p| p.get_query_element()).collect(),
            )),
        };

        let list_node = BinaryNode {
            tag: "list".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(user_nodes)),
        };

        BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("to".to_string(), S_WHATSAPP_NET.to_string()),
                ("type".to_string(), "get".to_string()),
                ("xmlns".to_string(), "usync".to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "usync".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("context".to_string(), self.context.clone()),
                    ("mode".to_string(), self.mode.clone()),
                    ("sid".to_string(), sid),
                    ("last".to_string(), "true".to_string()),
                    ("index".to_string(), "0".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![query_node, list_node])),
            }])),
        }
    }

    pub fn parse_usync_query_result(
        &self,
        result: &BinaryNode,
    ) -> Result<Option<USyncQueryResult>, BinaryNodeError> {
        if result.attrs.get("type").map(|s| s.as_str()) != Some("result") {
            return Ok(None);
        }

        let protocol_map: HashMap<&'static str, &dyn USyncQueryProtocol> = self
            .protocols
            .iter()
            .map(|p| (p.name(), p.as_ref()))
            .collect();

        let mut query_result = USyncQueryResult::default();
        let usync_node = get_binary_node_child(Some(result), "usync");
        let list_node = get_binary_node_child(usync_node, "list");

        if let Some(BinaryNodeData::List(nodes)) = list_node.and_then(|n| n.content.as_ref()) {
            for node in nodes {
                let Some(id) = node.attrs.get("jid").cloned() else {
                    continue;
                };
                let mut data = HashMap::new();
                if let Some(BinaryNodeData::List(children)) = &node.content {
                    for child in children {
                        if let Some(protocol) = protocol_map.get(child.tag.as_str()) {
                            if let Some(parsed) = protocol.parser(child)? {
                                data.insert(child.tag.clone(), parsed);
                            }
                        }
                    }
                }
                query_result.list.push(USyncQueryResultList { id, data });
            }
        }

        Ok(Some(query_result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usync_query_build_and_parse_all_protocols() {
        let query = USyncQuery::new()
            .with_contact_protocol()
            .with_device_protocol()
            .with_lid_protocol()
            .with_status_protocol()
            .with_disappearing_mode_protocol()
            .with_username_protocol()
            .with_user(USyncUser::new().with_phone("+573001234567"));

        let iq = query.build_iq_node("sid-1".to_string());
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("xmlns").map(|s| s.as_str()), Some("usync"));

        let mock_response = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([("type".to_string(), "result".to_string())]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "usync".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "list".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "user".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "jid".to_string(),
                            "573001234567@s.whatsapp.net".to_string(),
                        )]),
                        content: Some(BinaryNodeData::List(vec![
                            BinaryNode {
                                tag: "contact".to_string(),
                                attrs: BinaryNodeAttributes::from([(
                                    "type".to_string(),
                                    "in".to_string(),
                                )]),
                                content: None,
                            },
                            BinaryNode {
                                tag: "lid".to_string(),
                                attrs: BinaryNodeAttributes::from([(
                                    "val".to_string(),
                                    "123456789@lid".to_string(),
                                )]),
                                content: None,
                            },
                            BinaryNode {
                                tag: "status".to_string(),
                                attrs: BinaryNodeAttributes::from([(
                                    "t".to_string(),
                                    "1700000000".to_string(),
                                )]),
                                content: Some(BinaryNodeData::String("Disponible".to_string())),
                            },
                            BinaryNode {
                                tag: "disappearing_mode".to_string(),
                                attrs: BinaryNodeAttributes::from([
                                    ("duration".to_string(), "86400".to_string()),
                                    ("t".to_string(), "1700000000".to_string()),
                                ]),
                                content: None,
                            },
                            BinaryNode {
                                tag: "username".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::String("lufer".to_string())),
                            },
                            BinaryNode {
                                tag: "devices".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::List(vec![BinaryNode {
                                    tag: "device-list".to_string(),
                                    attrs: BinaryNodeAttributes::new(),
                                    content: Some(BinaryNodeData::List(vec![
                                        BinaryNode {
                                            tag: "device".to_string(),
                                            attrs: BinaryNodeAttributes::from([(
                                                "id".to_string(),
                                                "0".to_string(),
                                            )]),
                                            content: None,
                                        },
                                        BinaryNode {
                                            tag: "device".to_string(),
                                            attrs: BinaryNodeAttributes::from([
                                                ("id".to_string(), "2".to_string()),
                                                ("key-index".to_string(), "1".to_string()),
                                                ("is_hosted".to_string(), "true".to_string()),
                                            ]),
                                            content: None,
                                        },
                                    ])),
                                }])),
                            },
                        ])),
                    }])),
                }])),
            }])),
        };

        let parsed = query
            .parse_usync_query_result(&mock_response)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.list.len(), 1);
        let item = &parsed.list[0];
        assert_eq!(item.id, "573001234567@s.whatsapp.net");
        assert_eq!(item.contact(), Some(true));
        assert_eq!(item.lid(), Some("123456789@lid"));
        assert_eq!(item.username(), Some("lufer"));
        assert_eq!(
            item.status().unwrap().status.as_deref(),
            Some("Disponible")
        );
        assert_eq!(item.disappearing_mode().unwrap().duration, 86400);
        assert_eq!(item.devices().unwrap().device_list.len(), 2);
        assert!(item.devices().unwrap().device_list[1].is_hosted);
    }
}
