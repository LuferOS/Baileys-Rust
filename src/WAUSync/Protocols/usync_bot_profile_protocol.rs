use super::types::{USyncProtocolData, USyncQueryProtocol};
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_child_string, get_binary_node_children, BinaryNode,
    BinaryNodeAttributes, BinaryNodeData, BinaryNodeError,
};
use crate::wa_usync::USyncUser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotProfileCommand {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotProfileInfo {
    pub jid: String,
    pub name: String,
    pub attributes: String,
    pub description: String,
    pub category: String,
    pub is_default: bool,
    pub prompts: Vec<String>,
    pub persona_id: String,
    pub commands: Vec<BotProfileCommand>,
    pub commands_description: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct USyncBotProfileProtocol;

impl USyncQueryProtocol for USyncBotProfileProtocol {
    fn name(&self) -> &'static str {
        "bot"
    }

    fn get_query_element(&self) -> BinaryNode {
        BinaryNode {
            tag: "bot".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "profile".to_string(),
                attrs: BinaryNodeAttributes::from([("v".to_string(), "1".to_string())]),
                content: None,
            }])),
        }
    }

    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        let persona_id = user.persona_id.clone().unwrap_or_default();
        Some(BinaryNode {
            tag: "bot".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "profile".to_string(),
                attrs: BinaryNodeAttributes::from([("persona_id".to_string(), persona_id)]),
                content: None,
            }])),
        })
    }

    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncProtocolData>, BinaryNodeError> {
        let bot_node = get_binary_node_child(Some(node), "bot").unwrap_or(node);
        let profile = get_binary_node_child(Some(bot_node), "profile");
        let commands_node = get_binary_node_child(profile, "commands");
        let prompts_node = get_binary_node_child(profile, "prompts");

        let mut commands = Vec::new();
        for command in get_binary_node_children(commands_node, "command") {
            commands.push(BotProfileCommand {
                name: get_binary_node_child_string(Some(command), "name").unwrap_or_default(),
                description: get_binary_node_child_string(Some(command), "description")
                    .unwrap_or_default(),
            });
        }

        let mut prompts = Vec::new();
        for prompt in get_binary_node_children(prompts_node, "prompt") {
            let emoji = get_binary_node_child_string(Some(prompt), "emoji").unwrap_or_default();
            let text = get_binary_node_child_string(Some(prompt), "text").unwrap_or_default();
            prompts.push(format!("{} {}", emoji, text));
        }

        let info = BotProfileInfo {
            is_default: get_binary_node_child(profile, "default").is_some(),
            jid: node.attrs.get("jid").cloned().unwrap_or_default(),
            name: get_binary_node_child_string(profile, "name").unwrap_or_default(),
            attributes: get_binary_node_child_string(profile, "attributes").unwrap_or_default(),
            description: get_binary_node_child_string(profile, "description").unwrap_or_default(),
            category: get_binary_node_child_string(profile, "category").unwrap_or_default(),
            persona_id: profile
                .and_then(|p| p.attrs.get("persona_id").cloned())
                .unwrap_or_default(),
            commands_description: get_binary_node_child_string(commands_node, "description")
                .unwrap_or_default(),
            commands,
            prompts,
        };

        Ok(Some(USyncProtocolData::BotProfile(info)))
    }
}
