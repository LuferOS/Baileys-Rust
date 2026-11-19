use super::groups::GroupsError;
use super::socket::{SocketError, WaSocket};
use crate::proto::message::GroupInviteMessage;
use crate::types::{
    GroupMetadata, GroupParticipant, GroupRequestAction, GroupSetting, JoinApprovalMode,
    MemberAddMode, ParticipantAction, ParticipantUpdateResult, RequestParticipantUpdateResult,
    WaMessageAddressingMode,
};
use crate::utils::{generate_message_id, generate_message_id_v2};
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_child_string, get_binary_node_children, jid_encode,
    jid_normalized_user, BinaryNode, BinaryNodeAttributes, BinaryNodeData, JidServer,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommunitiesError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("groups error: {0}")]
    Groups(#[from] GroupsError),
    #[error("invalid community metadata response: missing <community> node")]
    MissingCommunityNode,
    #[error("missing required field in invite message: {0}")]
    MissingInviteField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedGroupInfo {
    pub id: Option<String>,
    pub subject: String,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedGroupsResponse {
    pub community_jid: String,
    pub is_community: bool,
    pub linked_groups: Vec<LinkedGroupInfo>,
}

pub fn extract_community_metadata(result: &BinaryNode) -> Result<GroupMetadata, CommunitiesError> {
    let community = get_binary_node_child(Some(result), "community")
        .ok_or(CommunitiesError::MissingCommunityNode)?;

    let desc_child = get_binary_node_child(Some(community), "description");
    let (desc, desc_id) = if let Some(dc) = desc_child {
        (
            get_binary_node_child_string(Some(dc), "body"),
            dc.attrs.get("id").cloned(),
        )
    } else {
        (None, None)
    };

    let raw_id = community
        .attrs
        .get("id")
        .map(|s| s.as_str())
        .unwrap_or("");
    let community_id = if raw_id.contains('@') {
        raw_id.to_string()
    } else {
        jid_encode(Some(raw_id), &JidServer::GUs, None, None)
    };

    let participants: Vec<GroupParticipant> = get_binary_node_children(Some(community), "participant")
        .into_iter()
        .filter_map(|node| {
            let jid = node.attrs.get("jid")?.clone();
            let admin = node
                .attrs
                .get("type")
                .filter(|s| !s.is_empty())
                .cloned();
            Some(GroupParticipant {
                id: jid,
                phone_number: None,
                lid: None,
                username: None,
                admin,
            })
        })
        .collect();

    let eph = get_binary_node_child(Some(community), "ephemeral")
        .and_then(|e| e.attrs.get("expiration"))
        .and_then(|v| v.parse::<u32>().ok());
    let member_add_mode =
        get_binary_node_child_string(Some(community), "member_add_mode").as_deref()
            == Some("all_member_add");
    let addressing_mode =
        if get_binary_node_child_string(Some(community), "addressing_mode").as_deref() == Some("lid")
        {
            WaMessageAddressingMode::Lid
        } else {
            WaMessageAddressingMode::Pn
        };

    Ok(GroupMetadata {
        id: community_id,
        notify: None,
        addressing_mode,
        subject: community.attrs.get("subject").cloned().unwrap_or_default(),
        subject_owner: community.attrs.get("s_o").cloned(),
        subject_owner_pn: None,
        subject_owner_username: None,
        subject_time: community.attrs.get("s_t").and_then(|v| v.parse::<u64>().ok()),
        size: participants.len(),
        creation: community
            .attrs
            .get("creation")
            .and_then(|v| v.parse::<u64>().ok()),
        owner: community
            .attrs
            .get("creator")
            .map(|c| jid_normalized_user(Some(c))),
        owner_pn: None,
        owner_username: None,
        owner_country_code: None,
        desc,
        desc_id,
        desc_owner: None,
        desc_owner_pn: None,
        desc_owner_username: None,
        desc_time: None,
        linked_parent: get_binary_node_child(Some(community), "linked_parent")
            .and_then(|n| n.attrs.get("jid"))
            .filter(|s| !s.is_empty())
            .cloned(),
        restrict: get_binary_node_child(Some(community), "locked").is_some(),
        announce: get_binary_node_child(Some(community), "announcement").is_some(),
        is_community: get_binary_node_child(Some(community), "parent").is_some(),
        is_community_announce: get_binary_node_child(Some(community), "default_sub_community")
            .is_some(),
        join_approval_mode: get_binary_node_child(Some(community), "membership_approval_mode")
            .is_some(),
        member_add_mode,
        participants,
        ephemeral_duration: eph,
    })
}

impl WaSocket {
    async fn community_query(
        &self,
        jid: &str,
        iq_type: &str,
        content: Vec<BinaryNode>,
    ) -> Result<BinaryNode, CommunitiesError> {
        let res = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("type".to_string(), iq_type.to_string()),
                        ("xmlns".to_string(), "w:g2".to_string()),
                        ("to".to_string(), jid.to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(content)),
                },
                None,
            )
            .await?;
        Ok(res)
    }

    async fn parse_community_group_result(&self, node: &BinaryNode) -> Option<GroupMetadata> {
        let group_node = get_binary_node_child(Some(node), "group")?;
        let id = group_node.attrs.get("id")?;
        let jid = if id.contains('@') {
            id.clone()
        } else {
            format!("{}@g.us", id)
        };
        self.group_metadata(&jid).await.ok()
    }

    pub async fn community_metadata(&self, jid: &str) -> Result<GroupMetadata, CommunitiesError> {
        let result = self
            .community_query(
                jid,
                "get",
                vec![BinaryNode {
                    tag: "query".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "request".to_string(),
                        "interactive".to_string(),
                    )]),
                    content: None,
                }],
            )
            .await?;
        extract_community_metadata(&result)
    }

    pub async fn community_fetch_all_participating(
        &self,
    ) -> Result<HashMap<String, GroupMetadata>, CommunitiesError> {
        let result = self
            .community_query(
                "@g.us",
                "get",
                vec![BinaryNode {
                    tag: "participating".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![
                        BinaryNode {
                            tag: "participants".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: None,
                        },
                        BinaryNode {
                            tag: "description".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: None,
                        },
                    ])),
                }],
            )
            .await?;

        let mut data = HashMap::new();
        if let Some(communities_child) = get_binary_node_child(Some(&result), "communities") {
            for community_node in get_binary_node_children(Some(communities_child), "community") {
                let wrapper = BinaryNode {
                    tag: "result".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![community_node.clone()])),
                };
                if let Ok(meta) = extract_community_metadata(&wrapper) {
                    data.insert(meta.id.clone(), meta);
                }
            }
        }
        Ok(data)
    }

    pub async fn community_create(
        &self,
        subject: &str,
        body: &str,
    ) -> Result<Option<GroupMetadata>, CommunitiesError> {
        let description_id = generate_message_id()[..12].to_string();
        let result = self
            .community_query(
                "@g.us",
                "set",
                vec![BinaryNode {
                    tag: "create".to_string(),
                    attrs: BinaryNodeAttributes::from([("subject".to_string(), subject.to_string())]),
                    content: Some(BinaryNodeData::List(vec![
                        BinaryNode {
                            tag: "description".to_string(),
                            attrs: BinaryNodeAttributes::from([("id".to_string(), description_id)]),
                            content: Some(BinaryNodeData::List(vec![BinaryNode {
                                tag: "body".to_string(),
                                attrs: BinaryNodeAttributes::new(),
                                content: Some(BinaryNodeData::Bytes(body.as_bytes().to_vec())),
                            }])),
                        },
                        BinaryNode {
                            tag: "parent".to_string(),
                            attrs: BinaryNodeAttributes::from([(
                                "default_membership_approval_mode".to_string(),
                                "request_required".to_string(),
                            )]),
                            content: None,
                        },
                        BinaryNode {
                            tag: "allow_non_admin_sub_group_creation".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: None,
                        },
                        BinaryNode {
                            tag: "create_general_chat".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: None,
                        },
                    ])),
                }],
            )
            .await?;

        Ok(self.parse_community_group_result(&result).await)
    }

    pub async fn community_create_group(
        &self,
        subject: &str,
        participants: &[String],
        parent_community_jid: &str,
    ) -> Result<Option<GroupMetadata>, CommunitiesError> {
        let key = generate_message_id_v2(None);
        let mut children: Vec<BinaryNode> = participants
            .iter()
            .map(|jid| BinaryNode {
                tag: "participant".to_string(),
                attrs: BinaryNodeAttributes::from([("jid".to_string(), jid.clone())]),
                content: None,
            })
            .collect();
        children.push(BinaryNode {
            tag: "linked_parent".to_string(),
            attrs: BinaryNodeAttributes::from([(
                "jid".to_string(),
                parent_community_jid.to_string(),
            )]),
            content: None,
        });

        let result = self
            .community_query(
                "@g.us",
                "set",
                vec![BinaryNode {
                    tag: "create".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("subject".to_string(), subject.to_string()),
                        ("key".to_string(), key),
                    ]),
                    content: Some(BinaryNodeData::List(children)),
                }],
            )
            .await?;

        Ok(self.parse_community_group_result(&result).await)
    }

    pub async fn community_leave(&self, id: &str) -> Result<(), CommunitiesError> {
        self.community_query(
            "@g.us",
            "set",
            vec![BinaryNode {
                tag: "leave".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "community".to_string(),
                    attrs: BinaryNodeAttributes::from([("id".to_string(), id.to_string())]),
                    content: None,
                }])),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_update_subject(
        &self,
        jid: &str,
        subject: &str,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: "subject".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(subject.as_bytes().to_vec())),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_link_group(
        &self,
        group_jid: &str,
        parent_community_jid: &str,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            parent_community_jid,
            "set",
            vec![BinaryNode {
                tag: "links".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "link".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "link_type".to_string(),
                        "sub_group".to_string(),
                    )]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "group".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "jid".to_string(),
                            group_jid.to_string(),
                        )]),
                        content: None,
                    }])),
                }])),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_unlink_group(
        &self,
        group_jid: &str,
        parent_community_jid: &str,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            parent_community_jid,
            "set",
            vec![BinaryNode {
                tag: "unlink".to_string(),
                attrs: BinaryNodeAttributes::from([(
                    "unlink_type".to_string(),
                    "sub_group".to_string(),
                )]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "group".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "jid".to_string(),
                        group_jid.to_string(),
                    )]),
                    content: None,
                }])),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_fetch_linked_groups(
        &self,
        jid: &str,
    ) -> Result<LinkedGroupsResponse, CommunitiesError> {
        let metadata = self.group_metadata(jid).await?;
        let (community_jid, is_community) = match metadata.linked_parent {
            Some(parent) => (parent, false),
            None => (jid.to_string(), true),
        };

        let result = self
            .community_query(
                &community_jid,
                "get",
                vec![BinaryNode {
                    tag: "sub_groups".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }],
            )
            .await?;

        let mut linked_groups = Vec::new();
        if let Some(sub_groups_node) = get_binary_node_child(Some(&result), "sub_groups") {
            for group_node in get_binary_node_children(Some(sub_groups_node), "group") {
                linked_groups.push(LinkedGroupInfo {
                    id: group_node
                        .attrs
                        .get("id")
                        .map(|id| jid_encode(Some(id), &JidServer::GUs, None, None)),
                    subject: group_node.attrs.get("subject").cloned().unwrap_or_default(),
                    creation: group_node
                        .attrs
                        .get("creation")
                        .and_then(|v| v.parse::<u64>().ok()),
                    owner: group_node
                        .attrs
                        .get("creator")
                        .map(|c| jid_normalized_user(Some(c))),
                    size: group_node
                        .attrs
                        .get("size")
                        .and_then(|v| v.parse::<usize>().ok()),
                });
            }
        }

        Ok(LinkedGroupsResponse {
            community_jid,
            is_community,
            linked_groups,
        })
    }

    pub async fn community_request_participants_list(
        &self,
        jid: &str,
    ) -> Result<Vec<BinaryNodeAttributes>, CommunitiesError> {
        let result = self
            .community_query(
                jid,
                "get",
                vec![BinaryNode {
                    tag: "membership_approval_requests".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }],
            )
            .await?;
        let node = get_binary_node_child(Some(&result), "membership_approval_requests");
        Ok(get_binary_node_children(node, "membership_approval_request")
            .into_iter()
            .map(|n| n.attrs.clone())
            .collect())
    }

    pub async fn community_request_participants_update(
        &self,
        jid: &str,
        participants: &[String],
        action: GroupRequestAction,
    ) -> Result<Vec<RequestParticipantUpdateResult>, CommunitiesError> {
        let action_str = action.as_str();
        let participant_nodes: Vec<BinaryNode> = participants
            .iter()
            .map(|p| BinaryNode {
                tag: "participant".to_string(),
                attrs: BinaryNodeAttributes::from([("jid".to_string(), p.clone())]),
                content: None,
            })
            .collect();

        let result = self
            .community_query(
                jid,
                "set",
                vec![BinaryNode {
                    tag: "membership_requests_action".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: action_str.to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(participant_nodes)),
                    }])),
                }],
            )
            .await?;

        let node = get_binary_node_child(Some(&result), "membership_requests_action");
        let node_action = get_binary_node_child(node, action_str);
        Ok(get_binary_node_children(node_action, "participant")
            .into_iter()
            .map(|p| RequestParticipantUpdateResult {
                status: p
                    .attrs
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "200".to_string()),
                jid: p.attrs.get("jid").cloned(),
            })
            .collect())
    }

    pub async fn community_participants_update(
        &self,
        jid: &str,
        participants: &[String],
        action: ParticipantAction,
    ) -> Result<Vec<ParticipantUpdateResult>, CommunitiesError> {
        let action_str = action.as_str();
        let attrs = if action == ParticipantAction::Remove {
            BinaryNodeAttributes::from([("linked_groups".to_string(), "true".to_string())])
        } else {
            BinaryNodeAttributes::new()
        };
        let participant_nodes: Vec<BinaryNode> = participants
            .iter()
            .map(|p| BinaryNode {
                tag: "participant".to_string(),
                attrs: BinaryNodeAttributes::from([("jid".to_string(), p.clone())]),
                content: None,
            })
            .collect();

        let result = self
            .community_query(
                jid,
                "set",
                vec![BinaryNode {
                    tag: action_str.to_string(),
                    attrs,
                    content: Some(BinaryNodeData::List(participant_nodes)),
                }],
            )
            .await?;

        let node = get_binary_node_child(Some(&result), action_str);
        Ok(get_binary_node_children(node, "participant")
            .into_iter()
            .map(|p| ParticipantUpdateResult {
                status: p
                    .attrs
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "200".to_string()),
                jid: p.attrs.get("jid").cloned(),
                content: p.clone(),
            })
            .collect())
    }

    pub async fn community_update_description(
        &self,
        jid: &str,
        description: Option<&str>,
    ) -> Result<(), CommunitiesError> {
        let metadata = self.community_metadata(jid).await?;
        let mut attrs = BinaryNodeAttributes::new();
        if description.is_some() {
            attrs.insert("id".to_string(), generate_message_id());
        } else {
            attrs.insert("delete".to_string(), "true".to_string());
        }
        if let Some(prev) = metadata.desc_id {
            attrs.insert("prev".to_string(), prev);
        }

        let content = description.map(|desc| {
            BinaryNodeData::List(vec![BinaryNode {
                tag: "body".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(desc.as_bytes().to_vec())),
            }])
        });

        self.community_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: "description".to_string(),
                attrs,
                content,
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_invite_code(
        &self,
        jid: &str,
    ) -> Result<Option<String>, CommunitiesError> {
        let result = self
            .community_query(
                jid,
                "get",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }],
            )
            .await?;
        Ok(get_binary_node_child(Some(&result), "invite").and_then(|n| n.attrs.get("code").cloned()))
    }

    pub async fn community_revoke_invite(
        &self,
        jid: &str,
    ) -> Result<Option<String>, CommunitiesError> {
        let result = self
            .community_query(
                jid,
                "set",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: None,
                }],
            )
            .await?;
        Ok(get_binary_node_child(Some(&result), "invite").and_then(|n| n.attrs.get("code").cloned()))
    }

    pub async fn community_accept_invite(
        &self,
        code: &str,
    ) -> Result<Option<String>, CommunitiesError> {
        let results = self
            .community_query(
                "@g.us",
                "set",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::from([("code".to_string(), code.to_string())]),
                    content: None,
                }],
            )
            .await?;
        Ok(get_binary_node_child(Some(&results), "community")
            .and_then(|n| n.attrs.get("jid").cloned()))
    }

    pub async fn community_revoke_invite_v4(
        &self,
        community_jid: &str,
        invited_jid: &str,
    ) -> Result<bool, CommunitiesError> {
        let _ = self
            .community_query(
                community_jid,
                "set",
                vec![BinaryNode {
                    tag: "revoke".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "participant".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "jid".to_string(),
                            invited_jid.to_string(),
                        )]),
                        content: None,
                    }])),
                }],
            )
            .await?;
        Ok(true)
    }

    pub async fn community_accept_invite_v4(
        &self,
        admin_jid: &str,
        invite_message: &GroupInviteMessage,
    ) -> Result<Option<String>, CommunitiesError> {
        let group_jid = invite_message
            .group_jid
            .as_deref()
            .ok_or(CommunitiesError::MissingInviteField("group_jid"))?;
        let invite_code = invite_message
            .invite_code
            .as_deref()
            .ok_or(CommunitiesError::MissingInviteField("invite_code"))?;
        let invite_expiration = invite_message
            .invite_expiration
            .ok_or(CommunitiesError::MissingInviteField("invite_expiration"))?;

        let results = self
            .community_query(
                group_jid,
                "set",
                vec![BinaryNode {
                    tag: "accept".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("code".to_string(), invite_code.to_string()),
                        ("expiration".to_string(), invite_expiration.to_string()),
                        ("admin".to_string(), admin_jid.to_string()),
                    ]),
                    content: None,
                }],
            )
            .await?;
        Ok(results.attrs.get("from").cloned())
    }

    pub async fn community_get_invite_info(
        &self,
        code: &str,
    ) -> Result<GroupMetadata, CommunitiesError> {
        let results = self
            .community_query(
                "@g.us",
                "get",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::from([("code".to_string(), code.to_string())]),
                    content: None,
                }],
            )
            .await?;
        extract_community_metadata(&results)
    }

    pub async fn community_toggle_ephemeral(
        &self,
        jid: &str,
        ephemeral_expiration: u32,
    ) -> Result<(), CommunitiesError> {
        let content = if ephemeral_expiration > 0 {
            BinaryNode {
                tag: "ephemeral".to_string(),
                attrs: BinaryNodeAttributes::from([(
                    "expiration".to_string(),
                    ephemeral_expiration.to_string(),
                )]),
                content: None,
            }
        } else {
            BinaryNode {
                tag: "not_ephemeral".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: None,
            }
        };
        self.community_query(jid, "set", vec![content]).await?;
        Ok(())
    }

    pub async fn community_setting_update(
        &self,
        jid: &str,
        setting: GroupSetting,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: setting.as_str().to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: None,
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_member_add_mode(
        &self,
        jid: &str,
        mode: MemberAddMode,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: "member_add_mode".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::String(mode.as_str().to_string())),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn community_join_approval_mode(
        &self,
        jid: &str,
        mode: JoinApprovalMode,
    ) -> Result<(), CommunitiesError> {
        self.community_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: "membership_approval_mode".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "community_join".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "state".to_string(),
                        mode.as_str().to_string(),
                    )]),
                    content: None,
                }])),
            }],
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_community_metadata() {
        let stanza = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "community".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("id".to_string(), "120363000777".to_string()),
                    ("subject".to_string(), "Comunidad Rust".to_string()),
                    ("creation".to_string(), "1700000000".to_string()),
                    ("creator".to_string(), "573001111111:1@s.whatsapp.net".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "parent".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: None,
                    },
                    BinaryNode {
                        tag: "addressing_mode".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::String("lid".to_string())),
                    },
                    BinaryNode {
                        tag: "description".to_string(),
                        attrs: BinaryNodeAttributes::from([("id".to_string(), "D1".to_string())]),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "body".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::String("Desc".to_string())),
                        }])),
                    },
                    BinaryNode {
                        tag: "participant".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("jid".to_string(), "573001111111@s.whatsapp.net".to_string()),
                            ("type".to_string(), "admin".to_string()),
                        ]),
                        content: None,
                    },
                ])),
            }])),
        };

        let meta = extract_community_metadata(&stanza).unwrap();
        assert_eq!(meta.id, "120363000777@g.us");
        assert!(meta.is_community);
        assert_eq!(meta.addressing_mode, WaMessageAddressingMode::Lid);
        assert_eq!(meta.desc.as_deref(), Some("Desc"));
        assert_eq!(meta.participants.len(), 1);
    }
}
