use super::socket::{SocketError, WaSocket};
use crate::proto::message::GroupInviteMessage;
use crate::types::{
    GroupMetadata, GroupParticipant, GroupRequestAction, GroupSetting, JoinApprovalMode,
    MemberAddMode, ParticipantAction, ParticipantUpdateResult, RequestParticipantUpdateResult,
    WaMessageAddressingMode,
};
use crate::utils::generate_message_id_v2;
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_child_string, get_binary_node_children, is_lid_user,
    is_pn_user, jid_encode, jid_normalized_user, BinaryNode, BinaryNodeAttributes, BinaryNodeData,
    JidServer,
};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupsError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("{text} (code {code})")]
    ServerError { code: u16, text: String },
    #[error("invalid group metadata response: missing <group> node")]
    MissingGroupNode,
    #[error("invalid group metadata response: missing group id")]
    MissingGroupId,
    #[error("missing required field in invite message: {0}")]
    MissingInviteField(&'static str),
}

pub fn extract_group_metadata(result: &BinaryNode) -> Result<GroupMetadata, GroupsError> {
    let Some(group) = get_binary_node_child(Some(result), "group") else {
        if let Some(error_node) = get_binary_node_child(Some(result), "error") {
            let code = error_node
                .attrs
                .get("code")
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(500);
            let text = error_node
                .attrs
                .get("text")
                .cloned()
                .unwrap_or_else(|| "group metadata query failed".to_string());
            return Err(GroupsError::ServerError { code, text });
        }
        return Err(GroupsError::MissingGroupNode);
    };

    let raw_id = group
        .attrs
        .get("id")
        .filter(|s| !s.is_empty())
        .ok_or(GroupsError::MissingGroupId)?;

    let group_id = if raw_id.contains('@') {
        raw_id.clone()
    } else {
        jid_encode(Some(raw_id), &JidServer::GUs, None, None)
    };

    let desc_child = get_binary_node_child(Some(group), "description");
    let (desc, desc_id, desc_owner, desc_owner_pn, desc_owner_username, desc_time) =
        if let Some(dc) = desc_child {
            (
                get_binary_node_child_string(Some(dc), "body"),
                dc.attrs.get("id").cloned(),
                dc.attrs
                    .get("participant")
                    .map(|p| jid_normalized_user(Some(p))),
                dc.attrs
                    .get("participant_pn")
                    .map(|p| jid_normalized_user(Some(p))),
                dc.attrs
                    .get("participant_username")
                    .filter(|s| !s.is_empty())
                    .cloned(),
                dc.attrs.get("t").and_then(|t| t.parse::<u64>().ok()),
            )
        } else {
            (None, None, None, None, None, None)
        };

    let participant_nodes = get_binary_node_children(Some(group), "participant");
    let participants: Vec<GroupParticipant> = participant_nodes
        .iter()
        .filter_map(|node| {
            let jid = node.attrs.get("jid")?.clone();
            let phone_number = node
                .attrs
                .get("phone_number")
                .filter(|pn| is_lid_user(Some(&jid)) && is_pn_user(Some(pn)))
                .cloned();
            let lid = node
                .attrs
                .get("lid")
                .filter(|l| is_pn_user(Some(&jid)) && is_lid_user(Some(l)))
                .cloned();
            let username = node
                .attrs
                .get("participant_username")
                .or_else(|| node.attrs.get("username"))
                .filter(|s| !s.is_empty())
                .cloned();
            let admin = node
                .attrs
                .get("type")
                .filter(|s| !s.is_empty())
                .cloned();

            Some(GroupParticipant {
                id: jid,
                phone_number,
                lid,
                username,
                admin,
            })
        })
        .collect();

    let size = group
        .attrs
        .get("size")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(participants.len());

    let addressing_mode = if group.attrs.get("addressing_mode").map(|s| s.as_str()) == Some("lid") {
        WaMessageAddressingMode::Lid
    } else {
        WaMessageAddressingMode::Pn
    };

    let ephemeral_duration = get_binary_node_child(Some(group), "ephemeral")
        .and_then(|e| e.attrs.get("expiration"))
        .and_then(|v| v.parse::<u32>().ok());

    let member_add_mode =
        get_binary_node_child_string(Some(group), "member_add_mode").as_deref()
            == Some("all_member_add");

    Ok(GroupMetadata {
        id: group_id,
        notify: group.attrs.get("notify").cloned(),
        addressing_mode,
        subject: group.attrs.get("subject").cloned().unwrap_or_default(),
        subject_owner: group.attrs.get("s_o").cloned(),
        subject_owner_pn: group.attrs.get("s_o_pn").cloned(),
        subject_owner_username: group.attrs.get("s_o_username").cloned(),
        subject_time: group.attrs.get("s_t").and_then(|v| v.parse::<u64>().ok()),
        size,
        creation: group
            .attrs
            .get("creation")
            .and_then(|v| v.parse::<u64>().ok()),
        owner: group
            .attrs
            .get("creator")
            .map(|c| jid_normalized_user(Some(c))),
        owner_pn: group
            .attrs
            .get("creator_pn")
            .map(|c| jid_normalized_user(Some(c))),
        owner_username: group
            .attrs
            .get("creator_username")
            .filter(|s| !s.is_empty())
            .cloned(),
        owner_country_code: group.attrs.get("creator_country_code").cloned(),
        desc,
        desc_id,
        desc_owner,
        desc_owner_pn,
        desc_owner_username,
        desc_time,
        linked_parent: get_binary_node_child(Some(group), "linked_parent")
            .and_then(|n| n.attrs.get("jid"))
            .filter(|s| !s.is_empty())
            .cloned(),
        restrict: get_binary_node_child(Some(group), "locked").is_some(),
        announce: get_binary_node_child(Some(group), "announcement").is_some(),
        is_community: get_binary_node_child(Some(group), "parent").is_some(),
        is_community_announce: get_binary_node_child(Some(group), "default_sub_group").is_some(),
        join_approval_mode: get_binary_node_child(Some(group), "membership_approval_mode")
            .is_some(),
        member_add_mode,
        participants,
        ephemeral_duration,
    })
}

impl WaSocket {
    async fn group_query(
        &self,
        jid: &str,
        iq_type: &str,
        content: Vec<BinaryNode>,
    ) -> Result<BinaryNode, GroupsError> {
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

    pub async fn group_metadata(&self, jid: &str) -> Result<GroupMetadata, GroupsError> {
        let result = self
            .group_query(
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
        extract_group_metadata(&result)
    }

    pub async fn group_fetch_all_participating(
        &self,
    ) -> Result<HashMap<String, GroupMetadata>, GroupsError> {
        let result = self
            .group_query(
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
        if let Some(groups_child) = get_binary_node_child(Some(&result), "groups") {
            for group_node in get_binary_node_children(Some(groups_child), "group") {
                let wrapper = BinaryNode {
                    tag: "result".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![group_node.clone()])),
                };
                if let Ok(meta) = extract_group_metadata(&wrapper) {
                    data.insert(meta.id.clone(), meta);
                }
            }
        }

        Ok(data)
    }

    pub async fn group_create(
        &self,
        subject: &str,
        participants: &[String],
    ) -> Result<GroupMetadata, GroupsError> {
        let key = generate_message_id_v2(None);
        let participant_nodes: Vec<BinaryNode> = participants
            .iter()
            .map(|jid| BinaryNode {
                tag: "participant".to_string(),
                attrs: BinaryNodeAttributes::from([("jid".to_string(), jid.clone())]),
                content: None,
            })
            .collect();

        let result = self
            .group_query(
                "@g.us",
                "set",
                vec![BinaryNode {
                    tag: "create".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("subject".to_string(), subject.to_string()),
                        ("key".to_string(), key),
                    ]),
                    content: Some(BinaryNodeData::List(participant_nodes)),
                }],
            )
            .await?;

        extract_group_metadata(&result)
    }

    pub async fn group_leave(&self, id: &str) -> Result<(), GroupsError> {
        self.group_query(
            "@g.us",
            "set",
            vec![BinaryNode {
                tag: "leave".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "group".to_string(),
                    attrs: BinaryNodeAttributes::from([("id".to_string(), id.to_string())]),
                    content: None,
                }])),
            }],
        )
        .await?;
        Ok(())
    }

    pub async fn group_update_subject(&self, jid: &str, subject: &str) -> Result<(), GroupsError> {
        self.group_query(
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

    pub async fn group_request_participants_list(
        &self,
        jid: &str,
    ) -> Result<Vec<BinaryNodeAttributes>, GroupsError> {
        let result = self
            .group_query(
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
        let list = get_binary_node_children(node, "membership_approval_request")
            .into_iter()
            .map(|n| n.attrs.clone())
            .collect();
        Ok(list)
    }

    pub async fn group_request_participants_update(
        &self,
        jid: &str,
        participants: &[String],
        action: GroupRequestAction,
    ) -> Result<Vec<RequestParticipantUpdateResult>, GroupsError> {
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
            .group_query(
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
        let affected = get_binary_node_children(node_action, "participant")
            .into_iter()
            .map(|p| RequestParticipantUpdateResult {
                status: p
                    .attrs
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "200".to_string()),
                jid: p.attrs.get("jid").cloned(),
            })
            .collect();
        Ok(affected)
    }

    pub async fn group_participants_update(
        &self,
        jid: &str,
        participants: &[String],
        action: ParticipantAction,
    ) -> Result<Vec<ParticipantUpdateResult>, GroupsError> {
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
            .group_query(
                jid,
                "set",
                vec![BinaryNode {
                    tag: action_str.to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(participant_nodes)),
                }],
            )
            .await?;

        let node = get_binary_node_child(Some(&result), action_str);
        let affected = get_binary_node_children(node, "participant")
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
            .collect();
        Ok(affected)
    }

    pub async fn group_update_description(
        &self,
        jid: &str,
        description: Option<&str>,
    ) -> Result<(), GroupsError> {
        let metadata = self.group_metadata(jid).await?;
        let mut attrs = BinaryNodeAttributes::new();
        if description.is_some() {
            attrs.insert("id".to_string(), generate_message_id_v2(None));
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

        self.group_query(
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

    pub async fn group_invite_code(&self, jid: &str) -> Result<Option<String>, GroupsError> {
        let result = self
            .group_query(
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

    pub async fn group_revoke_invite(&self, jid: &str) -> Result<Option<String>, GroupsError> {
        let result = self
            .group_query(
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

    pub async fn group_accept_invite(&self, code: &str) -> Result<Option<String>, GroupsError> {
        let results = self
            .group_query(
                "@g.us",
                "set",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::from([("code".to_string(), code.to_string())]),
                    content: None,
                }],
            )
            .await?;
        Ok(get_binary_node_child(Some(&results), "group").and_then(|n| n.attrs.get("jid").cloned()))
    }

    pub async fn group_revoke_invite_v4(
        &self,
        group_jid: &str,
        invited_jid: &str,
    ) -> Result<bool, GroupsError> {
        let _ = self
            .group_query(
                group_jid,
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

    pub async fn group_accept_invite_v4(
        &self,
        admin_jid: &str,
        invite_message: &GroupInviteMessage,
    ) -> Result<Option<String>, GroupsError> {
        let group_jid = invite_message
            .group_jid
            .as_deref()
            .ok_or(GroupsError::MissingInviteField("group_jid"))?;
        let invite_code = invite_message
            .invite_code
            .as_deref()
            .ok_or(GroupsError::MissingInviteField("invite_code"))?;
        let invite_expiration = invite_message
            .invite_expiration
            .ok_or(GroupsError::MissingInviteField("invite_expiration"))?;

        let results = self
            .group_query(
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

    pub async fn group_get_invite_info(&self, code: &str) -> Result<GroupMetadata, GroupsError> {
        let results = self
            .group_query(
                "@g.us",
                "get",
                vec![BinaryNode {
                    tag: "invite".to_string(),
                    attrs: BinaryNodeAttributes::from([("code".to_string(), code.to_string())]),
                    content: None,
                }],
            )
            .await?;
        extract_group_metadata(&results)
    }

    pub async fn group_toggle_ephemeral(
        &self,
        jid: &str,
        ephemeral_expiration: u32,
    ) -> Result<(), GroupsError> {
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
        self.group_query(jid, "set", vec![content]).await?;
        Ok(())
    }

    pub async fn group_setting_update(
        &self,
        jid: &str,
        setting: GroupSetting,
    ) -> Result<(), GroupsError> {
        self.group_query(
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

    pub async fn group_member_add_mode(
        &self,
        jid: &str,
        mode: MemberAddMode,
    ) -> Result<(), GroupsError> {
        self.group_query(
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

    pub async fn group_join_approval_mode(
        &self,
        jid: &str,
        mode: JoinApprovalMode,
    ) -> Result<(), GroupsError> {
        self.group_query(
            jid,
            "set",
            vec![BinaryNode {
                tag: "membership_approval_mode".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "group_join".to_string(),
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
    fn test_extract_group_metadata_full() {
        let stanza = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([("type".to_string(), "result".to_string())]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "group".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("id".to_string(), "12036300012345".to_string()),
                    ("subject".to_string(), "Baileys Rust".to_string()),
                    ("addressing_mode".to_string(), "lid".to_string()),
                    ("creation".to_string(), "1700000000".to_string()),
                    ("s_t".to_string(), "1700000100".to_string()),
                    ("creator".to_string(), "573001111111:1@s.whatsapp.net".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![
                    BinaryNode {
                        tag: "description".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("id".to_string(), "DESC1".to_string()),
                            ("t".to_string(), "1700000200".to_string()),
                        ]),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "body".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::String("Grupo oficial".to_string())),
                        }])),
                    },
                    BinaryNode {
                        tag: "ephemeral".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "expiration".to_string(),
                            "86400".to_string(),
                        )]),
                        content: None,
                    },
                    BinaryNode {
                        tag: "locked".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: None,
                    },
                    BinaryNode {
                        tag: "member_add_mode".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::String("all_member_add".to_string())),
                    },
                    BinaryNode {
                        tag: "participant".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("jid".to_string(), "123456@lid".to_string()),
                            ("phone_number".to_string(), "573001111111@s.whatsapp.net".to_string()),
                            ("type".to_string(), "superadmin".to_string()),
                        ]),
                        content: None,
                    },
                ])),
            }])),
        };

        let meta = extract_group_metadata(&stanza).unwrap();
        assert_eq!(meta.id, "12036300012345@g.us");
        assert_eq!(meta.subject, "Baileys Rust");
        assert_eq!(meta.addressing_mode, WaMessageAddressingMode::Lid);
        assert_eq!(meta.desc.as_deref(), Some("Grupo oficial"));
        assert_eq!(meta.desc_id.as_deref(), Some("DESC1"));
        assert_eq!(meta.ephemeral_duration, Some(86400));
        assert!(meta.restrict);
        assert!(meta.member_add_mode);
        assert_eq!(meta.participants.len(), 1);
        assert_eq!(meta.participants[0].admin.as_deref(), Some("superadmin"));
        assert_eq!(
            meta.participants[0].phone_number.as_deref(),
            Some("573001111111@s.whatsapp.net")
        );
    }

    #[test]
    fn test_extract_group_metadata_error_node() {
        let stanza = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "error".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("code".to_string(), "404".to_string()),
                    ("text".to_string(), "item-not-found".to_string()),
                ]),
                content: None,
            }])),
        };

        let err = extract_group_metadata(&stanza).unwrap_err();
        match err {
            GroupsError::ServerError { code, text } => {
                assert_eq!(code, 404);
                assert_eq!(text, "item-not-found");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
