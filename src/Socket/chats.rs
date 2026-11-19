use super::socket::{SocketError, WaSocket};
use crate::signal::LidMappingStore;
use crate::types::{
    BlockAction, BotListInfo, CallLinkMedia, DirtyBitsType, PresenceData, PresenceUpdate,
    ProfilePictureType, ServerProps, WaBusinessHoursConfig, WaBusinessHoursInfo, WaBusinessProfile,
    WaPresence, WaPrivacyCallValue, WaPrivacyGroupAddValue, WaPrivacyMessagesValue,
    WaPrivacyOnlineValue, WaPrivacyValue, WaReadReceiptsValue,
};
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_children, is_hosted_lid_user, is_hosted_pn_user,
    is_lid_user, is_pn_user, jid_decode, jid_normalized_user, reduce_binary_node_to_dictionary,
    BinaryNode, BinaryNodeAttributes, BinaryNodeData, JidServer, S_WHATSAPP_NET,
};
use crate::wa_usync::{USyncQuery, USyncQueryResultList, USyncUser};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChatsError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("not authenticated: missing own jid")]
    NotAuthenticated,
    #[error("illegal empty jid for profile update")]
    EmptyProfileJid,
    #[error("invalid jid: {0}")]
    InvalidJid(String),
    #[error("unable to resolve PN JID for LID: {0}")]
    UnableToResolvePn(String),
    #[error("unable to resolve LID for PN JID: {0}")]
    UnableToResolveLid(String),
    #[error("missing destination jid for chatstate presence")]
    MissingPresenceTarget,
    #[error("missing own lid for lid chatstate presence")]
    MissingOwnLid,
}

fn node_content_to_string(node: Option<&BinaryNode>) -> Option<String> {
    match node?.content.as_ref()? {
        BinaryNodeData::String(s) => Some(s.clone()),
        BinaryNodeData::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
        BinaryNodeData::List(_) => None,
    }
}

pub fn build_profile_picture_query_content(
    pic_type: ProfilePictureType,
    tc_token_content: Option<Vec<BinaryNode>>,
) -> Vec<BinaryNode> {
    let content = tc_token_content
        .filter(|list| !list.is_empty())
        .map(BinaryNodeData::List);
    vec![BinaryNode {
        tag: "picture".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("type".to_string(), pic_type.as_str().to_string()),
            ("query".to_string(), "url".to_string()),
        ]),
        content,
    }]
}

pub fn parse_bot_list_v2_node(resp: &BinaryNode) -> Vec<BotListInfo> {
    let bot_node = get_binary_node_child(Some(resp), "bot");
    let mut bot_list = Vec::new();
    for section in get_binary_node_children(bot_node, "section") {
        if section.attrs.get("type").map(|s| s.as_str()) == Some("all") {
            for bot in get_binary_node_children(Some(section), "bot") {
                if let (Some(jid), Some(persona_id)) = (
                    bot.attrs.get("jid").cloned(),
                    bot.attrs.get("persona_id").cloned(),
                ) {
                    bot_list.push(BotListInfo { jid, persona_id });
                }
            }
        }
    }
    bot_list
}

pub fn parse_business_profile_node(results: &BinaryNode) -> Option<WaBusinessProfile> {
    let profile_node = get_binary_node_child(Some(results), "business_profile");
    let profile = get_binary_node_child(profile_node, "profile")?;

    let address = node_content_to_string(get_binary_node_child(Some(profile), "address"));
    let description =
        node_content_to_string(get_binary_node_child(Some(profile), "description"))
            .unwrap_or_default();
    let website = node_content_to_string(get_binary_node_child(Some(profile), "website"))
        .map(|w| vec![w])
        .unwrap_or_default();
    let email = node_content_to_string(get_binary_node_child(Some(profile), "email"));
    let categories_node = get_binary_node_child(Some(profile), "categories");
    let category = node_content_to_string(get_binary_node_child(categories_node, "category"));

    let business_hours_node = get_binary_node_child(Some(profile), "business_hours");
    let business_config = get_binary_node_children(business_hours_node, "business_hours_config")
        .into_iter()
        .map(|node| WaBusinessHoursConfig {
            day_of_week: node.attrs.get("day_of_week").cloned().unwrap_or_default(),
            mode: node.attrs.get("mode").cloned().unwrap_or_default(),
            open_time: node.attrs.get("open_time").cloned(),
            close_time: node.attrs.get("close_time").cloned(),
        })
        .collect();

    Some(WaBusinessProfile {
        wid: profile.attrs.get("jid").cloned(),
        address,
        description,
        website,
        email,
        category,
        business_hours: WaBusinessHoursInfo {
            timezone: business_hours_node.and_then(|n| n.attrs.get("timezone").cloned()),
            business_config,
        },
    })
}

pub fn parse_presence_update(node: &BinaryNode) -> Option<PresenceUpdate> {
    let jid = node.attrs.get("from")?.clone();
    let participant = node
        .attrs
        .get("participant")
        .cloned()
        .unwrap_or_else(|| jid.clone());

    let presence = if node.tag == "presence" {
        let last_known_presence = if node.attrs.get("type").map(|s| s.as_str()) == Some("unavailable") {
            WaPresence::Unavailable
        } else {
            WaPresence::Available
        };
        let last_seen = node
            .attrs
            .get("last")
            .filter(|v| v.as_str() != "deny")
            .and_then(|v| v.parse::<u64>().ok());
        let group_online_count = node
            .attrs
            .get("count")
            .and_then(|v| v.parse::<u32>().ok());
        Some(PresenceData {
            last_known_presence,
            last_seen,
            group_online_count,
        })
    } else if let Some(BinaryNodeData::List(children)) = &node.content {
        let first = children.first()?;
        let last_known_presence = if first.attrs.get("media").map(|s| s.as_str()) == Some("audio") {
            WaPresence::Recording
        } else {
            match first.tag.as_str() {
                "composing" => WaPresence::Composing,
                "recording" => WaPresence::Recording,
                "paused" => WaPresence::Available,
                "unavailable" => WaPresence::Unavailable,
                _ => WaPresence::Available,
            }
        };
        Some(PresenceData {
            last_known_presence,
            last_seen: None,
            group_online_count: None,
        })
    } else {
        None
    }?;

    let mut presences = HashMap::new();
    presences.insert(participant, presence);

    Some(PresenceUpdate { id: jid, presences })
}

pub fn apply_ab_props(props: &HashMap<String, String>, server_props: &mut ServerProps) {
    if let Some(val) = props
        .get("10518")
        .or_else(|| props.get("privacy_token_sending_on_all_1_on_1_messages"))
    {
        server_props.privacy_token_on_1to1 = val == "true" || val == "1";
    }
    if let Some(val) = props
        .get("9666")
        .or_else(|| props.get("profile_scraping_privacy_token_in_photo_iq"))
    {
        server_props.profile_pic_privacy_token = val == "true" || val == "1";
    }
    if let Some(val) = props
        .get("14303")
        .or_else(|| props.get("lid_trusted_token_issue_to_lid"))
    {
        server_props.lid_trusted_token_issue_to_lid = val == "true" || val == "1";
    }
}

impl WaSocket {
    pub async fn fetch_privacy_settings(&self) -> Result<HashMap<String, String>, ChatsError> {
        let res = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("xmlns".to_string(), "privacy".to_string()),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "privacy".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: None,
                    }])),
                },
                None,
            )
            .await?;

        if let Some(BinaryNodeData::List(children)) = &res.content {
            if let Some(first) = children.first() {
                return Ok(reduce_binary_node_to_dictionary(first, "category"));
            }
        }
        Ok(HashMap::new())
    }

    async fn privacy_query(&self, name: &str, value: &str) -> Result<(), ChatsError> {
        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("xmlns".to_string(), "privacy".to_string()),
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "privacy".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "category".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("name".to_string(), name.to_string()),
                            ("value".to_string(), value.to_string()),
                        ]),
                        content: None,
                    }])),
                }])),
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn update_messages_privacy(
        &self,
        value: WaPrivacyMessagesValue,
    ) -> Result<(), ChatsError> {
        self.privacy_query("messages", value.as_str()).await
    }

    pub async fn update_call_privacy(&self, value: WaPrivacyCallValue) -> Result<(), ChatsError> {
        self.privacy_query("calladd", value.as_str()).await
    }

    pub async fn update_last_seen_privacy(&self, value: WaPrivacyValue) -> Result<(), ChatsError> {
        self.privacy_query("last", value.as_str()).await
    }

    pub async fn update_online_privacy(
        &self,
        value: WaPrivacyOnlineValue,
    ) -> Result<(), ChatsError> {
        self.privacy_query("online", value.as_str()).await
    }

    pub async fn update_profile_picture_privacy(
        &self,
        value: WaPrivacyValue,
    ) -> Result<(), ChatsError> {
        self.privacy_query("profile", value.as_str()).await
    }

    pub async fn update_status_privacy(&self, value: WaPrivacyValue) -> Result<(), ChatsError> {
        self.privacy_query("status", value.as_str()).await
    }

    pub async fn update_read_receipts_privacy(
        &self,
        value: WaReadReceiptsValue,
    ) -> Result<(), ChatsError> {
        self.privacy_query("readreceipts", value.as_str()).await
    }

    pub async fn update_groups_add_privacy(
        &self,
        value: WaPrivacyGroupAddValue,
    ) -> Result<(), ChatsError> {
        self.privacy_query("groupadd", value.as_str()).await
    }

    pub async fn update_default_disappearing_mode(&self, duration: u32) -> Result<(), ChatsError> {
        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("xmlns".to_string(), "disappearing_mode".to_string()),
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "disappearing_mode".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "duration".to_string(),
                        duration.to_string(),
                    )]),
                    content: None,
                }])),
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn get_bot_list_v2(&self) -> Result<Vec<BotListInfo>, ChatsError> {
        let resp = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("xmlns".to_string(), "bot".to_string()),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "bot".to_string(),
                        attrs: BinaryNodeAttributes::from([("v".to_string(), "2".to_string())]),
                        content: None,
                    }])),
                },
                None,
            )
            .await?;

        Ok(parse_bot_list_v2_node(&resp))
    }

    pub async fn fetch_status(
        &self,
        jids: &[String],
    ) -> Result<Option<Vec<USyncQueryResultList>>, ChatsError> {
        let mut usync_query = USyncQuery::new().with_status_protocol();
        for jid in jids {
            usync_query = usync_query.with_user(USyncUser::new().with_id(jid.clone()));
        }
        Ok(self.execute_usync_query(&usync_query).await?.map(|r| r.list))
    }

    pub async fn fetch_disappearing_duration(
        &self,
        jids: &[String],
    ) -> Result<Option<Vec<USyncQueryResultList>>, ChatsError> {
        let mut usync_query = USyncQuery::new().with_disappearing_mode_protocol();
        for jid in jids {
            usync_query = usync_query.with_user(USyncUser::new().with_id(jid.clone()));
        }
        Ok(self.execute_usync_query(&usync_query).await?.map(|r| r.list))
    }

    pub async fn update_profile_picture_bytes(
        &self,
        jid: &str,
        jpeg_bytes: Vec<u8>,
    ) -> Result<(), ChatsError> {
        if jid.is_empty() {
            return Err(ChatsError::EmptyProfileJid);
        }
        let creds = self.creds().await;
        let me_id = creds
            .me
            .as_ref()
            .map(|m| m.id.as_str())
            .ok_or(ChatsError::NotAuthenticated)?;

        let norm_target = jid_normalized_user(Some(jid));
        let norm_me = jid_normalized_user(Some(me_id));

        let mut attrs = BinaryNodeAttributes::from([
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:profile:picture".to_string()),
        ]);
        if norm_target != norm_me {
            attrs.insert("target".to_string(), norm_target);
        }

        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs,
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "picture".to_string(),
                    attrs: BinaryNodeAttributes::from([("type".to_string(), "image".to_string())]),
                    content: Some(BinaryNodeData::Bytes(jpeg_bytes)),
                }])),
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn remove_profile_picture(&self, jid: &str) -> Result<(), ChatsError> {
        if jid.is_empty() {
            return Err(ChatsError::EmptyProfileJid);
        }
        let creds = self.creds().await;
        let me_id = creds
            .me
            .as_ref()
            .map(|m| m.id.as_str())
            .ok_or(ChatsError::NotAuthenticated)?;

        let norm_target = jid_normalized_user(Some(jid));
        let norm_me = jid_normalized_user(Some(me_id));

        let mut attrs = BinaryNodeAttributes::from([
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
            ("type".to_string(), "set".to_string()),
            ("xmlns".to_string(), "w:profile:picture".to_string()),
        ]);
        if norm_target != norm_me {
            attrs.insert("target".to_string(), norm_target);
        }

        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs,
                content: None,
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn update_profile_status(&self, status: &str) -> Result<(), ChatsError> {
        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                    ("xmlns".to_string(), "status".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "status".to_string(),
                    attrs: BinaryNodeAttributes::new(),
                    content: Some(BinaryNodeData::Bytes(status.as_bytes().to_vec())),
                }])),
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn fetch_blocklist(&self) -> Result<Vec<String>, ChatsError> {
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("xmlns".to_string(), "blocklist".to_string()),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                    ]),
                    content: None,
                },
                None,
            )
            .await?;

        let list_node = get_binary_node_child(Some(&result), "list");
        Ok(get_binary_node_children(list_node, "item")
            .into_iter()
            .filter_map(|n| n.attrs.get("jid").cloned())
            .collect())
    }

    pub async fn update_block_status(
        &self,
        jid: &str,
        action: BlockAction,
        lid_mapping: &LidMappingStore,
    ) -> Result<(), ChatsError> {
        let normalized_jid = jid_normalized_user(Some(jid));
        let lid: String;
        let mut pn_jid: Option<String> = None;

        if is_lid_user(Some(&normalized_jid)) || is_hosted_lid_user(Some(&normalized_jid)) {
            lid = normalized_jid.clone();
            if action == BlockAction::Block {
                let pn = lid_mapping
                    .get_pn_for_lid(&normalized_jid)
                    .await
                    .ok_or_else(|| ChatsError::UnableToResolvePn(jid.to_string()))?;
                pn_jid = Some(jid_normalized_user(Some(&pn)));
            }
        } else if is_pn_user(Some(&normalized_jid)) || is_hosted_pn_user(Some(&normalized_jid)) {
            lid = lid_mapping
                .get_lid_for_pn(&normalized_jid)
                .await
                .ok_or_else(|| ChatsError::UnableToResolveLid(jid.to_string()))?;
            if action == BlockAction::Block {
                pn_jid = Some(normalized_jid);
            }
        } else {
            return Err(ChatsError::InvalidJid(jid.to_string()));
        }

        let mut item_attrs = BinaryNodeAttributes::from([
            ("action".to_string(), action.as_str().to_string()),
            ("jid".to_string(), lid),
        ]);
        if action == BlockAction::Block {
            let resolved_pn =
                pn_jid.ok_or_else(|| ChatsError::UnableToResolvePn(jid.to_string()))?;
            item_attrs.insert("pn_jid".to_string(), resolved_pn);
        }

        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("xmlns".to_string(), "blocklist".to_string()),
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("type".to_string(), "set".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "item".to_string(),
                    attrs: item_attrs,
                    content: None,
                }])),
            },
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn get_business_profile(
        &self,
        jid: &str,
    ) -> Result<Option<WaBusinessProfile>, ChatsError> {
        let results = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("xmlns".to_string(), "w:biz".to_string()),
                        ("type".to_string(), "get".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "business_profile".to_string(),
                        attrs: BinaryNodeAttributes::from([("v".to_string(), "244".to_string())]),
                        content: Some(BinaryNodeData::List(vec![BinaryNode {
                            tag: "profile".to_string(),
                            attrs: BinaryNodeAttributes::from([("jid".to_string(), jid.to_string())]),
                            content: None,
                        }])),
                    }])),
                },
                None,
            )
            .await?;

        Ok(parse_business_profile_node(&results))
    }

    pub fn clean_dirty_bits(
        &self,
        dirty_type: DirtyBitsType,
        from_timestamp: Option<&str>,
    ) -> Result<(), ChatsError> {
        let mut clean_attrs =
            BinaryNodeAttributes::from([("type".to_string(), dirty_type.as_str().to_string())]);
        if let Some(ts) = from_timestamp {
            clean_attrs.insert("timestamp".to_string(), ts.to_string());
        }

        self.send_node(&BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("to".to_string(), S_WHATSAPP_NET.to_string()),
                ("type".to_string(), "set".to_string()),
                ("xmlns".to_string(), "urn:xmpp:whatsapp:dirty".to_string()),
                ("id".to_string(), self.generate_message_tag()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "clean".to_string(),
                attrs: clean_attrs,
                content: None,
            }])),
        })?;
        Ok(())
    }

    pub async fn profile_picture_url(
        &self,
        jid: &str,
        pic_type: ProfilePictureType,
        tc_token_content: Option<Vec<BinaryNode>>,
        timeout_ms: Option<u64>,
    ) -> Result<Option<String>, ChatsError> {
        let normalized = jid_normalized_user(Some(jid));
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("target".to_string(), normalized),
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("type".to_string(), "get".to_string()),
                        ("xmlns".to_string(), "w:profile:picture".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(build_profile_picture_query_content(
                        pic_type,
                        tc_token_content,
                    ))),
                },
                timeout_ms,
            )
            .await?;

        Ok(get_binary_node_child(Some(&result), "picture")
            .and_then(|c| c.attrs.get("url").cloned()))
    }

    pub async fn create_call_link(
        &self,
        media: CallLinkMedia,
        start_time: Option<u64>,
        timeout_ms: Option<u64>,
    ) -> Result<Option<String>, ChatsError> {
        let event_content = start_time.map(|st| {
            BinaryNodeData::List(vec![BinaryNode {
                tag: "event".to_string(),
                attrs: BinaryNodeAttributes::from([("start_time".to_string(), st.to_string())]),
                content: None,
            }])
        });

        let result = self
            .query(
                BinaryNode {
                    tag: "call".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("id".to_string(), self.generate_message_tag()),
                        ("to".to_string(), "@call".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "link_create".to_string(),
                        attrs: BinaryNodeAttributes::from([(
                            "media".to_string(),
                            media.as_str().to_string(),
                        )]),
                        content: event_content,
                    }])),
                },
                timeout_ms,
            )
            .await?;

        Ok(get_binary_node_child(Some(&result), "link_create")
            .and_then(|c| c.attrs.get("token").cloned()))
    }

    pub async fn send_presence_update(
        &self,
        presence: WaPresence,
        to_jid: Option<&str>,
    ) -> Result<(), ChatsError> {
        let creds = self.creds().await;
        let me = creds.me.as_ref().ok_or(ChatsError::NotAuthenticated)?;

        if matches!(presence, WaPresence::Available | WaPresence::Unavailable) {
            let Some(ref name) = me.name else {
                return Ok(());
            };
            if presence == WaPresence::Available {
                let _ = self.send_unified_session();
            }
            self.send_node(&BinaryNode {
                tag: "presence".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("name".to_string(), name.replace('@', "")),
                    ("type".to_string(), presence.as_str().to_string()),
                ]),
                content: None,
            })?;
            return Ok(());
        }

        let target = to_jid.ok_or(ChatsError::MissingPresenceTarget)?;
        let decoded =
            jid_decode(target).ok_or_else(|| ChatsError::InvalidJid(target.to_string()))?;
        let from_jid = if decoded.server == JidServer::Lid {
            me.lid
                .as_deref()
                .ok_or(ChatsError::MissingOwnLid)?
                .to_string()
        } else {
            me.id.clone()
        };

        let (child_tag, child_attrs) = if presence == WaPresence::Recording {
            (
                "composing".to_string(),
                BinaryNodeAttributes::from([("media".to_string(), "audio".to_string())]),
            )
        } else {
            (presence.as_str().to_string(), BinaryNodeAttributes::new())
        };

        self.send_node(&BinaryNode {
            tag: "chatstate".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), from_jid),
                ("to".to_string(), target.to_string()),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: child_tag,
                attrs: child_attrs,
                content: None,
            }])),
        })?;
        Ok(())
    }

    pub fn presence_subscribe(
        &self,
        to_jid: &str,
        tc_token_content: Option<Vec<BinaryNode>>,
    ) -> Result<(), ChatsError> {
        let content = tc_token_content
            .filter(|list| !list.is_empty())
            .map(BinaryNodeData::List);
        self.send_node(&BinaryNode {
            tag: "presence".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("to".to_string(), to_jid.to_string()),
                ("id".to_string(), self.generate_message_tag()),
                ("type".to_string(), "subscribe".to_string()),
            ]),
            content,
        })?;
        Ok(())
    }

    pub async fn fetch_props(
        &self,
        last_prop_hash: Option<&str>,
    ) -> Result<(HashMap<String, String>, Option<String>), ChatsError> {
        let mut props_attrs =
            BinaryNodeAttributes::from([("protocol".to_string(), "1".to_string())]);
        if let Some(hash) = last_prop_hash {
            props_attrs.insert("hash".to_string(), hash.to_string());
        }

        let result_node = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("to".to_string(), S_WHATSAPP_NET.to_string()),
                        ("xmlns".to_string(), "abt".to_string()),
                        ("type".to_string(), "get".to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "props".to_string(),
                        attrs: props_attrs,
                        content: None,
                    }])),
                },
                None,
            )
            .await?;

        let Some(props_node) = get_binary_node_child(Some(&result_node), "props") else {
            return Ok((HashMap::new(), None));
        };

        let new_hash = props_node.attrs.get("hash").cloned();
        let props = reduce_binary_node_to_dictionary(props_node, "prop");
        Ok((props, new_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_picture_query_content() {
        let simple = build_profile_picture_query_content(ProfilePictureType::Preview, None);
        assert_eq!(simple.len(), 1);
        assert_eq!(simple[0].tag, "picture");
        assert_eq!(
            simple[0].attrs.get("type").map(|s| s.as_str()),
            Some("preview")
        );
        assert!(simple[0].content.is_none());

        let token = BinaryNode {
            tag: "tctoken".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::Bytes(vec![1, 2, 3])),
        };
        let with_token =
            build_profile_picture_query_content(ProfilePictureType::Image, Some(vec![token]));
        assert!(with_token[0].content.is_some());
    }

    #[test]
    fn test_parse_presence_and_chatstate() {
        let presence_node = BinaryNode {
            tag: "presence".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), "573001111111@s.whatsapp.net".to_string()),
                ("type".to_string(), "unavailable".to_string()),
                ("last".to_string(), "1700000000".to_string()),
            ]),
            content: None,
        };
        let parsed = parse_presence_update(&presence_node).unwrap();
        assert_eq!(parsed.id, "573001111111@s.whatsapp.net");
        let data = parsed.presences.get("573001111111@s.whatsapp.net").unwrap();
        assert_eq!(data.last_known_presence, WaPresence::Unavailable);
        assert_eq!(data.last_seen, Some(1700000000));

        let recording_node = BinaryNode {
            tag: "chatstate".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("from".to_string(), "1203630001@g.us".to_string()),
                (
                    "participant".to_string(),
                    "573002222222@s.whatsapp.net".to_string(),
                ),
            ]),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "composing".to_string(),
                attrs: BinaryNodeAttributes::from([("media".to_string(), "audio".to_string())]),
                content: None,
            }])),
        };
        let parsed_rec = parse_presence_update(&recording_node).unwrap();
        assert_eq!(
            parsed_rec
                .presences
                .get("573002222222@s.whatsapp.net")
                .unwrap()
                .last_known_presence,
            WaPresence::Recording
        );
    }

    #[test]
    fn test_parse_business_profile_bot_list_and_ab_props() {
        let biz_resp = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "business_profile".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "profile".to_string(),
                    attrs: BinaryNodeAttributes::from([(
                        "jid".to_string(),
                        "573001111111@s.whatsapp.net".to_string(),
                    )]),
                    content: Some(BinaryNodeData::List(vec![
                        BinaryNode {
                            tag: "description".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::String("Tienda oficial".to_string())),
                        },
                        BinaryNode {
                            tag: "website".to_string(),
                            attrs: BinaryNodeAttributes::new(),
                            content: Some(BinaryNodeData::String("https://lufer.dev".to_string())),
                        },
                    ])),
                }])),
            }])),
        };
        let profile = parse_business_profile_node(&biz_resp).unwrap();
        assert_eq!(profile.description, "Tienda oficial");
        assert_eq!(profile.website, vec!["https://lufer.dev"]);

        let bot_resp = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "bot".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "section".to_string(),
                    attrs: BinaryNodeAttributes::from([("type".to_string(), "all".to_string())]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "bot".to_string(),
                        attrs: BinaryNodeAttributes::from([
                            ("jid".to_string(), "13135550002@s.whatsapp.net".to_string()),
                            ("persona_id".to_string(), "meta-ai".to_string()),
                        ]),
                        content: None,
                    }])),
                }])),
            }])),
        };
        let bots = parse_bot_list_v2_node(&bot_resp);
        assert_eq!(bots.len(), 1);
        assert_eq!(bots[0].persona_id, "meta-ai");

        let mut sp = ServerProps::default();
        let props = HashMap::from([
            ("10518".to_string(), "0".to_string()),
            ("14303".to_string(), "true".to_string()),
        ]);
        apply_ab_props(&props, &mut sp);
        assert!(!sp.privacy_token_on_1to1);
        assert!(sp.lid_trusted_token_issue_to_lid);
    }
}
