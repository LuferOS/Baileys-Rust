use super::mex::{execute_w_mex_query, MexError};
use super::socket::{SocketError, WaSocket};
use crate::types::{
    NewsletterCreateResponse, NewsletterMetadata, NewsletterPicture, NewsletterUpdate, QueryIds,
    XwaPaths,
};
use crate::wa_binary::{
    get_binary_node_child, BinaryNode, BinaryNodeAttributes, BinaryNodeData,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewsletterLookupType {
    Invite,
    Jid,
}

impl NewsletterLookupType {
    pub fn as_upper_str(&self) -> &'static str {
        match self {
            NewsletterLookupType::Invite => "INVITE",
            NewsletterLookupType::Jid => "JID",
        }
    }
}

#[derive(Debug, Deserialize)]
struct SubscribersResponse {
    subscribers: u64,
}

#[derive(Debug, Deserialize)]
struct AdminCountResponse {
    admin_count: u64,
}

pub fn parse_newsletter_create_response(
    response: NewsletterCreateResponse,
) -> NewsletterMetadata {
    let thread = response.thread_metadata;
    let viewer = response.viewer_metadata;
    NewsletterMetadata {
        id: response.id,
        owner: None,
        name: thread.name.text,
        creation_time: thread.creation_time.parse::<u64>().ok(),
        description: Some(thread.description.text),
        invite: Some(thread.invite),
        subscribers: thread.subscribers_count.parse::<u64>().ok(),
        verification: Some(thread.verification),
        picture: Some(NewsletterPicture {
            id: Some(thread.picture.id),
            direct_path: Some(thread.picture.direct_path),
            ..Default::default()
        }),
        mute_state: Some(viewer.mute),
        ..Default::default()
    }
}

pub fn parse_newsletter_metadata(result: &Value) -> Option<NewsletterMetadata> {
    let obj = result.as_object()?;
    if obj.get("id").and_then(|v| v.as_str()).is_some() {
        return serde_json::from_value(result.clone()).ok();
    }
    if let Some(inner) = obj.get("result") {
        if inner
            .as_object()
            .and_then(|o| o.get("id"))
            .and_then(|v| v.as_str())
            .is_some()
        {
            return serde_json::from_value(inner.clone()).ok();
        }
    }
    None
}

impl WaSocket {
    pub async fn newsletter_update(
        &self,
        jid: &str,
        updates: NewsletterUpdate,
    ) -> Result<Value, MexError> {
        let mut updates_val = serde_json::to_value(updates)?;
        if let Some(map) = updates_val.as_object_mut() {
            map.insert("settings".to_string(), Value::Null);
        }
        let variables = json!({
            "newsletter_id": jid,
            "updates": updates_val
        });
        execute_w_mex_query(
            variables,
            QueryIds::UPDATE_METADATA,
            "xwa2_newsletter_update",
            self,
        )
        .await
    }

    pub async fn newsletter_create(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<NewsletterMetadata, MexError> {
        let variables = json!({
            "input": {
                "name": name,
                "description": description
            }
        });
        let raw: NewsletterCreateResponse = execute_w_mex_query(
            variables,
            QueryIds::CREATE,
            XwaPaths::XWA2_NEWSLETTER_CREATE,
            self,
        )
        .await?;
        Ok(parse_newsletter_create_response(raw))
    }

    pub async fn newsletter_subscribers(&self, jid: &str) -> Result<u64, MexError> {
        let res: SubscribersResponse = execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::SUBSCRIBERS,
            XwaPaths::XWA2_NEWSLETTER_SUBSCRIBERS,
            self,
        )
        .await?;
        Ok(res.subscribers)
    }

    pub async fn newsletter_metadata(
        &self,
        lookup_type: NewsletterLookupType,
        key: &str,
    ) -> Result<Option<NewsletterMetadata>, MexError> {
        let variables = json!({
            "fetch_creation_time": true,
            "fetch_full_image": true,
            "fetch_viewer_metadata": true,
            "input": {
                "key": key,
                "type": lookup_type.as_upper_str()
            }
        });
        let raw: Value = execute_w_mex_query(
            variables,
            QueryIds::METADATA,
            XwaPaths::XWA2_NEWSLETTER_METADATA,
            self,
        )
        .await?;
        Ok(parse_newsletter_metadata(&raw))
    }

    pub async fn newsletter_follow(&self, jid: &str) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::FOLLOW,
            XwaPaths::XWA2_NEWSLETTER_JOIN_V2,
            self,
        )
        .await
    }

    pub async fn newsletter_unfollow(&self, jid: &str) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::UNFOLLOW,
            XwaPaths::XWA2_NEWSLETTER_LEAVE_V2,
            self,
        )
        .await
    }

    pub async fn newsletter_mute(&self, jid: &str) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::MUTE,
            XwaPaths::XWA2_NEWSLETTER_MUTE_V2,
            self,
        )
        .await
    }

    pub async fn newsletter_unmute(&self, jid: &str) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::UNMUTE,
            XwaPaths::XWA2_NEWSLETTER_UNMUTE_V2,
            self,
        )
        .await
    }

    pub async fn newsletter_update_name(&self, jid: &str, name: &str) -> Result<Value, MexError> {
        self.newsletter_update(
            jid,
            NewsletterUpdate {
                name: Some(name.to_string()),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn newsletter_update_description(
        &self,
        jid: &str,
        description: &str,
    ) -> Result<Value, MexError> {
        self.newsletter_update(
            jid,
            NewsletterUpdate {
                description: Some(description.to_string()),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn newsletter_update_picture_bytes(
        &self,
        jid: &str,
        jpeg_bytes: &[u8],
    ) -> Result<Value, MexError> {
        self.newsletter_update(
            jid,
            NewsletterUpdate {
                picture: Some(BASE64.encode(jpeg_bytes)),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn newsletter_remove_picture(&self, jid: &str) -> Result<Value, MexError> {
        self.newsletter_update(
            jid,
            NewsletterUpdate {
                picture: Some(String::new()),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn newsletter_react_message(
        &self,
        jid: &str,
        server_id: &str,
        reaction: Option<&str>,
    ) -> Result<BinaryNode, SocketError> {
        let mut attrs = BinaryNodeAttributes::from([
            ("to".to_string(), jid.to_string()),
            ("type".to_string(), "reaction".to_string()),
            ("server_id".to_string(), server_id.to_string()),
            ("id".to_string(), self.generate_message_tag()),
        ]);
        if reaction.is_none() {
            attrs.insert("edit".to_string(), "7".to_string());
        }

        let reaction_attrs = reaction
            .map(|r| BinaryNodeAttributes::from([("code".to_string(), r.to_string())]))
            .unwrap_or_default();

        self.query(
            BinaryNode {
                tag: "message".to_string(),
                attrs,
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "reaction".to_string(),
                    attrs: reaction_attrs,
                    content: None,
                }])),
            },
            None,
        )
        .await
    }

    pub async fn newsletter_fetch_messages(
        &self,
        jid: &str,
        count: u32,
        since: Option<u64>,
        after: Option<u64>,
    ) -> Result<BinaryNode, SocketError> {
        let mut attrs = BinaryNodeAttributes::from([("count".to_string(), count.to_string())]);
        if let Some(s) = since {
            attrs.insert("since".to_string(), s.to_string());
        }
        if let Some(a) = after.filter(|&v| v > 0) {
            attrs.insert("after".to_string(), a.to_string());
        }

        self.query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("id".to_string(), self.generate_message_tag()),
                    ("type".to_string(), "get".to_string()),
                    ("xmlns".to_string(), "newsletter".to_string()),
                    ("to".to_string(), jid.to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![BinaryNode {
                    tag: "message_updates".to_string(),
                    attrs,
                    content: None,
                }])),
            },
            None,
        )
        .await
    }

    pub async fn subscribe_newsletter_updates(
        &self,
        jid: &str,
    ) -> Result<Option<String>, SocketError> {
        let result = self
            .query(
                BinaryNode {
                    tag: "iq".to_string(),
                    attrs: BinaryNodeAttributes::from([
                        ("id".to_string(), self.generate_message_tag()),
                        ("type".to_string(), "set".to_string()),
                        ("xmlns".to_string(), "newsletter".to_string()),
                        ("to".to_string(), jid.to_string()),
                    ]),
                    content: Some(BinaryNodeData::List(vec![BinaryNode {
                        tag: "live_updates".to_string(),
                        attrs: BinaryNodeAttributes::new(),
                        content: Some(BinaryNodeData::List(Vec::new())),
                    }])),
                },
                None,
            )
            .await?;

        Ok(get_binary_node_child(Some(&result), "live_updates")
            .and_then(|n| n.attrs.get("duration").cloned()))
    }

    pub async fn newsletter_admin_count(&self, jid: &str) -> Result<u64, MexError> {
        let res: AdminCountResponse = execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::ADMIN_COUNT,
            XwaPaths::XWA2_NEWSLETTER_ADMIN_COUNT,
            self,
        )
        .await?;
        Ok(res.admin_count)
    }

    pub async fn newsletter_change_owner(
        &self,
        jid: &str,
        new_owner_jid: &str,
    ) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid, "user_id": new_owner_jid }),
            QueryIds::CHANGE_OWNER,
            XwaPaths::XWA2_NEWSLETTER_CHANGE_OWNER,
            self,
        )
        .await
    }

    pub async fn newsletter_demote(
        &self,
        jid: &str,
        user_jid: &str,
    ) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid, "user_id": user_jid }),
            QueryIds::DEMOTE,
            XwaPaths::XWA2_NEWSLETTER_DEMOTE,
            self,
        )
        .await
    }

    pub async fn newsletter_delete(&self, jid: &str) -> Result<Value, MexError> {
        execute_w_mex_query(
            json!({ "newsletter_id": jid }),
            QueryIds::DELETE,
            XwaPaths::XWA2_NEWSLETTER_DELETE_V2,
            self,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_newsletter_create_and_metadata() {
        let raw_create = json!({
            "id": "1203630001@newsletter",
            "state": { "type": "ACTIVE" },
            "thread_metadata": {
                "creation_time": "1700000000",
                "description": { "id": "d1", "text": "Canal Rust", "update_time": "1700000001" },
                "handle": null,
                "invite": "INV123",
                "name": { "id": "n1", "text": "Baileys Rust", "update_time": "1700000001" },
                "picture": { "direct_path": "/v/pic", "id": "p1", "type": "IMAGE" },
                "preview": { "direct_path": "/v/prev", "id": "p2", "type": "PREVIEW" },
                "subscribers_count": "150",
                "verification": "VERIFIED"
            },
            "viewer_metadata": {
                "mute": "OFF",
                "role": "OWNER"
            }
        });

        let create_resp: NewsletterCreateResponse = serde_json::from_value(raw_create).unwrap();
        let meta = parse_newsletter_create_response(create_resp);
        assert_eq!(meta.id, "1203630001@newsletter");
        assert_eq!(meta.name, "Baileys Rust");
        assert_eq!(meta.subscribers, Some(150));
        assert_eq!(meta.mute_state.as_deref(), Some("OFF"));

        let wrapped = json!({ "result": meta });
        let parsed = parse_newsletter_metadata(&wrapped).unwrap();
        assert_eq!(parsed.id, "1203630001@newsletter");
    }
}
