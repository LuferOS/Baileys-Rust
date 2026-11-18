use super::groups::GroupsSocket;
use super::mex::execute_w_mex_query;
use crate::types::{QueryParams, XwaPaths};
use crate::wa_binary::{get_binary_node_child, BinaryNode, BinaryNodeAttributes, BinaryNodeData};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterPictureInfo {
    pub id: String,
    pub direct_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterThreadMetadata {
    pub name: NewsletterTextObj,
    pub creation_time: String,
    pub description: NewsletterTextObj,
    pub invite: Option<String>,
    pub subscribers_count: String,
    pub verification: Option<String>,
    pub picture: NewsletterPictureInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterTextObj {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterViewerMetadata {
    pub mute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterCreateResponse {
    pub id: String,
    pub thread_metadata: NewsletterThreadMetadata,
    pub viewer_metadata: NewsletterViewerMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterMetadata {
    pub id: String,
    pub owner: Option<String>,
    pub name: String,
    pub creation_time: u64,
    pub description: String,
    pub invite: Option<String>,
    pub subscribers: u64,
    pub verification: Option<String>,
    pub picture: NewsletterPictureInfo,
    pub mute_state: Option<String>,
}

pub struct NewsletterSocket {
    pub groups: GroupsSocket,
}

impl NewsletterSocket {
    pub fn new(groups: GroupsSocket) -> Self {
        Self { groups }
    }

    async fn execute_mex<T: serde::de::DeserializeOwned>(
        &self,
        variables: serde_json::Map<String, Value>,
        query_id: &str,
        data_path: &str,
    ) -> Result<T, super::mex::MexError> {
        execute_w_mex_query(variables, query_id, data_path, &self.groups.socket).await
    }

    pub async fn newsletter_create(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<NewsletterMetadata, super::mex::MexError> {
        let mut input = serde_json::Map::new();
        input.insert("name".to_string(), Value::String(name.to_string()));
        input.insert(
            "description".to_string(),
            description.map(|d| Value::String(d.to_string())).unwrap_or(Value::Null),
        );

        let mut variables = serde_json::Map::new();
        variables.insert("input".to_string(), Value::Object(input));

        let res: NewsletterCreateResponse = self
            .execute_mex(
                variables,
                QueryParams::CREATE,
                XwaPaths::XWA2_NEWSLETTER_CREATE,
            )
            .await?;

        Ok(NewsletterMetadata {
            id: res.id,
            owner: None,
            name: res.thread_metadata.name.text,
            creation_time: res.thread_metadata.creation_time.parse().unwrap_or(0),
            description: res.thread_metadata.description.text,
            invite: res.thread_metadata.invite,
            subscribers: res.thread_metadata.subscribers_count.parse().unwrap_or(0),
            verification: res.thread_metadata.verification,
            picture: res.thread_metadata.picture,
            mute_state: res.viewer_metadata.mute,
        })
    }

    pub async fn newsletter_follow(&self, jid: &str) -> Result<(), super::mex::MexError> {
        let mut variables = serde_json::Map::new();
        variables.insert("newsletter_id".to_string(), Value::String(jid.to_string()));
        let _: Value = self
            .execute_mex(
                variables,
                QueryParams::FOLLOW,
                XwaPaths::XWA2_NEWSLETTER_JOIN_V2,
            )
            .await?;
        Ok(())
    }

    pub async fn newsletter_unfollow(&self, jid: &str) -> Result<(), super::mex::MexError> {
        let mut variables = serde_json::Map::new();
        variables.insert("newsletter_id".to_string(), Value::String(jid.to_string()));
        let _: Value = self
            .execute_mex(
                variables,
                QueryParams::UNFOLLOW,
                XwaPaths::XWA2_NEWSLETTER_LEAVE_V2,
            )
            .await?;
        Ok(())
    }

    pub async fn newsletter_react_message(
        &self,
        jid: &str,
        server_id: &str,
        reaction: Option<&str>,
    ) -> Result<(), super::socket::SocketError> {
        let mut attrs = BinaryNodeAttributes::from([
            ("to".to_string(), jid.to_string()),
            ("type".to_string(), "reaction".to_string()),
            ("server_id".to_string(), server_id.to_string()),
            ("id".to_string(), self.groups.socket.generate_message_tag()),
        ]);
        if reaction.is_none() {
            attrs.insert("edit".to_string(), "7".to_string());
        }

        let content = vec![BinaryNode {
            tag: "reaction".to_string(),
            attrs: reaction
                .map(|r| BinaryNodeAttributes::from([("code".to_string(), r.to_string())]))
                .unwrap_or_default(),
            content: None,
        }];

        self.groups
            .socket
            .send_node(&BinaryNode {
                tag: "message".to_string(),
                attrs,
                content: Some(BinaryNodeData::List(content)),
            })
    }
}
