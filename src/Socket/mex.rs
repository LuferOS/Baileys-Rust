use super::socket::{SocketError, WaSocket};
use crate::wa_binary::{get_binary_node_child, BinaryNode, BinaryNodeAttributes, BinaryNodeData, S_WHATSAPP_NET};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MexError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("graphql server error: {0}")]
    Graphql(String),
    #[error("failed to execute mex query: unexpected response structure")]
    UnexpectedResponse,
}

pub async fn execute_w_mex_query<T: DeserializeOwned>(
    variables: serde_json::Map<String, Value>,
    query_id: &str,
    data_path: &str,
    socket: &WaSocket,
) -> Result<T, MexError> {
    let query_node = BinaryNode {
        tag: "query".to_string(),
        attrs: BinaryNodeAttributes::from([("query_id".to_string(), query_id.to_string())]),
        content: Some(BinaryNodeData::Bytes(
            serde_json::to_vec(&variables).unwrap_or_default(),
        )),
    };

    let result = socket
        .query(
            BinaryNode {
                tag: "iq".to_string(),
                attrs: BinaryNodeAttributes::from([
                    ("id".to_string(), socket.generate_message_tag()),
                    ("type".to_string(), "get".to_string()),
                    ("to".to_string(), S_WHATSAPP_NET.to_string()),
                    ("xmlns".to_string(), "w:mex".to_string()),
                ]),
                content: Some(BinaryNodeData::List(vec![query_node])),
            },
            None,
        )
        .await?;

    let child = get_binary_node_child(Some(&result), "result");
    if let Some(content) = child.and_then(|c| c.content.as_ref()) {
        let bytes = match content {
            BinaryNodeData::Bytes(b) => b.clone(),
            BinaryNodeData::String(s) => s.as_bytes().to_vec(),
            _ => Vec::new(),
        };

        if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(errors) = json.get("errors").and_then(|e| e.as_array()) {
                if !errors.is_empty() {
                    let err_str = errors
                        .iter()
                        .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(MexError::Graphql(err_str));
                }
            }

            let data_obj = json.get("data");
            let target = if data_path.is_empty() {
                data_obj
            } else {
                data_obj.and_then(|d| d.get(data_path))
            };

            if let Some(val) = target {
                if let Ok(parsed) = serde_json::from_value::<T>(val.clone()) {
                    return Ok(parsed);
                }
            }
        }
    }

    Err(MexError::UnexpectedResponse)
}
