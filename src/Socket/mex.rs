use super::socket::{SocketError, WaSocket};
use crate::wa_binary::{
    get_binary_node_child, BinaryNode, BinaryNodeAttributes, BinaryNodeData, S_WHATSAPP_NET,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MexError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("graphql server error ({code}): {message}")]
    Graphql { code: u16, message: String },
    #[error("failed to {action}, unexpected response structure")]
    UnexpectedResponse { action: String },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn build_w_mex_query_node(
    variables: Value,
    query_id: &str,
    msg_id: String,
) -> Result<BinaryNode, MexError> {
    let payload = serde_json::to_vec(&json!({ "variables": variables }))?;
    Ok(BinaryNode {
        tag: "iq".to_string(),
        attrs: BinaryNodeAttributes::from([
            ("id".to_string(), msg_id),
            ("type".to_string(), "get".to_string()),
            ("to".to_string(), S_WHATSAPP_NET.to_string()),
            ("xmlns".to_string(), "w:mex".to_string()),
        ]),
        content: Some(BinaryNodeData::List(vec![BinaryNode {
            tag: "query".to_string(),
            attrs: BinaryNodeAttributes::from([("query_id".to_string(), query_id.to_string())]),
            content: Some(BinaryNodeData::Bytes(payload)),
        }])),
    })
}

pub fn parse_w_mex_response<T: DeserializeOwned>(
    result: &BinaryNode,
    data_path: &str,
) -> Result<T, MexError> {
    if let Some(child) = get_binary_node_child(Some(result), "result") {
        if let Some(content) = &child.content {
            let bytes = match content {
                BinaryNodeData::Bytes(b) => b.as_slice(),
                BinaryNodeData::String(s) => s.as_bytes(),
                BinaryNodeData::List(_) => &[],
            };

            if !bytes.is_empty() {
                let data: Value = serde_json::from_slice(bytes)?;

                if let Some(errors) = data.get("errors").and_then(|e| e.as_array()) {
                    if !errors.is_empty() {
                        let message = errors
                            .iter()
                            .map(|err| {
                                err.get("message")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("Unknown error")
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let code = errors[0]
                            .get("extensions")
                            .and_then(|ext| ext.get("error_code"))
                            .and_then(|c| c.as_u64())
                            .unwrap_or(400) as u16;
                        return Err(MexError::Graphql { code, message });
                    }
                }

                let response = if data_path.is_empty() {
                    data.get("data")
                } else {
                    data.get("data").and_then(|d| d.get(data_path))
                };

                if let Some(val) = response {
                    if !val.is_null() {
                        return Ok(serde_json::from_value(val.clone())?);
                    }
                }
            }
        }
    }

    let action = data_path
        .strip_prefix("xwa2_")
        .unwrap_or(data_path)
        .replace('_', " ");
    Err(MexError::UnexpectedResponse { action })
}

pub async fn execute_w_mex_query<T: DeserializeOwned>(
    variables: Value,
    query_id: &str,
    data_path: &str,
    socket: &WaSocket,
) -> Result<T, MexError> {
    let iq = build_w_mex_query_node(variables, query_id, socket.generate_message_tag())?;
    let result = socket.query(iq, None).await?;
    parse_w_mex_response(&result, data_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mex_query_build_and_parse() {
        let iq = build_w_mex_query_node(
            json!({ "newsletter_id": "123@newsletter" }),
            "9783111038412085",
            "tag-1".to_string(),
        )
        .unwrap();
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("xmlns").map(|s| s.as_str()), Some("w:mex"));

        let ok_res = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "result".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(
                    br#"{"data":{"xwa2_newsletter_subscribers":{"subscribers":42}}}"#.to_vec(),
                )),
            }])),
        };
        let parsed: Value =
            parse_w_mex_response(&ok_res, "xwa2_newsletter_subscribers").unwrap();
        assert_eq!(parsed["subscribers"], 42);

        let err_res = BinaryNode {
            tag: "iq".to_string(),
            attrs: BinaryNodeAttributes::new(),
            content: Some(BinaryNodeData::List(vec![BinaryNode {
                tag: "result".to_string(),
                attrs: BinaryNodeAttributes::new(),
                content: Some(BinaryNodeData::Bytes(
                    br#"{"errors":[{"message":"Not allowed","extensions":{"error_code":403}}]}"#
                        .to_vec(),
                )),
            }])),
        };
        match parse_w_mex_response::<Value>(&err_res, "xwa2_newsletter_subscribers").unwrap_err() {
            MexError::Graphql { code, message } => {
                assert_eq!(code, 403);
                assert_eq!(message, "Not allowed");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
