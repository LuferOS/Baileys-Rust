use super::types::{BinaryNode, BinaryNodeData, BinaryNodeError};
use std::collections::HashMap;

pub fn get_binary_node_children<'a>(
    node: Option<&'a BinaryNode>,
    child_tag: &str,
) -> Vec<&'a BinaryNode> {
    let Some(node) = node else {
        return Vec::new();
    };
    let Some(BinaryNodeData::List(children)) = &node.content else {
        return Vec::new();
    };
    children.iter().filter(|c| c.tag == child_tag).collect()
}

pub fn get_binary_node_child<'a>(
    node: Option<&'a BinaryNode>,
    child_tag: &str,
) -> Option<&'a BinaryNode> {
    let node = node?;
    let Some(BinaryNodeData::List(children)) = &node.content else {
        return None;
    };
    children.iter().find(|c| c.tag == child_tag)
}

pub fn get_all_binary_node_children(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryNodeData::List(children)) => children.as_slice(),
        _ => &[],
    }
}

pub fn get_binary_node_child_buffer<'a>(
    node: Option<&'a BinaryNode>,
    child_tag: &str,
) -> Option<&'a [u8]> {
    let child = get_binary_node_child(node, child_tag)?;
    match &child.content {
        Some(BinaryNodeData::Bytes(bytes)) => Some(bytes.as_slice()),
        _ => None,
    }
}

pub fn get_binary_node_child_string(node: Option<&BinaryNode>, child_tag: &str) -> Option<String> {
    let child = get_binary_node_child(node, child_tag)?;
    match &child.content {
        Some(BinaryNodeData::Bytes(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Some(BinaryNodeData::String(s)) => Some(s.clone()),
        _ => None,
    }
}

pub fn get_binary_node_child_uint(
    node: &BinaryNode,
    child_tag: &str,
    length: usize,
) -> Option<u64> {
    let buff = get_binary_node_child_buffer(Some(node), child_tag)?;
    buffer_to_uint(buff, length)
}

pub fn assert_node_error_free(node: &BinaryNode) -> Result<(), BinaryNodeError> {
    if let Some(err_node) = get_binary_node_child(Some(node), "error") {
        let text = err_node
            .attrs
            .get("text")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| "Unknown error".to_string());
        let code = err_node
            .attrs
            .get("code")
            .and_then(|c| c.parse::<i32>().ok());
        return Err(BinaryNodeError::NodeError { text, code });
    }
    Ok(())
}

pub fn reduce_binary_node_to_dictionary(node: &BinaryNode, tag: &str) -> HashMap<String, String> {
    let mut dict = HashMap::new();
    for child in get_binary_node_children(Some(node), tag) {
        let key = child
            .attrs
            .get("name")
            .or_else(|| child.attrs.get("config_code"));
        let val = child
            .attrs
            .get("value")
            .filter(|v| !v.is_empty())
            .or_else(|| child.attrs.get("config_value"));
        if let (Some(k), Some(v)) = (key, val) {
            dict.insert(k.clone(), v.clone());
        }
    }
    dict
}

pub fn get_binary_node_message_bytes(node: &BinaryNode) -> Vec<&[u8]> {
    let mut msgs = Vec::new();
    if let Some(BinaryNodeData::List(items)) = &node.content {
        for item in items {
            if item.tag == "message" {
                if let Some(BinaryNodeData::Bytes(bytes)) = &item.content {
                    msgs.push(bytes.as_slice());
                }
            }
        }
    }
    msgs
}

pub fn buffer_to_uint(buf: &[u8], length: usize) -> Option<u64> {
    if buf.len() < length || length > 8 {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in &buf[..length] {
        acc = (acc << 8) | u64::from(b);
    }
    Some(acc)
}

pub fn binary_node_data_to_string(data: &BinaryNodeData, indent: usize) -> String {
    let tabs = "\t".repeat(indent);
    match data {
        BinaryNodeData::String(s) => format!("{}{}", tabs, s),
        BinaryNodeData::Bytes(b) => {
            let hex: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
            format!("{}{}", tabs, hex)
        }
        BinaryNodeData::List(nodes) => nodes
            .iter()
            .map(|x| {
                format!(
                    "{}{}",
                    "\t".repeat(indent + 1),
                    binary_node_to_string(x, indent + 1)
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

pub fn binary_node_to_string(node: &BinaryNode, indent: usize) -> String {
    let children = match &node.content {
        Some(content) => binary_node_data_to_string(content, indent + 1),
        None => String::new(),
    };

    let attrs_str = node
        .attrs
        .iter()
        .map(|(k, v)| format!("{}='{}'", k, v))
        .collect::<Vec<_>>()
        .join(" ");

    let tag = format!("<{} {}", node.tag, attrs_str);

    let content = if !children.is_empty() {
        format!(">\n{}\n{}</{}>", children, "\t".repeat(indent), node.tag)
    } else {
        "/>".to_string()
    };

    format!("{}{}", tag, content)
}
