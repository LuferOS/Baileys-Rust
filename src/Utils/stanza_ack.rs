use crate::wa_binary::{BinaryNode, BinaryNodeAttributes};

pub fn build_ack_stanza(
    node: &BinaryNode,
    error_code: Option<u16>,
    _me_id: &str,
) -> BinaryNode {
    let mut attrs = BinaryNodeAttributes::new();
    attrs.insert("class".to_string(), node.tag.clone());

    if let Some(id) = node.attrs.get("id") {
        attrs.insert("id".to_string(), id.clone());
    }
    if let Some(from) = node.attrs.get("from") {
        attrs.insert("to".to_string(), from.clone());
    }
    if let Some(participant) = node.attrs.get("participant") {
        attrs.insert("participant".to_string(), participant.clone());
    }
    if let Some(recipient) = node.attrs.get("recipient") {
        attrs.insert("recipient".to_string(), recipient.clone());
    }
    if node.tag != "message" {
        if let Some(t) = node.attrs.get("type") {
            attrs.insert("type".to_string(), t.clone());
        }
    }
    if let Some(code) = error_code {
        attrs.insert("error".to_string(), code.to_string());
    }

    BinaryNode {
        tag: "ack".to_string(),
        attrs,
        content: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ack_stanza() {
        let node = BinaryNode {
            tag: "notification".to_string(),
            attrs: BinaryNodeAttributes::from([
                ("id".to_string(), "N1".to_string()),
                ("from".to_string(), "1203630001@g.us".to_string()),
                ("type".to_string(), "w:gp2".to_string()),
                ("participant".to_string(), "573001@s.whatsapp.net".to_string()),
            ]),
            content: None,
        };

        let ack = build_ack_stanza(&node, Some(500), "573002@s.whatsapp.net");
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs.get("class").map(|s| s.as_str()), Some("notification"));
        assert_eq!(ack.attrs.get("id").map(|s| s.as_str()), Some("N1"));
        assert_eq!(ack.attrs.get("to").map(|s| s.as_str()), Some("1203630001@g.us"));
        assert_eq!(ack.attrs.get("type").map(|s| s.as_str()), Some("w:gp2"));
        assert_eq!(ack.attrs.get("error").map(|s| s.as_str()), Some("500"));
    }
}
