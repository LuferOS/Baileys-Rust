use crate::proto::message::FutureProofMessage;
use crate::proto::{AiRichResponseMessage, AiRichResponseUnifiedResponse, ContextInfo, Message, MessageContextInfo};
use serde_json::{json, Value};

pub const DEFAULT_AI_BOT_JID: &str = "13135550002@s.whatsapp.net";

#[derive(Debug, Clone)]
pub struct AiRichBuilder {
    title: Option<String>,
    footer: Option<String>,
    disclaimer: String,
    #[allow(dead_code)]
    bot_jid: String,
    sections: Vec<Value>,
    embedded_screens: Vec<Value>,
}

impl Default for AiRichBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AiRichBuilder {
    pub fn new() -> Self {
        Self {
            title: None,
            footer: None,
            disclaimer: String::new(),
            bot_jid: DEFAULT_AI_BOT_JID.to_string(),
            sections: Vec::with_capacity(2),
            embedded_screens: Vec::new(),
        }
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn footer(mut self, footer: impl Into<String>) -> Self {
        self.footer = Some(footer.into());
        self
    }

    pub fn disclaimer(mut self, disclaimer: impl Into<String>) -> Self {
        self.disclaimer = disclaimer.into();
        self
    }

    pub fn bot_jid(mut self, bot_jid: impl Into<String>) -> Self {
        self.bot_jid = bot_jid.into();
        self
    }

    pub fn add_raw_section(mut self, section: Value) -> Self {
        self.sections.push(section);
        self
    }

    pub fn add_html_section(
        mut self,
        html: impl Into<String>,
        trusted_sources: Vec<String>,
    ) -> Self {
        self.sections.push(json!({
            "__typename": "GenAIUnifiedResponseSection",
            "view_model": {
                "__typename": "GenAISingleLayoutViewModel",
                "primitive": {
                    "__typename": "FOAHtmlPrimitiveDemoDONOTUSE",
                    "trusted_sources": trusted_sources,
                    "payload": html.into()
                }
            }
        }));
        self
    }

    pub fn add_native_html_section(
        mut self,
        html: impl Into<String>,
        url: impl Into<String>,
        trusted_sources: Vec<String>,
    ) -> Self {
        self.sections.push(json!({
            "__typename": "GenAIUnifiedResponseSection",
            "view_model": {
                "__typename": "GenAISingleLayoutViewModel",
                "primitive": {
                    "__typename": "GenAIaeacdsnwHtmlPrimitive",
                    "payload": html.into(),
                    "url": url.into(),
                    "trusted_sources": trusted_sources
                }
            }
        }));
        self
    }

    pub fn add_progress_section(
        mut self,
        title: impl Into<String>,
        in_progress: bool,
    ) -> Self {
        self.sections.push(json!({
            "__typename": "GenAIUnifiedResponseSection",
            "view_model": {
                "__typename": "GenAISingleLayoutViewModel",
                "primitive": {
                    "__typename": "GenAIBotProgressStatusPrimitive",
                    "title": title.into(),
                    "is_in_progress": in_progress
                }
            }
        }));
        self
    }

    pub fn add_embedded_screen_html(
        mut self,
        screen_title: impl Into<String>,
        tab_header: impl Into<String>,
        html: impl Into<String>,
        url: impl Into<String>,
        trusted_sources: Vec<String>,
    ) -> Self {
        self.embedded_screens.push(json!({
            "title": screen_title.into(),
            "content": [{
                "__typename": "FOAIDNixelButtonSheets",
                "tabs": [{
                    "id": "tab_0",
                    "tab_header": tab_header.into(),
                    "sections": [{
                        "__typename": "GenAIUnifiedResponseSection",
                        "view_model": {
                            "__typename": "GenAISingleLayoutViewModel",
                            "primitive": {
                                "__typename": "GenAIaeacdsnwHtmlPrimitive",
                                "payload": html.into(),
                                "url": url.into(),
                                "trusted_sources": trusted_sources
                            }
                        }
                    }],
                    "step_entries": []
                }]
            }]
        }));
        self
    }

    pub fn build_payload_value(&self) -> Value {
        let mut root = serde_json::Map::with_capacity(4);
        if let Some(ref t) = self.title {
            root.insert("title".to_string(), Value::String(t.clone()));
        }
        if let Some(ref f) = self.footer {
            root.insert("footer".to_string(), Value::String(f.clone()));
        }
        root.insert("sections".to_string(), Value::Array(self.sections.clone()));
        if !self.embedded_screens.is_empty() {
            root.insert(
                "embedded_screens".to_string(),
                Value::Array(self.embedded_screens.clone()),
            );
        }
        Value::Object(root)
    }

    pub fn build_message(&self) -> Message {
        let payload_bytes = serde_json::to_vec(&self.build_payload_value()).unwrap_or_default();
        let rich = AiRichResponseMessage {
            message_type: Some(1),
            unified_response: Some(AiRichResponseUnifiedResponse { data: Some(payload_bytes), ..Default::default() }),
            ..Default::default()
        };
        Message {
            message_context_info: Some(MessageContextInfo {
                
                ..Default::default()
            }.into()),
            rich_response_message: Some(rich.into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_rich_builder_unified_message() {
        let msg = AiRichBuilder::new()
            .title("AURA AI")
            .footer("Rust Engine")
            .disclaimer("Aura Reed Rust")
            .add_html_section("<div>Hola</div>", vec![])
            .build_message();
        assert!(msg.message_context_info.is_some());
    }
}
