use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct USyncUser {
    pub id: Option<String>,
    pub lid: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub username_key: Option<String>,
    pub r#type: Option<String>,
    pub persona_id: Option<String>,
}

impl USyncUser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_lid(mut self, lid: impl Into<String>) -> Self {
        self.lid = Some(lid.into());
        self
    }

    pub fn with_phone(mut self, phone: impl Into<String>) -> Self {
        self.phone = Some(phone.into());
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_username_key(mut self, username_key: impl Into<String>) -> Self {
        self.username_key = Some(username_key.into());
        self
    }

    pub fn with_type(mut self, user_type: impl Into<String>) -> Self {
        self.r#type = Some(user_type.into());
        self
    }

    pub fn with_persona_id(mut self, persona_id: impl Into<String>) -> Self {
        self.persona_id = Some(persona_id.into());
        self
    }
}
