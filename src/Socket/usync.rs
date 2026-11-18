use super::socket::{SocketError, WaSocket};
use crate::types::LidMapping;
use crate::wa_binary::{is_lid_user, BinaryNodeError};
use crate::wa_usync::{USyncQuery, USyncQueryResult, USyncUser};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnWhatsAppResult {
    pub jid: String,
    pub exists: bool,
}

impl WaSocket {
    pub async fn execute_usync_query(
        &self,
        usync_query: &USyncQuery,
    ) -> Result<Option<USyncQueryResult>, SocketError> {
        if usync_query.protocols.is_empty() {
            return Err(SocketError::BinaryNode(BinaryNodeError::NodeError {
                text: "USyncQuery must have at least one protocol".to_string(),
                code: Some(400),
            }));
        }

        let iq = usync_query.build_iq_node(self.generate_message_tag());
        let result = self.query(iq, None).await?;
        Ok(usync_query.parse_usync_query_result(&result)?)
    }

    pub async fn on_whatsapp(
        &self,
        phone_numbers: &[&str],
    ) -> Result<Vec<OnWhatsAppResult>, SocketError> {
        let mut usync_query = USyncQuery::new();
        let mut contact_enabled = false;

        for &jid in phone_numbers {
            if is_lid_user(Some(jid)) {
                continue;
            }
            if !contact_enabled {
                contact_enabled = true;
                usync_query = usync_query.with_contact_protocol();
            }
            let cleaned = jid.replace('+', "");
            let base = cleaned
                .split('@')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let phone = format!("+{}", base);
            usync_query = usync_query.with_user(USyncUser::new().with_phone(phone));
        }

        if usync_query.users.is_empty() {
            return Ok(Vec::new());
        }

        let Some(results) = self.execute_usync_query(&usync_query).await? else {
            return Ok(Vec::new());
        };

        Ok(results
            .list
            .into_iter()
            .filter_map(|item| {
                let exists = item.contact().unwrap_or(false);
                if exists {
                    Some(OnWhatsAppResult {
                        jid: item.id,
                        exists,
                    })
                } else {
                    None
                }
            })
            .collect())
    }

    pub async fn pn_from_lid_usync(&self, jids: &[String]) -> Result<Vec<LidMapping>, SocketError> {
        let mut usync_query = USyncQuery::new()
            .with_lid_protocol()
            .with_context("background");

        for jid in jids {
            if is_lid_user(Some(jid)) {
                continue;
            }
            usync_query = usync_query.with_user(USyncUser::new().with_id(jid.clone()));
        }

        if usync_query.users.is_empty() {
            return Ok(Vec::new());
        }

        let Some(results) = self.execute_usync_query(&usync_query).await? else {
            return Ok(Vec::new());
        };

        Ok(results
            .list
            .into_iter()
            .filter_map(|item| {
                let lid = item.lid()?.to_string();
                Some(LidMapping { pn: item.id, lid })
            })
            .collect())
    }
}
