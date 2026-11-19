use crate::proto::sync_action_value::ContactAction;
use crate::types::{LidMapping, SyncActionEvent, SyncContact};
use crate::wa_binary::{is_lid_user, is_pn_user};

pub fn process_contact_action(
    action: &ContactAction,
    id: Option<&str>,
) -> Vec<SyncActionEvent> {
    let mut results = Vec::new();

    let Some(id) = id.filter(|s| !s.is_empty()) else {
        return results;
    };

    let lid_jid = action.lid_jid.as_deref().filter(|s| !s.is_empty());
    let id_is_pn = is_pn_user(Some(id));
    let phone_number = if id_is_pn {
        Some(id.to_string())
    } else {
        action
            .pn_jid
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    let name = action
        .full_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| action.first_name.as_deref().filter(|s| !s.is_empty()))
        .or_else(|| action.username.as_deref().filter(|s| !s.is_empty()))
        .map(String::from);

    results.push(SyncActionEvent::ContactsUpsert(vec![SyncContact {
        id: id.to_string(),
        name,
        username: action
            .username
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
        lid: lid_jid.map(String::from),
        phone_number,
    }]));

    if let Some(lid) = lid_jid {
        if is_lid_user(Some(lid)) && id_is_pn {
            results.push(SyncActionEvent::LidMappingUpdate(LidMapping {
                lid: lid.to_string(),
                pn: id.to_string(),
            }));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_contact_action_pn_with_lid() {
        let action = ContactAction {
            full_name: Some("Luis Guzman".to_string()),
            lid_jid: Some("123456@lid".to_string()),
            ..Default::default()
        };

        let events = process_contact_action(&action, Some("573001234567@s.whatsapp.net"));
        assert_eq!(events.len(), 2);

        match &events[0] {
            SyncActionEvent::ContactsUpsert(contacts) => {
                assert_eq!(contacts.len(), 1);
                assert_eq!(contacts[0].name.as_deref(), Some("Luis Guzman"));
                assert_eq!(
                    contacts[0].phone_number.as_deref(),
                    Some("573001234567@s.whatsapp.net")
                );
                assert_eq!(contacts[0].lid.as_deref(), Some("123456@lid"));
            }
            other => panic!("unexpected event: {:?}", other),
        }

        assert_eq!(
            events[1],
            SyncActionEvent::LidMappingUpdate(LidMapping {
                lid: "123456@lid".to_string(),
                pn: "573001234567@s.whatsapp.net".to_string(),
            })
        );
    }

    #[test]
    fn test_process_contact_action_missing_id() {
        let action = ContactAction {
            first_name: Some("Test".to_string()),
            ..Default::default()
        };
        assert!(process_contact_action(&action, None).is_empty());
        assert!(process_contact_action(&action, Some("")).is_empty());
    }
}
