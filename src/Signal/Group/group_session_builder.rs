use super::keyhelper::{
    generate_sender_key, generate_sender_key_id, generate_sender_signing_key,
};
use super::sender_key_distribution_message::SenderKeyDistributionMessage;
use super::sender_key_record::SenderKeyRecord;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupSessionError {
    #[error("no session state available")]
    NoSessionState,
}

pub struct GroupSessionBuilder;

impl GroupSessionBuilder {
    pub fn process(
        record: &mut SenderKeyRecord,
        skdm: &SenderKeyDistributionMessage,
    ) {
        record.add_sender_key_state(
            skdm.get_id(),
            skdm.get_iteration(),
            skdm.get_chain_key().to_vec(),
            skdm.get_signature_key().to_vec(),
        );
    }

    pub fn create(
        record: &mut SenderKeyRecord,
    ) -> Result<SenderKeyDistributionMessage, GroupSessionError> {
        if record.is_empty() {
            let key_id = generate_sender_key_id();
            let sender_key = generate_sender_key();
            let signing_key = generate_sender_signing_key();
            record.set_sender_key_state(key_id, 0, sender_key, signing_key);
        }

        let state = record
            .get_sender_key_state(None)
            .ok_or(GroupSessionError::NoSessionState)?;

        Ok(SenderKeyDistributionMessage::new(
            state.get_key_id(),
            state.get_sender_chain_key().get_iteration(),
            state.get_sender_chain_key().get_seed().to_vec(),
            state.get_signing_key_public(),
        ))
    }
}
