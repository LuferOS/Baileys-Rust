use super::group::{
    GroupCipher, GroupCipherError, GroupSessionBuilder, GroupSessionError,
    SenderKeyDistributionError, SenderKeyDistributionMessage, SenderKeyName, SenderKeyRecord,
};
use super::lid_mapping::{LidMappingStore, PnToLidCallback};
use super::protocol::{
    decode_pre_key_signal_message, PreKeySignalMessageProto, ProtocolError, SessionRecord,
    SessionState,
};
use crate::types::{
    E2ESession, EncryptedGroupMessage, EncryptedMessage, KeyPair, MessageCipherType,
    MigrateSessionResult, ProtocolAddress, SessionInfo, SessionValidation,
};
use crate::utils::crypto::generate_signal_pub_key;
use crate::utils::use_multi_file_auth_state::{AuthStateError, MultiFileAuthState};
use crate::wa_binary::{
    is_hosted_lid_user, is_hosted_pn_user, is_lid_user, is_pn_user, jid_decode, transfer_device,
    JidServer, WaJidDomains,
};
use prost::Message;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

const MIGRATED_CACHE_TTL: Duration = Duration::from_secs(3 * 24 * 60 * 60);

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("invalid jid: {0}")]
    InvalidJid(String),
    #[error("empty user in jid: {0}")]
    EmptyUserJid(String),
    #[error("unexpected non-hosted device jid with device 99: {0}")]
    InvalidHostedDevice(String),
    #[error("auth state error: {0}")]
    AuthState(#[from] AuthStateError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("group cipher error: {0}")]
    GroupCipher(#[from] GroupCipherError),
    #[error("group session error: {0}")]
    GroupSession(#[from] GroupSessionError),
    #[error("sender key distribution error: {0}")]
    SenderKeyDistribution(#[from] SenderKeyDistributionError),
    #[error("missing pre-key {0} in storage")]
    MissingPreKey(u32),
    #[error("group id is required for sender key distribution message")]
    MissingGroupId,
}

pub fn extract_identity_from_pkmsg(ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 2 {
        return None;
    }
    let version = ciphertext[0];
    if (version & 0x0f) != 3 {
        return None;
    }
    let pre_key_proto = PreKeySignalMessageProto::decode(&ciphertext[1..]).ok()?;
    let identity_key = pre_key_proto.identity_key?;
    if identity_key.len() == 33 {
        return Some(identity_key);
    }
    None
}

pub fn jid_to_signal_protocol_address(jid: &str) -> Result<ProtocolAddress, SignalError> {
    let decoded = jid_decode(jid).ok_or_else(|| SignalError::InvalidJid(jid.to_string()))?;
    if decoded.user.is_empty() {
        return Err(SignalError::EmptyUserJid(jid.to_string()));
    }
    let domain_type = decoded.domain_type.unwrap_or(WaJidDomains::Whatsapp as u32);
    let signal_user = if domain_type != WaJidDomains::Whatsapp as u32 {
        format!("{}_{}", decoded.user, domain_type)
    } else {
        decoded.user
    };
    let final_device = decoded.device.unwrap_or(0);
    if final_device == 99
        && decoded.server != JidServer::Hosted
        && decoded.server != JidServer::HostedLid
    {
        return Err(SignalError::InvalidHostedDevice(jid.to_string()));
    }
    Ok(ProtocolAddress {
        name: signal_user,
        device_id: final_device,
    })
}

pub fn jid_to_signal_sender_key_name(
    group: &str,
    user: &str,
) -> Result<SenderKeyName, SignalError> {
    let addr = jid_to_signal_protocol_address(user)?;
    Ok(SenderKeyName::new(group, addr))
}

pub struct LibSignalRepository {
    auth: Arc<MultiFileAuthState>,
    pub lid_mapping: Arc<LidMappingStore>,
    migrated_session_cache: Mutex<HashMap<String, Instant>>,
    tx_locks: AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl LibSignalRepository {
    pub fn new(auth: Arc<MultiFileAuthState>, pn_to_lid_func: Option<PnToLidCallback>) -> Self {
        let lid_mapping = Arc::new(LidMappingStore::new(Arc::clone(&auth), pn_to_lid_func));
        Self {
            auth,
            lid_mapping,
            migrated_session_cache: Mutex::new(HashMap::new()),
            tx_locks: AsyncMutex::new(HashMap::new()),
        }
    }

    async fn acquire_tx_lock(&self, key: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self.tx_locks.lock().await;
        locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    async fn resolve_lid_signal_address(&self, id: &str) -> String {
        if let Some((device_id, device)) = id.split_once('.') {
            let mut parts = device_id.split('_');
            let user = parts.next().unwrap_or("");
            let domain_type = parts
                .next()
                .and_then(|d| d.parse::<u32>().ok())
                .unwrap_or(0);

            if domain_type == WaJidDomains::Lid as u32
                || domain_type == WaJidDomains::HostedLid as u32
            {
                return id.to_string();
            }

            let dev_part = if device != "0" {
                format!(":{}", device)
            } else {
                String::new()
            };
            let server = if domain_type == WaJidDomains::Hosted as u32 {
                "hosted"
            } else {
                "s.whatsapp.net"
            };
            let pn_jid = format!("{}{}@{}", user, dev_part, server);

            if let Some(lid_for_pn) = self.lid_mapping.get_lid_for_pn(&pn_jid).await {
                if let Ok(lid_addr) = jid_to_signal_protocol_address(&lid_for_pn) {
                    return lid_addr.to_string();
                }
            }
        }
        id.to_string()
    }

    async fn load_session(&self, id: &str) -> Option<SessionRecord> {
        let wire_jid = self.resolve_lid_signal_address(id).await;
        let stored = self.auth.get_keys("session", &[wire_jid.clone()]).await;
        let val = stored.get(&wire_jid)?.as_ref()?;
        serde_json::from_value::<SessionRecord>(val.clone()).ok()
    }

    async fn store_session(&self, id: &str, session: &SessionRecord) -> Result<(), SignalError> {
        let wire_jid = self.resolve_lid_signal_address(id).await;
        let mut entries = HashMap::new();
        entries.insert(wire_jid, Some(serde_json::to_value(session)?));
        let mut batch = HashMap::new();
        batch.insert("session".to_string(), entries);
        self.auth.set_keys(batch).await?;
        Ok(())
    }

    async fn load_sender_key(&self, sender_name: &SenderKeyName) -> SenderKeyRecord {
        let key_id = sender_name.to_string();
        let stored = self.auth.get_keys("sender-key", &[key_id.clone()]).await;
        if let Some(Some(val)) = stored.get(&key_id) {
            if let Ok(record) = serde_json::from_value::<SenderKeyRecord>(val.clone()) {
                return record;
            }
        }
        SenderKeyRecord::new()
    }

    async fn store_sender_key(
        &self,
        sender_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalError> {
        let key_id = sender_name.to_string();
        let mut entries = HashMap::new();
        entries.insert(key_id, Some(serde_json::to_value(record)?));
        let mut batch = HashMap::new();
        batch.insert("sender-key".to_string(), entries);
        self.auth.set_keys(batch).await?;
        Ok(())
    }

    pub async fn load_identity_key(&self, id: &str) -> Option<Vec<u8>> {
        let wire_jid = self.resolve_lid_signal_address(id).await;
        let stored = self
            .auth
            .get_keys("identity-key", &[wire_jid.clone()])
            .await;
        let val = stored.get(&wire_jid)?.as_ref()?;
        serde_json::from_value::<Vec<u8>>(val.clone()).ok()
    }

    pub async fn save_identity(&self, id: &str, identity_key: &[u8]) -> Result<bool, SignalError> {
        let wire_jid = self.resolve_lid_signal_address(id).await;
        let existing = self.load_identity_key(id).await;
        let keys_match = existing.as_deref() == Some(identity_key);

        if existing.is_some() && !keys_match {
            let mut session_map = HashMap::new();
            session_map.insert(wire_jid.clone(), None);
            let mut id_map = HashMap::new();
            id_map.insert(wire_jid, Some(serde_json::to_value(identity_key)?));
            let mut batch = HashMap::new();
            batch.insert("session".to_string(), session_map);
            batch.insert("identity-key".to_string(), id_map);
            self.auth.set_keys(batch).await?;
            return Ok(true);
        }

        if existing.is_none() {
            let mut id_map = HashMap::new();
            id_map.insert(wire_jid, Some(serde_json::to_value(identity_key)?));
            let mut batch = HashMap::new();
            batch.insert("identity-key".to_string(), id_map);
            self.auth.set_keys(batch).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn load_pre_key(&self, id: u32) -> Option<KeyPair> {
        let key_id = id.to_string();
        let stored = self.auth.get_keys("pre-key", &[key_id.clone()]).await;
        let val = stored.get(&key_id)?.as_ref()?;
        serde_json::from_value::<KeyPair>(val.clone()).ok()
    }

    async fn remove_pre_key(&self, id: u32) -> Result<(), SignalError> {
        let mut entries = HashMap::new();
        entries.insert(id.to_string(), None);
        let mut batch = HashMap::new();
        batch.insert("pre-key".to_string(), entries);
        self.auth.set_keys(batch).await?;
        Ok(())
    }

    pub async fn inject_e2e_session(
        &self,
        jid: &str,
        session: &E2ESession,
    ) -> Result<(), SignalError> {
        let lock = self.acquire_tx_lock(jid).await;
        let _guard = lock.lock().await;

        let addr = jid_to_signal_protocol_address(jid)?.to_string();
        let mut record = self.load_session(&addr).await.unwrap_or_default();
        let state = SessionState::init_outgoing(
            &self.auth.creds.signed_identity_key,
            self.auth.creds.registration_id,
            session,
        )?;
        record.promote_state(state);
        self.store_session(&addr, &record).await?;
        let _ = self.save_identity(&addr, &session.identity_key).await?;
        Ok(())
    }

    pub async fn encrypt_message(
        &self,
        jid: &str,
        data: &[u8],
    ) -> Result<EncryptedMessage, SignalError> {
        let lock = self.acquire_tx_lock(jid).await;
        let _guard = lock.lock().await;

        let addr = jid_to_signal_protocol_address(jid)?.to_string();
        let mut record = self
            .load_session(&addr)
            .await
            .ok_or(SignalError::Protocol(ProtocolError::NoOpenSession))?;
        let current = record
            .current_session
            .as_mut()
            .ok_or(SignalError::Protocol(ProtocolError::NoOpenSession))?;

        let (cipher_type, ciphertext) = current.encrypt(data)?;
        self.store_session(&addr, &record).await?;

        Ok(EncryptedMessage {
            cipher_type,
            ciphertext,
        })
    }

    pub async fn decrypt_message(
        &self,
        jid: &str,
        cipher_type: MessageCipherType,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SignalError> {
        let lock = self.acquire_tx_lock(jid).await;
        let _guard = lock.lock().await;

        let addr = jid_to_signal_protocol_address(jid)?.to_string();

        if cipher_type == MessageCipherType::Pkmsg {
            if let Some(identity_key) = extract_identity_from_pkmsg(ciphertext) {
                let _ = self.save_identity(&addr, &identity_key).await?;
            }

            let pkmsg = decode_pre_key_signal_message(ciphertext)?;
            let inner_msg = pkmsg
                .message
                .as_deref()
                .ok_or(SignalError::Protocol(ProtocolError::MissingField("message")))?;
            let their_base = pkmsg
                .base_key
                .as_deref()
                .ok_or(SignalError::Protocol(ProtocolError::MissingField("base_key")))?;
            let their_base_33 = generate_signal_pub_key(their_base);

            let mut record = self.load_session(&addr).await.unwrap_or_default();
            let mut used_pre_key_id: Option<u32> = None;

            if !record.has_session_with_base_key(&their_base_33) {
                let pre_key = if let Some(pk_id) = pkmsg.pre_key_id {
                    used_pre_key_id = Some(pk_id);
                    Some(
                        self.load_pre_key(pk_id)
                            .await
                            .ok_or(SignalError::MissingPreKey(pk_id))?,
                    )
                } else {
                    None
                };

                let incoming_state = SessionState::init_incoming(
                    &self.auth.creds.signed_identity_key,
                    self.auth.creds.registration_id,
                    &self.auth.creds.signed_pre_key.key_pair,
                    pre_key.as_ref(),
                    &pkmsg,
                )?;
                record.promote_state(incoming_state);
            }

            let plaintext = record.decrypt_whisper_message(inner_msg)?;
            self.store_session(&addr, &record).await?;
            if let Some(pk_id) = used_pre_key_id {
                let _ = self.remove_pre_key(pk_id).await;
            }
            return Ok(plaintext);
        }

        let mut record = self
            .load_session(&addr)
            .await
            .ok_or(SignalError::Protocol(ProtocolError::NoOpenSession))?;
        let plaintext = record.decrypt_whisper_message(ciphertext)?;
        self.store_session(&addr, &record).await?;
        Ok(plaintext)
    }

    pub async fn encrypt_group_message(
        &self,
        group: &str,
        me_id: &str,
        data: &[u8],
    ) -> Result<EncryptedGroupMessage, SignalError> {
        let lock = self.acquire_tx_lock(group).await;
        let _guard = lock.lock().await;

        let sender_name = jid_to_signal_sender_key_name(group, me_id)?;
        let mut record = self.load_sender_key(&sender_name).await;
        let skdm = GroupSessionBuilder::create(&mut record)?;
        let ciphertext = GroupCipher::encrypt(&mut record, data)?;
        self.store_sender_key(&sender_name, &record).await?;

        Ok(EncryptedGroupMessage {
            ciphertext,
            sender_key_distribution_message: skdm.serialize().to_vec(),
        })
    }

    pub async fn decrypt_group_message(
        &self,
        group: &str,
        author_jid: &str,
        msg: &[u8],
    ) -> Result<Vec<u8>, SignalError> {
        let lock = self.acquire_tx_lock(group).await;
        let _guard = lock.lock().await;

        let sender_name = jid_to_signal_sender_key_name(group, author_jid)?;
        let mut record = self.load_sender_key(&sender_name).await;
        let plaintext = GroupCipher::decrypt(&mut record, msg)?;
        self.store_sender_key(&sender_name, &record).await?;
        Ok(plaintext)
    }

    pub async fn process_sender_key_distribution_message(
        &self,
        group_id: &str,
        author_jid: &str,
        axolotl_skdm: &[u8],
    ) -> Result<(), SignalError> {
        if group_id.is_empty() {
            return Err(SignalError::MissingGroupId);
        }
        let lock = self.acquire_tx_lock(group_id).await;
        let _guard = lock.lock().await;

        let sender_name = jid_to_signal_sender_key_name(group_id, author_jid)?;
        let sender_msg = SenderKeyDistributionMessage::from_serialized(axolotl_skdm)?;
        let mut record = self.load_sender_key(&sender_name).await;
        GroupSessionBuilder::process(&mut record, &sender_msg);
        self.store_sender_key(&sender_name, &record).await?;
        Ok(())
    }

    pub async fn get_sender_key_distribution_message(
        &self,
        group: &str,
        me_id: &str,
    ) -> Result<Vec<u8>, SignalError> {
        let lock = self.acquire_tx_lock(group).await;
        let _guard = lock.lock().await;

        let sender_name = jid_to_signal_sender_key_name(group, me_id)?;
        let mut record = self.load_sender_key(&sender_name).await;
        let skdm = GroupSessionBuilder::create(&mut record)?;
        self.store_sender_key(&sender_name, &record).await?;
        Ok(skdm.serialize().to_vec())
    }

    pub async fn has_sender_key(&self, group: &str, me_id: &str) -> Result<bool, SignalError> {
        let sender_name = jid_to_signal_sender_key_name(group, me_id)?.to_string();
        let stored = self.auth.get_keys("sender-key", &[sender_name.clone()]).await;
        Ok(stored.get(&sender_name).and_then(|v| v.as_ref()).is_some())
    }

    pub async fn get_session_info(&self, jid: &str) -> Option<SessionInfo> {
        let addr = jid_to_signal_protocol_address(jid).ok()?.to_string();
        let record = self.load_session(&addr).await?;
        let open = record.current_session?;
        Some(SessionInfo {
            base_key: open.base_key,
            registration_id: open.registration_id,
        })
    }

    pub async fn validate_session(&self, jid: &str) -> SessionValidation {
        let Ok(addr) = jid_to_signal_protocol_address(jid) else {
            return SessionValidation {
                exists: false,
                reason: Some("validation error".to_string()),
            };
        };
        let Some(session) = self.load_session(&addr.to_string()).await else {
            return SessionValidation {
                exists: false,
                reason: Some("no session".to_string()),
            };
        };
        if !session.have_open_session() {
            return SessionValidation {
                exists: false,
                reason: Some("no open session".to_string()),
            };
        }
        SessionValidation {
            exists: true,
            reason: None,
        }
    }

    pub async fn delete_session(&self, jids: &[String]) -> Result<(), SignalError> {
        if jids.is_empty() {
            return Ok(());
        }
        let mut updates: HashMap<String, Option<Value>> = HashMap::new();
        for jid in jids {
            let addr = jid_to_signal_protocol_address(jid)?.to_string();
            updates.insert(addr, None);
        }
        let mut batch = HashMap::new();
        batch.insert("session".to_string(), updates);
        self.auth.set_keys(batch).await?;
        Ok(())
    }

    pub async fn migrate_session(
        &self,
        from_jid: &str,
        to_jid: &str,
    ) -> Result<MigrateSessionResult, SignalError> {
        if from_jid.is_empty()
            || (!is_lid_user(Some(to_jid)) && !is_hosted_lid_user(Some(to_jid)))
        {
            return Ok(MigrateSessionResult {
                migrated: 0,
                skipped: 0,
                total: 0,
            });
        }
        if !is_pn_user(Some(from_jid)) && !is_hosted_pn_user(Some(from_jid)) {
            return Ok(MigrateSessionResult {
                migrated: 0,
                skipped: 0,
                total: 1,
            });
        }

        let from_decoded =
            jid_decode(from_jid).ok_or_else(|| SignalError::InvalidJid(from_jid.to_string()))?;
        let user = from_decoded.user;

        let stored_devices = self.auth.get_keys("device-list", &[user.clone()]).await;
        let mut user_devices: Vec<String> = match stored_devices.get(&user).and_then(|v| v.as_ref())
        {
            Some(val) => serde_json::from_value(val.clone()).unwrap_or_default(),
            None => {
                return Ok(MigrateSessionResult {
                    migrated: 0,
                    skipped: 0,
                    total: 0,
                });
            }
        };

        let from_device_str = from_decoded.device.unwrap_or(0).to_string();
        if !user_devices.contains(&from_device_str) {
            user_devices.push(from_device_str);
        }

        let uncached_devices: Vec<String> = {
            let mut cache = self.migrated_session_cache.lock().unwrap();
            cache.retain(|_, ts| ts.elapsed() <= MIGRATED_CACHE_TTL);
            user_devices
                .into_iter()
                .filter(|dev| !cache.contains_key(&format!("{}.{}", user, dev)))
                .collect()
        };

        let device_session_keys: Vec<String> = uncached_devices
            .iter()
            .map(|dev| format!("{}.{}", user, dev))
            .collect();
        let existing_sessions = self.auth.get_keys("session", &device_session_keys).await;

        let mut device_jids = Vec::new();
        for (session_key, session_val) in existing_sessions {
            if session_val.is_some() {
                if let Some((_, device_str)) = session_key.split_once('.') {
                    if let Ok(device_num) = device_str.parse::<u32>() {
                        let jid = if device_num == 99 {
                            format!("{}:99@hosted", user)
                        } else if device_num == 0 {
                            format!("{}@s.whatsapp.net", user)
                        } else {
                            format!("{}:{}@s.whatsapp.net", user, device_num)
                        };
                        device_jids.push(jid);
                    }
                }
            }
        }

        let lock_key = format!("migrate-sessions-{}", to_jid);
        let lock = self.acquire_tx_lock(&lock_key).await;
        let _guard = lock.lock().await;

        let mut ops = Vec::new();
        for jid in device_jids {
            if let Some(lid_with_device) = transfer_device(&jid, to_jid) {
                let from_d = jid_decode(&jid).unwrap();
                let from_addr = jid_to_signal_protocol_address(&jid)?;
                let to_addr = jid_to_signal_protocol_address(&lid_with_device)?;
                ops.push((
                    from_d.user,
                    from_d.device.unwrap_or(0),
                    from_addr.to_string(),
                    to_addr.to_string(),
                ));
            }
        }

        let total_ops = ops.len();
        let pn_addr_strings: Vec<String> = ops
            .iter()
            .map(|(_, _, from_s, _)| from_s.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let pn_sessions = self.auth.get_keys("session", &pn_addr_strings).await;

        let mut session_updates: HashMap<String, Option<Value>> = HashMap::new();
        let mut migrated_count = 0usize;
        let mut migrated_device_keys = Vec::new();

        for (pn_user, device_id, pn_addr_str, lid_addr_str) in ops {
            if let Some(Some(val)) = pn_sessions.get(&pn_addr_str) {
                if let Ok(record) = serde_json::from_value::<SessionRecord>(val.clone()) {
                    if record.have_open_session() {
                        session_updates.insert(lid_addr_str, Some(serde_json::to_value(&record)?));
                        session_updates.insert(pn_addr_str, None);
                        migrated_device_keys.push(format!("{}.{}", pn_user, device_id));
                        migrated_count += 1;
                    }
                }
            }
        }

        if !session_updates.is_empty() {
            let mut batch = HashMap::new();
            batch.insert("session".to_string(), session_updates);
            self.auth.set_keys(batch).await?;

            let mut cache = self.migrated_session_cache.lock().unwrap();
            let now = Instant::now();
            for key in migrated_device_keys {
                cache.insert(key, now);
            }
        }

        Ok(MigrateSessionResult {
            migrated: migrated_count,
            skipped: total_ops.saturating_sub(migrated_count),
            total: total_ops,
        })
    }

    pub fn close(&self) {
        self.migrated_session_cache.lock().unwrap().clear();
        self.lid_mapping.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{E2ESessionPreKey, E2ESessionSignedPreKey};
    use crate::utils::crypto::Curve;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_e2e_x3dh_and_double_ratchet_roundtrip() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir_a = std::env::temp_dir().join(format!("baileys_rs_sig_a_{}", suffix));
        let dir_b = std::env::temp_dir().join(format!("baileys_rs_sig_b_{}", suffix));

        let auth_a = Arc::new(use_multi_file_auth_state(&dir_a).await.unwrap());
        let auth_b = Arc::new(use_multi_file_auth_state(&dir_b).await.unwrap());

        let bob_pre_key = Curve::generate_key_pair();
        let mut pk_map = HashMap::new();
        pk_map.insert(
            "1".to_string(),
            Some(serde_json::to_value(&bob_pre_key).unwrap()),
        );
        let mut pk_batch = HashMap::new();
        pk_batch.insert("pre-key".to_string(), pk_map);
        auth_b.set_keys(pk_batch).await.unwrap();

        let repo_a = LibSignalRepository::new(Arc::clone(&auth_a), None);
        let repo_b = LibSignalRepository::new(Arc::clone(&auth_b), None);

        let bob_bundle = E2ESession {
            registration_id: auth_b.creds.registration_id,
            identity_key: generate_signal_pub_key(&auth_b.creds.signed_identity_key.public),
            signed_pre_key: E2ESessionSignedPreKey {
                key_id: auth_b.creds.signed_pre_key.key_id,
                public_key: generate_signal_pub_key(&auth_b.creds.signed_pre_key.key_pair.public),
                signature: auth_b.creds.signed_pre_key.signature.clone(),
            },
            pre_key: Some(E2ESessionPreKey {
                key_id: 1,
                public_key: generate_signal_pub_key(&bob_pre_key.public),
            }),
        };

        let alice_jid = "573001111111@s.whatsapp.net";
        let bob_jid = "573002222222@s.whatsapp.net";

        repo_a.inject_e2e_session(bob_jid, &bob_bundle).await.unwrap();
        assert!(repo_a.validate_session(bob_jid).await.exists);

        let enc1 = repo_a.encrypt_message(bob_jid, b"hola bob").await.unwrap();
        assert_eq!(enc1.cipher_type, MessageCipherType::Pkmsg);
        assert!(extract_identity_from_pkmsg(&enc1.ciphertext).is_some());

        let dec1 = repo_b
            .decrypt_message(alice_jid, enc1.cipher_type, &enc1.ciphertext)
            .await
            .unwrap();
        assert_eq!(dec1, b"hola bob");

        let enc2 = repo_b
            .encrypt_message(alice_jid, b"hola alice")
            .await
            .unwrap();
        assert_eq!(enc2.cipher_type, MessageCipherType::Msg);

        let dec2 = repo_a
            .decrypt_message(bob_jid, enc2.cipher_type, &enc2.ciphertext)
            .await
            .unwrap();
        assert_eq!(dec2, b"hola alice");

        let enc3 = repo_a.encrypt_message(bob_jid, b"msg 1").await.unwrap();
        let enc4 = repo_a.encrypt_message(bob_jid, b"msg 2").await.unwrap();
        assert_eq!(enc3.cipher_type, MessageCipherType::Msg);

        let dec4 = repo_b
            .decrypt_message(alice_jid, enc4.cipher_type, &enc4.ciphertext)
            .await
            .unwrap();
        let dec3 = repo_b
            .decrypt_message(alice_jid, enc3.cipher_type, &enc3.ciphertext)
            .await
            .unwrap();
        assert_eq!(dec4, b"msg 2");
        assert_eq!(dec3, b"msg 1");

        let _ = tokio::fs::remove_dir_all(&dir_a).await;
        let _ = tokio::fs::remove_dir_all(&dir_b).await;
    }

    #[tokio::test]
    async fn test_group_sender_key_roundtrip() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir_a = std::env::temp_dir().join(format!("baileys_rs_grp_a_{}", suffix));
        let dir_b = std::env::temp_dir().join(format!("baileys_rs_grp_b_{}", suffix));

        let auth_a = Arc::new(use_multi_file_auth_state(&dir_a).await.unwrap());
        let auth_b = Arc::new(use_multi_file_auth_state(&dir_b).await.unwrap());

        let repo_a = LibSignalRepository::new(Arc::clone(&auth_a), None);
        let repo_b = LibSignalRepository::new(Arc::clone(&auth_b), None);

        let group_jid = "120363000123456@g.us";
        let alice_jid = "573001111111@s.whatsapp.net";

        assert!(!repo_a.has_sender_key(group_jid, alice_jid).await.unwrap());

        let enc1 = repo_a
            .encrypt_group_message(group_jid, alice_jid, b"primer mensaje grupal")
            .await
            .unwrap();
        assert!(repo_a.has_sender_key(group_jid, alice_jid).await.unwrap());

        repo_b
            .process_sender_key_distribution_message(
                group_jid,
                alice_jid,
                &enc1.sender_key_distribution_message,
            )
            .await
            .unwrap();

        let dec1 = repo_b
            .decrypt_group_message(group_jid, alice_jid, &enc1.ciphertext)
            .await
            .unwrap();
        assert_eq!(dec1, b"primer mensaje grupal");

        let enc2 = repo_a
            .encrypt_group_message(group_jid, alice_jid, b"segundo mensaje grupal")
            .await
            .unwrap();
        let enc3 = repo_a
            .encrypt_group_message(group_jid, alice_jid, b"tercer mensaje grupal")
            .await
            .unwrap();

        let dec3 = repo_b
            .decrypt_group_message(group_jid, alice_jid, &enc3.ciphertext)
            .await
            .unwrap();
        let dec2 = repo_b
            .decrypt_group_message(group_jid, alice_jid, &enc2.ciphertext)
            .await
            .unwrap();

        assert_eq!(dec3, b"tercer mensaje grupal");
        assert_eq!(dec2, b"segundo mensaje grupal");

        let _ = tokio::fs::remove_dir_all(&dir_a).await;
        let _ = tokio::fs::remove_dir_all(&dir_b).await;
    }
}
