use crate::defaults::MediaType;
use crate::proto::message::AppStateSyncKeyData;
use crate::proto::sync_action_value::{
    ArchiveChatAction, ClearChatAction, ContactAction, DeleteChatAction, DeleteMessageForMeAction,
    LabelAssociationAction, LabelEditAction, MarkChatAsReadAction, MuteAction, PinAction,
    PrivacySettingDisableLinkPreviewsAction, PushNameSetting, QuickReplyAction, StarAction,
    SyncActionMessageRange,
};
use crate::proto::syncd_mutation::SyncdOperation;
use crate::proto::{
    ExternalBlobReference, KeyId, SyncActionData, SyncActionValue, SyncdIndex, SyncdMutation,
    SyncdMutations, SyncdPatch, SyncdRecord, SyncdSnapshot, SyncdValue, SyncdVersion,
};
use crate::types::{
    ChatModification, ChatMutation, LabelAssociation, LabelAssociationType, LastMessageList,
    LidMapping, LtHashState, LtHashValueMac, SyncActionEvent, SyncContact, WaMessageKey,
    WaPatchCreate, WaPatchName,
};
use crate::utils::crypto::{aes_decrypt_with_iv, aes_encrypt_with_iv, hkdf, CryptoError};
use crate::utils::generics::{now_millis, unix_timestamp_seconds};
use crate::utils::lt_hash::LT_HASH_ANTI_TAMPERING;
use crate::utils::messages_media::{
    download_content_from_message, DownloadableMessage, MediaDownloadOptions, MediaError,
};
use crate::utils::sync_action_utils::process_contact_action;
use crate::wa_binary::{
    get_binary_node_child, get_binary_node_children, is_jid_group, jid_normalized_user, BinaryNode,
    BinaryNodeData,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use prost::Message as ProstMessage;
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::future::Future;
use thiserror::Error;

pub const MAX_SYNC_ATTEMPTS: u32 = 2;

#[derive(Debug, Error)]
pub enum ChatUtilsError {
    #[error("missing app state sync key: {0}")]
    MissingKey(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("media error: {0}")]
    Media(#[from] MediaError),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HMAC index verification failed")]
    InvalidIndexMac,
    #[error("invalid patch mac")]
    InvalidPatchMac,
    #[error("invalid encrypted payload length")]
    InvalidEncryptedPayload,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid message range: {0}")]
    InvalidMessageRange(&'static str),
    #[error("empty star messages list")]
    EmptyStarMessages,
}

impl ChatUtilsError {
    pub fn is_missing_key(&self) -> bool {
        matches!(self, ChatUtilsError::MissingKey(_))
    }
}

#[derive(Debug, Clone)]
pub struct AppStateMutationKeys {
    pub index_key: [u8; 32],
    pub value_encryption_key: [u8; 32],
    pub value_mac_key: [u8; 32],
    pub snapshot_mac_key: [u8; 32],
    pub patch_mac_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct EncodedPatchResult {
    pub patch: SyncdPatch,
    pub state: LtHashState,
}

#[derive(Debug, Clone)]
pub struct ExtractedCollectionPatches {
    pub patches: Vec<SyncdPatch>,
    pub has_more_patches: bool,
    pub snapshot: Option<SyncdSnapshot>,
}

#[derive(Debug, Clone)]
pub struct DecodedAppStateResult {
    pub state: LtHashState,
    pub mutation_map: HashMap<String, ChatMutation>,
}

pub fn expand_app_state_keys(key_data: &[u8]) -> Result<AppStateMutationKeys, CryptoError> {
    let expanded = hkdf(key_data, 160, None, b"WhatsApp Mutation Keys")?;
    Ok(AppStateMutationKeys {
        index_key: expanded[0..32].try_into().unwrap(),
        value_encryption_key: expanded[32..64].try_into().unwrap(),
        value_mac_key: expanded[64..96].try_into().unwrap(),
        snapshot_mac_key: expanded[96..128].try_into().unwrap(),
        patch_mac_key: expanded[128..160].try_into().unwrap(),
    })
}

fn hmac_sha256(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn aes_encrypt_prefixed_iv(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let ciphertext = aes_encrypt_with_iv(plaintext, key, &iv)?;
    let mut out = Vec::with_capacity(16 + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn aes_decrypt_prefixed_iv(payload: &[u8], key: &[u8]) -> Result<Vec<u8>, ChatUtilsError> {
    if payload.len() <= 16 {
        return Err(ChatUtilsError::InvalidEncryptedPayload);
    }
    let iv = &payload[..16];
    let ciphertext = &payload[16..];
    Ok(aes_decrypt_with_iv(ciphertext, key, iv)?)
}

fn generate_mac(
    operation: i32,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let op_byte: u8 = if operation == SyncdOperation::Set as i32 {
        0x01
    } else {
        0x02
    };
    let mut key_data = Vec::with_capacity(1 + key_id.len());
    key_data.push(op_byte);
    key_data.extend_from_slice(key_id);

    let mut last = [0u8; 8];
    last[7] = key_data.len() as u8;

    let mut total = Vec::with_capacity(key_data.len() + data.len() + 8);
    total.extend_from_slice(&key_data);
    total.extend_from_slice(data);
    total.extend_from_slice(&last);

    let full = hmac_sha512(&total, key)?;
    Ok(full[..32].to_vec())
}

fn to_64bit_network_order(version: u64) -> [u8; 8] {
    version.to_be_bytes()
}

fn generate_snapshot_mac(
    lt_hash: &[u8],
    version: u64,
    name: WaPatchName,
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let name_bytes = name.as_str().as_bytes();
    let mut total = Vec::with_capacity(lt_hash.len() + 8 + name_bytes.len());
    total.extend_from_slice(lt_hash);
    total.extend_from_slice(&to_64bit_network_order(version));
    total.extend_from_slice(name_bytes);
    hmac_sha256(&total, key)
}

fn generate_patch_mac(
    snapshot_mac: &[u8],
    value_macs: &[&[u8]],
    version: u64,
    name: WaPatchName,
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let name_bytes = name.as_str().as_bytes();
    let value_macs_len: usize = value_macs.iter().map(|m| m.len()).sum();
    let mut total = Vec::with_capacity(snapshot_mac.len() + value_macs_len + 8 + name_bytes.len());
    total.extend_from_slice(snapshot_mac);
    for vm in value_macs {
        total.extend_from_slice(vm);
    }
    total.extend_from_slice(&to_64bit_network_order(version));
    total.extend_from_slice(name_bytes);
    hmac_sha256(&total, key)
}

pub fn parse_wa_patch_name(name: &str) -> Option<WaPatchName> {
    match name {
        "critical_block" => Some(WaPatchName::CriticalBlock),
        "critical_unblock_low" => Some(WaPatchName::CriticalUnblockLow),
        "regular_high" => Some(WaPatchName::RegularHigh),
        "regular_low" => Some(WaPatchName::RegularLow),
        "regular" => Some(WaPatchName::Regular),
        _ => None,
    }
}

pub fn new_lt_hash_state() -> LtHashState {
    LtHashState {
        version: 0,
        hash: vec![0u8; 128],
        index_value_map: HashMap::new(),
    }
}

pub struct LtHashGenerator {
    hash: Vec<u8>,
    index_value_map: HashMap<String, LtHashValueMac>,
    add_buffs: Vec<Vec<u8>>,
    sub_buffs: Vec<Vec<u8>>,
}

impl LtHashGenerator {
    pub fn new(state: &LtHashState) -> Self {
        Self {
            hash: state.hash.clone(),
            index_value_map: state.index_value_map.clone(),
            add_buffs: Vec::new(),
            sub_buffs: Vec::new(),
        }
    }

    pub fn mix(&mut self, index_mac: &[u8], value_mac: &[u8], operation: i32) {
        let index_b64 = BASE64.encode(index_mac);
        let prev_op = self.index_value_map.get(&index_b64).cloned();

        if operation == SyncdOperation::Remove as i32 {
            if prev_op.is_none() {
                return;
            }
            self.index_value_map.remove(&index_b64);
        } else {
            self.add_buffs.push(value_mac.to_vec());
            self.index_value_map.insert(
                index_b64,
                LtHashValueMac {
                    value_mac: value_mac.to_vec(),
                },
            );
        }

        if let Some(prev) = prev_op {
            self.sub_buffs.push(prev.value_mac);
        }
    }

    pub fn finish(self) -> Result<(Vec<u8>, HashMap<String, LtHashValueMac>), CryptoError> {
        let hash =
            LT_HASH_ANTI_TAMPERING.subtract_then_add(&self.hash, &self.sub_buffs, &self.add_buffs)?;
        Ok((hash, self.index_value_map))
    }
}

pub fn is_app_state_sync_irrecoverable(attempts: u32) -> bool {
    attempts >= MAX_SYNC_ATTEMPTS
}

pub async fn encode_syncd_patch<F, Fut>(
    patch_create: WaPatchCreate,
    my_app_state_key_id: &str,
    initial_state: &LtHashState,
    mut get_app_state_sync_key: F,
) -> Result<EncodedPatchResult, ChatUtilsError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<AppStateSyncKeyData>>,
{
    if my_app_state_key_id.is_empty() {
        return Err(ChatUtilsError::MissingKey(String::new()));
    }

    let key = get_app_state_sync_key(my_app_state_key_id.to_string())
        .await
        .ok_or_else(|| ChatUtilsError::MissingKey(my_app_state_key_id.to_string()))?;
    let key_data = key
        .key_data
        .as_deref()
        .ok_or(ChatUtilsError::MissingField("key_data"))?;

    let enc_key_id = BASE64.decode(my_app_state_key_id)?;
    let mut state = initial_state.clone();

    let index_buffer = serde_json::to_vec(&patch_create.index)?;
    let data_proto = SyncActionData {
        index: Some(index_buffer.clone()),
        value: Some(patch_create.sync_action),
        padding: Some(Vec::new()),
        version: Some(patch_create.api_version),
    };
    let encoded = data_proto.encode_to_vec();

    let key_value = expand_app_state_keys(key_data)?;
    let enc_value = aes_encrypt_prefixed_iv(&encoded, &key_value.value_encryption_key)?;
    let value_mac = generate_mac(
        patch_create.operation,
        &enc_value,
        &enc_key_id,
        &key_value.value_mac_key,
    )?;
    let index_mac = hmac_sha256(&index_buffer, &key_value.index_key)?;

    let mut generator = LtHashGenerator::new(&state);
    generator.mix(&index_mac, &value_mac, patch_create.operation);
    let (new_hash, mut new_map) = generator.finish()?;
    state.hash = new_hash;
    state.version = state.version.saturating_add(1);

    let snapshot_mac = generate_snapshot_mac(
        &state.hash,
        state.version,
        patch_create.patch_type,
        &key_value.snapshot_mac_key,
    )?;
    let patch_mac = generate_patch_mac(
        &snapshot_mac,
        &[value_mac.as_slice()],
        state.version,
        patch_create.patch_type,
        &key_value.patch_mac_key,
    )?;

    let mut value_blob = Vec::with_capacity(enc_value.len() + value_mac.len());
    value_blob.extend_from_slice(&enc_value);
    value_blob.extend_from_slice(&value_mac);

    let patch = SyncdPatch {
        patch_mac: Some(patch_mac),
        snapshot_mac: Some(snapshot_mac),
        key_id: Some(KeyId {
            id: Some(enc_key_id.clone()),
        }),
        mutations: vec![SyncdMutation {
            operation: Some(patch_create.operation),
            record: Some(SyncdRecord {
                index: Some(SyncdIndex {
                    blob: Some(index_mac.clone()),
                }),
                value: Some(SyncdValue {
                    blob: Some(value_blob),
                }),
                key_id: Some(KeyId {
                    id: Some(enc_key_id),
                }),
            }),
        }],
        ..Default::default()
    };

    new_map.insert(BASE64.encode(&index_mac), LtHashValueMac { value_mac });
    state.index_value_map = new_map;

    Ok(EncodedPatchResult { patch, state })
}

pub enum SyncdItem<'a> {
    Mutation(&'a SyncdMutation),
    Record(&'a SyncdRecord),
}

pub async fn decode_syncd_mutations<'a, F, Fut, M>(
    items: &[SyncdItem<'a>],
    initial_state: &LtHashState,
    mut get_app_state_sync_key: F,
    mut on_mutation: M,
    validate_macs: bool,
) -> Result<(Vec<u8>, HashMap<String, LtHashValueMac>), ChatUtilsError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<AppStateSyncKeyData>>,
    M: FnMut(ChatMutation),
{
    let mut lt_generator = LtHashGenerator::new(initial_state);
    let mut derived_key_cache: HashMap<String, AppStateMutationKeys> = HashMap::new();

    for item in items {
        let (operation, record) = match item {
            SyncdItem::Mutation(m) => {
                let op = m.operation.unwrap_or(SyncdOperation::Set as i32);
                let Some(rec) = m.record.as_ref() else {
                    continue;
                };
                (op, rec)
            }
            SyncdItem::Record(rec) => (SyncdOperation::Set as i32, *rec),
        };

        let Some(key_id_bytes) = record.key_id.as_ref().and_then(|k| k.id.as_deref()) else {
            continue;
        };
        let base64_key = BASE64.encode(key_id_bytes);

        let keys = if let Some(cached) = derived_key_cache.get(&base64_key) {
            cached.clone()
        } else {
            let key_enc = get_app_state_sync_key(base64_key.clone())
                .await
                .ok_or_else(|| ChatUtilsError::MissingKey(base64_key.clone()))?;
            let Some(key_data) = key_enc.key_data.as_deref() else {
                continue;
            };
            let Ok(expanded) = expand_app_state_keys(key_data) else {
                continue;
            };
            derived_key_cache.insert(base64_key, expanded.clone());
            expanded
        };

        let Some(content) = record.value.as_ref().and_then(|v| v.blob.as_deref()) else {
            continue;
        };
        if content.len() <= 32 {
            continue;
        }
        let split_idx = content.len() - 32;
        let enc_content = &content[..split_idx];
        let og_value_mac = &content[split_idx..];

        if validate_macs {
            let Ok(content_hmac) =
                generate_mac(operation, enc_content, key_id_bytes, &keys.value_mac_key)
            else {
                continue;
            };
            if content_hmac.as_slice() != og_value_mac {
                continue;
            }
        }

        let Ok(decrypted) = aes_decrypt_prefixed_iv(enc_content, &keys.value_encryption_key) else {
            continue;
        };
        let Ok(sync_action) = SyncActionData::decode(decrypted.as_slice()) else {
            continue;
        };

        let Some(index_bytes) = sync_action.index.as_deref() else {
            continue;
        };
        let Some(record_index_blob) = record.index.as_ref().and_then(|idx| idx.blob.as_deref())
        else {
            continue;
        };

        if validate_macs {
            let computed_index_mac = hmac_sha256(index_bytes, &keys.index_key)?;
            if computed_index_mac.as_slice() != record_index_blob {
                return Err(ChatUtilsError::InvalidIndexMac);
            }
        }

        let index: Vec<String> = serde_json::from_slice(index_bytes)?;
        on_mutation(ChatMutation { sync_action, index });

        lt_generator.mix(record_index_blob, og_value_mac, operation);
    }

    Ok(lt_generator.finish()?)
}

pub async fn decode_syncd_patch<F, Fut, M>(
    msg: &SyncdPatch,
    name: WaPatchName,
    initial_state: &LtHashState,
    mut get_app_state_sync_key: F,
    on_mutation: M,
    validate_macs: bool,
) -> Result<(Vec<u8>, HashMap<String, LtHashValueMac>), ChatUtilsError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<AppStateSyncKeyData>>,
    M: FnMut(ChatMutation),
{
    if validate_macs {
        let key_id_bytes = msg
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_deref())
            .ok_or(ChatUtilsError::MissingField("patch.key_id"))?;
        let base64_key = BASE64.encode(key_id_bytes);
        let main_key_obj = get_app_state_sync_key(base64_key.clone())
            .await
            .ok_or(ChatUtilsError::MissingKey(base64_key))?;
        let key_data = main_key_obj
            .key_data
            .as_deref()
            .ok_or(ChatUtilsError::MissingField("key_data"))?;
        let main_key = expand_app_state_keys(key_data)?;

        let mut value_macs: Vec<&[u8]> = Vec::with_capacity(msg.mutations.len());
        for mutation in &msg.mutations {
            let blob = mutation
                .record
                .as_ref()
                .and_then(|r| r.value.as_ref())
                .and_then(|v| v.blob.as_deref())
                .ok_or(ChatUtilsError::MissingField("mutation.record.value.blob"))?;
            if blob.len() < 32 {
                return Err(ChatUtilsError::InvalidPatchMac);
            }
            value_macs.push(&blob[blob.len() - 32..]);
        }

        let snapshot_mac = msg
            .snapshot_mac
            .as_deref()
            .ok_or(ChatUtilsError::MissingField("patch.snapshot_mac"))?;
        let expected_patch_mac = msg
            .patch_mac
            .as_deref()
            .ok_or(ChatUtilsError::MissingField("patch.patch_mac"))?;
        let version = msg
            .version
            .as_ref()
            .and_then(|v| v.version)
            .ok_or(ChatUtilsError::MissingField("patch.version"))?;

        let computed = generate_patch_mac(
            snapshot_mac,
            &value_macs,
            version,
            name,
            &main_key.patch_mac_key,
        )?;
        if computed.as_slice() != expected_patch_mac {
            return Err(ChatUtilsError::InvalidPatchMac);
        }
    }

    let items: Vec<SyncdItem<'_>> = msg.mutations.iter().map(SyncdItem::Mutation).collect();
    decode_syncd_mutations(
        &items,
        initial_state,
        get_app_state_sync_key,
        on_mutation,
        validate_macs,
    )
    .await
}

pub async fn download_external_blob(
    blob: &ExternalBlobReference,
    opts: &MediaDownloadOptions,
) -> Result<Vec<u8>, ChatUtilsError> {
    let downloadable = DownloadableMessage {
        media_key: blob.media_key.clone(),
        direct_path: blob.direct_path.clone(),
        url: None,
    };
    Ok(download_content_from_message(&downloadable, MediaType::MdAppState, opts).await?)
}

pub async fn download_external_patch(
    blob: &ExternalBlobReference,
    opts: &MediaDownloadOptions,
) -> Result<SyncdMutations, ChatUtilsError> {
    let buffer = download_external_blob(blob, opts).await?;
    Ok(SyncdMutations::decode(buffer.as_slice())?)
}

pub async fn extract_syncd_patches(
    result: &BinaryNode,
    opts: &MediaDownloadOptions,
) -> Result<HashMap<WaPatchName, ExtractedCollectionPatches>, ChatUtilsError> {
    let sync_node = get_binary_node_child(Some(result), "sync");
    let collection_nodes = get_binary_node_children(sync_node, "collection");

    let mut final_map = HashMap::new();
    for collection_node in collection_nodes {
        let Some(name_str) = collection_node.attrs.get("name") else {
            continue;
        };
        let Some(name) = parse_wa_patch_name(name_str) else {
            continue;
        };

        let patches_node = get_binary_node_child(Some(collection_node), "patches");
        let patch_nodes =
            get_binary_node_children(Some(patches_node.unwrap_or(collection_node)), "patch");
        let snapshot_node = get_binary_node_child(Some(collection_node), "snapshot");
        let has_more_patches = collection_node
            .attrs
            .get("has_more_patches")
            .is_some_and(|v| v == "true");

        let snapshot = if let Some(sn) = snapshot_node {
            if let Some(BinaryNodeData::Bytes(bytes)) = &sn.content {
                let blob_ref = ExternalBlobReference::decode(bytes.as_slice())?;
                let data = download_external_blob(&blob_ref, opts).await?;
                Some(SyncdSnapshot::decode(data.as_slice())?)
            } else {
                None
            }
        } else {
            None
        };

        let base_version = collection_node
            .attrs
            .get("version")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let mut syncds = Vec::new();
        for patch_node in patch_nodes {
            if let Some(BinaryNodeData::Bytes(bytes)) = &patch_node.content {
                let mut syncd = SyncdPatch::decode(bytes.as_slice())?;
                if syncd.version.is_none() {
                    syncd.version = Some(SyncdVersion {
                        version: Some(base_version + 1),
                    });
                }
                syncds.push(syncd);
            }
        }

        final_map.insert(
            name,
            ExtractedCollectionPatches {
                patches: syncds,
                has_more_patches,
                snapshot,
            },
        );
    }

    Ok(final_map)
}

pub async fn decode_syncd_snapshot<F, Fut>(
    name: WaPatchName,
    snapshot: &SyncdSnapshot,
    mut get_app_state_sync_key: F,
    minimum_version_number: Option<u64>,
    validate_macs: bool,
) -> Result<DecodedAppStateResult, ChatUtilsError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<AppStateSyncKeyData>>,
{
    let mut new_state = new_lt_hash_state();
    new_state.version = snapshot
        .version
        .as_ref()
        .and_then(|v| v.version)
        .unwrap_or(0);

    let mut mutation_map = HashMap::new();
    let are_mutations_required =
        minimum_version_number.is_none_or(|min_v| new_state.version > min_v);

    let items: Vec<SyncdItem<'_>> = snapshot.records.iter().map(SyncdItem::Record).collect();
    let (hash, index_value_map) = decode_syncd_mutations(
        &items,
        &new_state,
        &mut get_app_state_sync_key,
        |mutation| {
            if are_mutations_required {
                if let Some(idx_bytes) = mutation.sync_action.index.as_deref() {
                    let key = String::from_utf8_lossy(idx_bytes).into_owned();
                    mutation_map.insert(key, mutation);
                }
            }
        },
        validate_macs,
    )
    .await?;

    new_state.hash = hash;
    new_state.index_value_map = index_value_map;

    if validate_macs {
        let key_id_bytes = snapshot
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_deref())
            .ok_or(ChatUtilsError::MissingField("snapshot.key_id"))?;
        let base64_key = BASE64.encode(key_id_bytes);
        let key_enc = get_app_state_sync_key(base64_key.clone())
            .await
            .ok_or(ChatUtilsError::MissingKey(base64_key))?;
        let key_data = key_enc
            .key_data
            .as_deref()
            .ok_or(ChatUtilsError::MissingField("key_data"))?;
        let keys = expand_app_state_keys(key_data)?;
        let _computed_snapshot_mac =
            generate_snapshot_mac(&new_state.hash, new_state.version, name, &keys.snapshot_mac_key)?;
    }

    Ok(DecodedAppStateResult {
        state: new_state,
        mutation_map,
    })
}

pub async fn decode_patches<F, Fut>(
    name: WaPatchName,
    syncds: &mut [SyncdPatch],
    initial: &LtHashState,
    mut get_app_state_sync_key: F,
    opts: &MediaDownloadOptions,
    minimum_version_number: Option<u64>,
    validate_macs: bool,
) -> Result<DecodedAppStateResult, ChatUtilsError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<AppStateSyncKeyData>>,
{
    let mut new_state = initial.clone();
    let mut mutation_map = HashMap::new();

    for syncd in syncds.iter_mut() {
        if let Some(ref ext_ref) = syncd.external_mutations {
            let ext_mutations = download_external_patch(ext_ref, opts).await?;
            syncd.mutations.extend(ext_mutations.mutations);
        }

        let patch_version = syncd.version.as_ref().and_then(|v| v.version).unwrap_or(0);
        new_state.version = patch_version;
        let should_mutate = minimum_version_number.is_none_or(|min_v| patch_version > min_v);

        let decode_res = decode_syncd_patch(
            syncd,
            name,
            &new_state,
            &mut get_app_state_sync_key,
            |mutation| {
                if should_mutate {
                    if let Some(idx_bytes) = mutation.sync_action.index.as_deref() {
                        let key = String::from_utf8_lossy(idx_bytes).into_owned();
                        mutation_map.insert(key, mutation);
                    }
                }
            },
            validate_macs,
        )
        .await;

        let (hash, index_value_map) = match decode_res {
            Ok(pair) => pair,
            Err(err) if err.is_missing_key() => return Err(err),
            Err(_) => continue,
        };

        new_state.hash = hash;
        new_state.index_value_map = index_value_map;

        if validate_macs {
            let key_id_bytes = syncd
                .key_id
                .as_ref()
                .and_then(|k| k.id.as_deref())
                .ok_or(ChatUtilsError::MissingField("patch.key_id"))?;
            let base64_key = BASE64.encode(key_id_bytes);
            let key_enc = get_app_state_sync_key(base64_key.clone())
                .await
                .ok_or(ChatUtilsError::MissingKey(base64_key))?;
            let key_data = key_enc
                .key_data
                .as_deref()
                .ok_or(ChatUtilsError::MissingField("key_data"))?;
            let keys = expand_app_state_keys(key_data)?;
            let computed = generate_snapshot_mac(
                &new_state.hash,
                new_state.version,
                name,
                &keys.snapshot_mac_key,
            )?;
            if syncd.snapshot_mac.as_deref() != Some(computed.as_slice()) {
                break;
            }
        }

        syncd.mutations.clear();
    }

    Ok(DecodedAppStateResult {
        state: new_state,
        mutation_map,
    })
}

fn build_message_range(
    last_messages: LastMessageList,
) -> Result<SyncActionMessageRange, ChatUtilsError> {
    match last_messages {
        LastMessageList::Range(range) => Ok(range),
        LastMessageList::Messages(mut list) => {
            let last_ts = list.last().and_then(|m| m.timestamp);
            for m in &mut list {
                let key = m
                    .key
                    .as_mut()
                    .ok_or(ChatUtilsError::InvalidMessageRange("incomplete key"))?;
                let remote_jid = key
                    .remote_jid
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or(ChatUtilsError::InvalidMessageRange("incomplete key"))?;
                if key.id.as_deref().is_none_or(|s| s.is_empty()) {
                    return Err(ChatUtilsError::InvalidMessageRange("incomplete key"));
                }
                if is_jid_group(Some(remote_jid))
                    && key.from_me != Some(true)
                    && key.participant.as_deref().is_none_or(|s| s.is_empty())
                {
                    return Err(ChatUtilsError::InvalidMessageRange(
                        "expected not from me group message to have participant",
                    ));
                }
                if m.timestamp.unwrap_or(0) == 0 {
                    return Err(ChatUtilsError::InvalidMessageRange(
                        "missing timestamp in last message list",
                    ));
                }
                if let Some(ref p) = key.participant {
                    key.participant = Some(jid_normalized_user(Some(p)));
                }
            }
            Ok(SyncActionMessageRange {
                last_message_timestamp: last_ts,
                last_system_message_timestamp: None,
                messages: list,
            })
        }
    }
}

pub fn chat_modification_to_app_patch(
    modification: ChatModification,
    jid: &str,
) -> Result<WaPatchCreate, ChatUtilsError> {
    let set_op = SyncdOperation::Set as i32;
    let remove_op = SyncdOperation::Remove as i32;
    let now_ms = now_millis() as i64;

    let mut patch = match modification {
        ChatModification::Mute(mute_end) => WaPatchCreate {
            sync_action: SyncActionValue {
                mute_action: Some(MuteAction {
                    muted: Some(mute_end.is_some()),
                    mute_end_timestamp: mute_end,
                    ..Default::default()
                }),
                ..Default::default()
            },
            index: vec!["mute".to_string(), jid.to_string()],
            patch_type: WaPatchName::RegularHigh,
            api_version: 2,
            operation: set_op,
        },
        ChatModification::Archive {
            archive,
            last_messages,
        } => WaPatchCreate {
            sync_action: SyncActionValue {
                archive_chat_action: Some(ArchiveChatAction {
                    archived: Some(archive),
                    message_range: Some(build_message_range(last_messages)?),
                }),
                ..Default::default()
            },
            index: vec!["archive".to_string(), jid.to_string()],
            patch_type: WaPatchName::RegularLow,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::MarkRead {
            mark_read,
            last_messages,
        } => WaPatchCreate {
            sync_action: SyncActionValue {
                mark_chat_as_read_action: Some(MarkChatAsReadAction {
                    read: Some(mark_read),
                    message_range: Some(build_message_range(last_messages)?),
                }),
                ..Default::default()
            },
            index: vec!["markChatAsRead".to_string(), jid.to_string()],
            patch_type: WaPatchName::RegularLow,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::DeleteForMe {
            key,
            timestamp,
            delete_media,
        } => WaPatchCreate {
            sync_action: SyncActionValue {
                delete_message_for_me_action: Some(DeleteMessageForMeAction {
                    delete_media: Some(delete_media),
                    message_timestamp: Some(timestamp),
                }),
                ..Default::default()
            },
            index: vec![
                "deleteMessageForMe".to_string(),
                jid.to_string(),
                key.id.unwrap_or_default(),
                if key.from_me == Some(true) { "1" } else { "0" }.to_string(),
                "0".to_string(),
            ],
            patch_type: WaPatchName::RegularHigh,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::Clear { last_messages } => WaPatchCreate {
            sync_action: SyncActionValue {
                clear_chat_action: Some(ClearChatAction {
                    message_range: Some(build_message_range(last_messages)?),
                }),
                ..Default::default()
            },
            index: vec![
                "clearChat".to_string(),
                jid.to_string(),
                "1".to_string(),
                "0".to_string(),
            ],
            patch_type: WaPatchName::RegularHigh,
            api_version: 6,
            operation: set_op,
        },
        ChatModification::Pin(pinned) => WaPatchCreate {
            sync_action: SyncActionValue {
                pin_action: Some(PinAction {
                    pinned: Some(pinned),
                }),
                ..Default::default()
            },
            index: vec!["pin_v1".to_string(), jid.to_string()],
            patch_type: WaPatchName::RegularLow,
            api_version: 5,
            operation: set_op,
        },
        ChatModification::Contact(contact_opt) => {
            let operation = if contact_opt.is_some() {
                set_op
            } else {
                remove_op
            };
            WaPatchCreate {
                sync_action: SyncActionValue {
                    contact_action: Some(contact_opt.unwrap_or_default()),
                    ..Default::default()
                },
                index: vec!["contact".to_string(), jid.to_string()],
                patch_type: WaPatchName::CriticalUnblockLow,
                api_version: 2,
                operation,
            }
        }
        ChatModification::DisableLinkPreviews(disabled) => WaPatchCreate {
            sync_action: SyncActionValue {
                privacy_setting_disable_link_previews_action: Some(
                    PrivacySettingDisableLinkPreviewsAction {
                        is_previews_disabled: Some(disabled),
                    },
                ),
                ..Default::default()
            },
            index: vec!["setting_disableLinkPreviews".to_string()],
            patch_type: WaPatchName::Regular,
            api_version: 8,
            operation: set_op,
        },
        ChatModification::Star { messages, star } => {
            let first = messages
                .first()
                .ok_or(ChatUtilsError::EmptyStarMessages)?;
            WaPatchCreate {
                sync_action: SyncActionValue {
                    star_action: Some(StarAction {
                        starred: Some(star),
                    }),
                    ..Default::default()
                },
                index: vec![
                    "star".to_string(),
                    jid.to_string(),
                    first.id.clone(),
                    if first.from_me { "1" } else { "0" }.to_string(),
                    "0".to_string(),
                ],
                patch_type: WaPatchName::RegularLow,
                api_version: 2,
                operation: set_op,
            }
        }
        ChatModification::Delete { last_messages } => WaPatchCreate {
            sync_action: SyncActionValue {
                delete_chat_action: Some(DeleteChatAction {
                    message_range: Some(build_message_range(last_messages)?),
                }),
                ..Default::default()
            },
            index: vec!["deleteChat".to_string(), jid.to_string(), "1".to_string()],
            patch_type: WaPatchName::RegularHigh,
            api_version: 6,
            operation: set_op,
        },
        ChatModification::PushNameSetting(name) => WaPatchCreate {
            sync_action: SyncActionValue {
                push_name_setting: Some(PushNameSetting { name: Some(name) }),
                ..Default::default()
            },
            index: vec!["setting_pushName".to_string()],
            patch_type: WaPatchName::CriticalBlock,
            api_version: 1,
            operation: set_op,
        },
        ChatModification::QuickReply(qr) => {
            let ts = qr
                .timestamp
                .unwrap_or_else(|| unix_timestamp_seconds().to_string());
            WaPatchCreate {
                sync_action: SyncActionValue {
                    quick_reply_action: Some(QuickReplyAction {
                        count: Some(0),
                        deleted: Some(qr.deleted),
                        keywords: Vec::new(),
                        message: Some(qr.message.unwrap_or_default()),
                        shortcut: Some(qr.shortcut.unwrap_or_default()),
                    }),
                    ..Default::default()
                },
                index: vec!["quick_reply".to_string(), ts],
                patch_type: WaPatchName::Regular,
                api_version: 2,
                operation: set_op,
            }
        }
        ChatModification::AddLabel(label) => WaPatchCreate {
            sync_action: SyncActionValue {
                label_edit_action: Some(LabelEditAction {
                    name: Some(label.name),
                    color: Some(label.color),
                    predefined_id: label.predefined_id,
                    deleted: Some(label.deleted),
                    ..Default::default()
                }),
                ..Default::default()
            },
            index: vec!["label_edit".to_string(), label.id],
            patch_type: WaPatchName::Regular,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::AddChatLabel { label_id } => WaPatchCreate {
            sync_action: SyncActionValue {
                label_association_action: Some(LabelAssociationAction {
                    labeled: Some(true),
                }),
                ..Default::default()
            },
            index: vec![
                LabelAssociationType::Chat.as_str().to_string(),
                label_id,
                jid.to_string(),
            ],
            patch_type: WaPatchName::Regular,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::RemoveChatLabel { label_id } => WaPatchCreate {
            sync_action: SyncActionValue {
                label_association_action: Some(LabelAssociationAction {
                    labeled: Some(false),
                }),
                ..Default::default()
            },
            index: vec![
                LabelAssociationType::Chat.as_str().to_string(),
                label_id,
                jid.to_string(),
            ],
            patch_type: WaPatchName::Regular,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::AddMessageLabel {
            message_id,
            label_id,
        } => WaPatchCreate {
            sync_action: SyncActionValue {
                label_association_action: Some(LabelAssociationAction {
                    labeled: Some(true),
                }),
                ..Default::default()
            },
            index: vec![
                LabelAssociationType::Message.as_str().to_string(),
                label_id,
                jid.to_string(),
                message_id,
                "0".to_string(),
                "0".to_string(),
            ],
            patch_type: WaPatchName::Regular,
            api_version: 3,
            operation: set_op,
        },
        ChatModification::RemoveMessageLabel {
            message_id,
            label_id,
        } => WaPatchCreate {
            sync_action: SyncActionValue {
                label_association_action: Some(LabelAssociationAction {
                    labeled: Some(false),
                }),
                ..Default::default()
            },
            index: vec![
                LabelAssociationType::Message.as_str().to_string(),
                label_id,
                jid.to_string(),
                message_id,
                "0".to_string(),
                "0".to_string(),
            ],
            patch_type: WaPatchName::Regular,
            api_version: 3,
            operation: set_op,
        },
    };

    patch.sync_action.timestamp = Some(now_ms);
    Ok(patch)
}

pub fn is_valid_patch_based_on_message_range(
    chat_last_msg_timestamp: u64,
    msg_range: Option<&SyncActionMessageRange>,
) -> bool {
    let last_msg_ts = msg_range
        .and_then(|r| r.last_message_timestamp.or(r.last_system_message_timestamp))
        .unwrap_or(0)
        .max(0) as u64;
    last_msg_ts >= chat_last_msg_timestamp
}

pub fn process_sync_action(
    mutation: &ChatMutation,
    me_name: Option<&str>,
    is_initial_sync: bool,
    unarchive_chats_setting: bool,
) -> Vec<SyncActionEvent> {
    let mut events = Vec::new();
    let action = mutation.sync_action.value.as_ref();
    let action_type = mutation.index.first().map(|s| s.as_str()).unwrap_or("");
    let id = mutation.index.get(1).map(|s| s.as_str());
    let msg_id = mutation.index.get(2).cloned();
    let from_me = mutation.index.get(3).map(|s| s.as_str() == "1");

    if let Some(mute_action) = action.and_then(|a| a.mute_action.as_ref()) {
        if let Some(chat_id) = id {
            let mute_end_time = if mute_action.muted == Some(true) {
                mute_action.mute_end_timestamp
            } else {
                None
            };
            events.push(SyncActionEvent::ChatMuteUpdate {
                id: chat_id.to_string(),
                mute_end_time,
            });
        }
    } else if action
        .and_then(|a| a.archive_chat_action.as_ref())
        .is_some()
        || action_type == "archive"
        || action_type == "unarchive"
    {
        if let Some(chat_id) = id {
            let archive_action = action.and_then(|a| a.archive_chat_action.as_ref());
            let archived = archive_action
                .and_then(|a| a.archived)
                .unwrap_or(action_type == "archive");
            let message_range = if unarchive_chats_setting {
                archive_action.and_then(|a| a.message_range.clone())
            } else {
                None
            };
            events.push(SyncActionEvent::ChatArchiveUpdate {
                id: chat_id.to_string(),
                archived,
                message_range,
            });
        }
    } else if let Some(mark_read) = action.and_then(|a| a.mark_chat_as_read_action.as_ref()) {
        if let Some(chat_id) = id {
            let is_read = mark_read.read == Some(true);
            let is_null_update = is_initial_sync && is_read;
            let unread_count = if is_null_update {
                None
            } else if is_read {
                Some(0)
            } else {
                Some(-1)
            };
            events.push(SyncActionEvent::ChatReadUpdate {
                id: chat_id.to_string(),
                unread_count,
                message_range: mark_read.message_range.clone(),
            });
        }
    } else if action
        .and_then(|a| a.delete_message_for_me_action.as_ref())
        .is_some()
        || action_type == "deleteMessageForMe"
    {
        events.push(SyncActionEvent::MessagesDelete(vec![WaMessageKey {
            remote_jid: id.map(String::from),
            id: msg_id,
            from_me,
            ..Default::default()
        }]));
    } else if let Some(contact_action) = action.and_then(|a| a.contact_action.as_ref()) {
        events.extend(process_contact_action(contact_action, id));
    } else if let Some(push_name) = action.and_then(|a| a.push_name_setting.as_ref()) {
        if let Some(name) = push_name.name.as_deref().filter(|s| !s.is_empty()) {
            if me_name != Some(name) {
                events.push(SyncActionEvent::CredsPushNameUpdate(name.to_string()));
            }
        }
    } else if let Some(pin_action) = action.and_then(|a| a.pin_action.as_ref()) {
        if let Some(chat_id) = id {
            let pinned = if pin_action.pinned == Some(true) {
                action.and_then(|a| a.timestamp)
            } else {
                None
            };
            events.push(SyncActionEvent::ChatPinUpdate {
                id: chat_id.to_string(),
                pinned,
            });
        }
    } else if let Some(unarchive_setting) = action.and_then(|a| a.unarchive_chats_setting.as_ref())
    {
        events.push(SyncActionEvent::CredsUnarchiveChatsUpdate(
            unarchive_setting.unarchive_chats == Some(true),
        ));
    } else if action.and_then(|a| a.star_action.as_ref()).is_some() || action_type == "star" {
        let starred = action
            .and_then(|a| a.star_action.as_ref())
            .and_then(|s| s.starred)
            .unwrap_or_else(|| mutation.index.last().is_some_and(|v| v == "1"));
        events.push(SyncActionEvent::MessageStarUpdate {
            key: WaMessageKey {
                remote_jid: id.map(String::from),
                id: msg_id,
                from_me,
                ..Default::default()
            },
            starred,
        });
    } else if action.and_then(|a| a.delete_chat_action.as_ref()).is_some()
        || action_type == "deleteChat"
    {
        if !is_initial_sync {
            if let Some(chat_id) = id {
                events.push(SyncActionEvent::ChatDelete(vec![chat_id.to_string()]));
            }
        }
    } else if let Some(label_edit) = action.and_then(|a| a.label_edit_action.as_ref()) {
        if let Some(label_id) = id {
            events.push(SyncActionEvent::LabelEdit {
                id: label_id.to_string(),
                name: label_edit.name.clone().unwrap_or_default(),
                color: label_edit.color.unwrap_or(0),
                deleted: label_edit.deleted.unwrap_or(false),
                predefined_id: label_edit.predefined_id.map(|p| p.to_string()),
            });
        }
    } else if let Some(label_assoc) = action.and_then(|a| a.label_association_action.as_ref()) {
        let added = label_assoc.labeled == Some(true);
        let label_id = mutation.index.get(1).cloned().unwrap_or_default();
        let chat_id = mutation.index.get(2).cloned().unwrap_or_default();
        let association = if action_type == LabelAssociationType::Chat.as_str() {
            LabelAssociation::Chat { chat_id, label_id }
        } else {
            let message_id = mutation.index.get(3).cloned().unwrap_or_default();
            LabelAssociation::Message {
                chat_id,
                message_id,
                label_id,
            }
        };
        events.push(SyncActionEvent::LabelAssociation { added, association });
    } else if let Some(locale) = action
        .and_then(|a| a.locale_setting.as_ref())
        .and_then(|l| l.locale.as_deref())
        .filter(|s| !s.is_empty())
    {
        events.push(SyncActionEvent::SettingLocale(locale.to_string()));
    } else if let Some(tf) = action.and_then(|a| a.time_format_action.as_ref()) {
        events.push(SyncActionEvent::SettingTimeFormat(tf.clone()));
    } else if let Some(pn_for_lid) = action.and_then(|a| a.pn_for_lid_chat_action.as_ref()) {
        if let (Some(lid), Some(pn)) = (id, pn_for_lid.pn_jid.as_deref().filter(|s| !s.is_empty()))
        {
            events.push(SyncActionEvent::LidMappingUpdate(LidMapping {
                lid: lid.to_string(),
                pn: pn.to_string(),
            }));
        }
    } else if let Some(relay) = action.and_then(|a| a.privacy_setting_relay_all_calls.as_ref()) {
        events.push(SyncActionEvent::SettingRelayAllCalls(relay.clone()));
    } else if let Some(sp) = action.and_then(|a| a.status_privacy.as_ref()) {
        events.push(SyncActionEvent::SettingStatusPrivacy(sp.clone()));
    } else if let Some(lock_chat) = action.and_then(|a| a.lock_chat_action.as_ref()) {
        if let Some(chat_id) = id {
            events.push(SyncActionEvent::ChatLock {
                id: chat_id.to_string(),
                locked: lock_chat.locked == Some(true),
            });
        }
    } else if let Some(dlp) = action
        .and_then(|a| a.privacy_setting_disable_link_previews_action.as_ref())
    {
        events.push(SyncActionEvent::SettingDisableLinkPreviews(dlp.clone()));
    } else if let Some(notif_setting) = action
        .and_then(|a| a.notification_activity_setting_action.as_ref())
        .and_then(|n| n.notification_activity_setting)
    {
        events.push(SyncActionEvent::SettingNotificationActivity(notif_setting));
    } else if let Some(lid_contact) = action.and_then(|a| a.lid_contact_action.as_ref()) {
        if let Some(lid_id) = id {
            let name = lid_contact
                .full_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .or_else(|| lid_contact.first_name.as_deref().filter(|s| !s.is_empty()))
                .or_else(|| lid_contact.username.as_deref().filter(|s| !s.is_empty()))
                .map(String::from);
            events.push(SyncActionEvent::ContactsUpsert(vec![SyncContact {
                id: lid_id.to_string(),
                name,
                username: lid_contact
                    .username
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                lid: Some(lid_id.to_string()),
                phone_number: None,
            }]));
        }
    } else if let Some(rec) = action.and_then(|a| {
        a.privacy_setting_channels_personalised_recommendation_action
            .as_ref()
    }) {
        events.push(SyncActionEvent::SettingChannelsPersonalisedRecommendation(
            rec.is_user_opted_out != Some(true),
        ));
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StarMessageTarget;

    #[tokio::test]
    async fn test_encode_and_decode_syncd_patch_roundtrip() {
        let key_id_b64 = BASE64.encode(b"key-001");
        let sync_key = AppStateSyncKeyData {
            key_data: Some(vec![42u8; 32]),
            ..Default::default()
        };

        let patch_create = chat_modification_to_app_patch(
            ChatModification::Pin(true),
            "573001111111@s.whatsapp.net",
        )
        .unwrap();

        let initial = new_lt_hash_state();
        let encoded = encode_syncd_patch(patch_create, &key_id_b64, &initial, |_| {
            let k = sync_key.clone();
            async move { Some(k) }
        })
        .await
        .unwrap();

        assert_eq!(encoded.state.version, 1);

        let mut patch_with_version = encoded.patch.clone();
        patch_with_version.version = Some(SyncdVersion { version: Some(1) });

        let mut decoded_mutations = Vec::new();
        let (decoded_hash, _) = decode_syncd_patch(
            &patch_with_version,
            WaPatchName::RegularLow,
            &initial,
            |_| {
                let k = sync_key.clone();
                async move { Some(k) }
            },
            |m| decoded_mutations.push(m),
            true,
        )
        .await
        .unwrap();

        assert_eq!(decoded_hash, encoded.state.hash);
        assert_eq!(decoded_mutations.len(), 1);
        assert_eq!(
            decoded_mutations[0].index,
            vec!["pin_v1", "573001111111@s.whatsapp.net"]
        );

        let events = process_sync_action(&decoded_mutations[0], None, false, false);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], SyncActionEvent::ChatPinUpdate { .. }));
    }

    #[test]
    fn test_chat_modifications_and_process_sync_actions() {
        let star_patch = chat_modification_to_app_patch(
            ChatModification::Star {
                messages: vec![StarMessageTarget {
                    id: "MSG_9".to_string(),
                    from_me: true,
                }],
                star: true,
            },
            "573002222222@s.whatsapp.net",
        )
        .unwrap();
        assert_eq!(
            star_patch.index,
            vec!["star", "573002222222@s.whatsapp.net", "MSG_9", "1", "0"]
        );

        let mut_data = ChatMutation {
            sync_action: SyncActionData {
                index: Some(serde_json::to_vec(&star_patch.index).unwrap()),
                value: Some(star_patch.sync_action),
                padding: Some(Vec::new()),
                version: Some(2),
            },
            index: star_patch.index,
        };
        let events = process_sync_action(&mut_data, None, false, false);
        assert_eq!(events.len(), 1);
        match &events[0] {
            SyncActionEvent::MessageStarUpdate { key, starred } => {
                assert_eq!(key.id.as_deref(), Some("MSG_9"));
                assert_eq!(key.from_me, Some(true));
                assert!(*starred);
            }
            other => panic!("unexpected event: {:?}", other),
        }

        let push_patch = chat_modification_to_app_patch(
            ChatModification::PushNameSetting("Lufer".to_string()),
            "",
        )
        .unwrap();
        let push_mut = ChatMutation {
            sync_action: SyncActionData {
                index: Some(serde_json::to_vec(&push_patch.index).unwrap()),
                value: Some(push_patch.sync_action),
                padding: Some(Vec::new()),
                version: Some(1),
            },
            index: push_patch.index,
        };
        let push_events = process_sync_action(&push_mut, Some("Old"), false, false);
        assert_eq!(
            push_events,
            vec![SyncActionEvent::CredsPushNameUpdate("Lufer".to_string())]
        );
    }
}
