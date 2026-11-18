use crate::types::LidMapping;
use crate::utils::use_multi_file_auth_state::{AuthStateError, MultiFileAuthState};
use crate::wa_binary::{
    is_hosted_pn_user, is_lid_user, is_pn_user, jid_decode, jid_normalized_user, FullJid,
    WaJidDomains,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(3 * 24 * 60 * 60);

pub type PnToLidCallback = Arc<
    dyn Fn(Vec<String>) -> Pin<Box<dyn Future<Output = Vec<LidMapping>> + Send>> + Send + Sync,
>;

#[derive(Clone)]
struct CacheEntry {
    value: String,
    updated_at: Instant,
}

pub struct LidMappingStore {
    cache: Mutex<HashMap<String, CacheEntry>>,
    auth: Arc<MultiFileAuthState>,
    pn_to_lid_func: Option<PnToLidCallback>,
}

impl LidMappingStore {
    pub fn new(auth: Arc<MultiFileAuthState>, pn_to_lid_func: Option<PnToLidCallback>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            auth,
            pn_to_lid_func,
        }
    }

    fn cache_get(&self, key: &str) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        let entry = cache.get_mut(key)?;
        if entry.updated_at.elapsed() > CACHE_TTL {
            cache.remove(key);
            return None;
        }
        entry.updated_at = Instant::now();
        Some(entry.value.clone())
    }

    fn cache_set(&self, key: String, value: String) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            key,
            CacheEntry {
                value,
                updated_at: Instant::now(),
            },
        );
    }

    pub async fn store_lid_pn_mappings(&self, pairs: &[LidMapping]) -> Result<(), AuthStateError> {
        if pairs.is_empty() {
            return Ok(());
        }

        let mut validated_pairs: Vec<(String, String)> = Vec::new();
        for pair in pairs {
            let valid = (is_lid_user(Some(&pair.lid)) && is_pn_user(Some(&pair.pn)))
                || (is_pn_user(Some(&pair.lid)) && is_lid_user(Some(&pair.pn)));
            if !valid {
                continue;
            }
            let (Some(lid_decoded), Some(pn_decoded)) =
                (jid_decode(&pair.lid), jid_decode(&pair.pn))
            else {
                continue;
            };
            validated_pairs.push((pn_decoded.user, lid_decoded.user));
        }

        if validated_pairs.is_empty() {
            return Ok(());
        }

        let mut cache_miss_set: HashSet<String> = HashSet::new();
        let mut existing_mappings: HashMap<String, String> = HashMap::new();

        for (pn_user, _) in &validated_pairs {
            if let Some(cached) = self.cache_get(&format!("pn:{}", pn_user)) {
                existing_mappings.insert(pn_user.clone(), cached);
            } else {
                cache_miss_set.insert(pn_user.clone());
            }
        }

        if !cache_miss_set.is_empty() {
            let cache_misses: Vec<String> = cache_miss_set.into_iter().collect();
            let stored = self.auth.get_keys("lid-mapping", &cache_misses).await;
            for pn_user in cache_misses {
                if let Some(Some(Value::String(existing_lid))) = stored.get(&pn_user) {
                    existing_mappings.insert(pn_user.clone(), existing_lid.clone());
                    self.cache_set(format!("pn:{}", pn_user), existing_lid.clone());
                    self.cache_set(format!("lid:{}", existing_lid), pn_user);
                }
            }
        }

        let mut pair_map: HashMap<String, String> = HashMap::new();
        for (pn_user, lid_user) in validated_pairs {
            if existing_mappings.get(&pn_user) == Some(&lid_user) {
                continue;
            }
            pair_map.insert(pn_user, lid_user);
        }

        if pair_map.is_empty() {
            return Ok(());
        }

        let mut batch_data: HashMap<String, Option<Value>> = HashMap::new();
        for (pn_user, lid_user) in &pair_map {
            batch_data.insert(pn_user.clone(), Some(Value::String(lid_user.clone())));
            batch_data.insert(
                format!("{}_reverse", lid_user),
                Some(Value::String(pn_user.clone())),
            );
        }

        let mut outer = HashMap::new();
        outer.insert("lid-mapping".to_string(), batch_data);
        self.auth.set_keys(outer).await?;

        for (pn_user, lid_user) in pair_map {
            self.cache_set(format!("pn:{}", pn_user), lid_user.clone());
            self.cache_set(format!("lid:{}", lid_user), pn_user);
        }

        Ok(())
    }

    pub async fn get_lid_for_pn(&self, pn: &str) -> Option<String> {
        self.get_lids_for_pns(&[pn.to_string()])
            .await
            .and_then(|mut list| list.drain(..).next().map(|m| m.lid))
    }

    pub async fn get_lids_for_pns(&self, pns: &[String]) -> Option<Vec<LidMapping>> {
        if pns.is_empty() {
            return None;
        }

        let mut usync_fetch: HashMap<String, Vec<u32>> = HashMap::new();
        let mut successful_pairs: HashMap<String, LidMapping> = HashMap::new();
        let mut pending: Vec<(String, String, FullJid)> = Vec::new();

        let add_resolved_pair =
            |pn: &str, decoded: &FullJid, lid_user: &str, out: &mut HashMap<String, LidMapping>| {
                if lid_user.is_empty() {
                    return;
                }
                let pn_device = decoded.device.unwrap_or(0);
                let device_part = if pn_device != 0 {
                    format!(":{}", pn_device)
                } else {
                    String::new()
                };
                let server_part = if decoded.server.as_str() == "hosted" {
                    "hosted.lid"
                } else {
                    "lid"
                };
                let device_specific_lid = format!("{}{}@{}", lid_user, device_part, server_part);
                out.insert(
                    pn.to_string(),
                    LidMapping {
                        lid: device_specific_lid,
                        pn: pn.to_string(),
                    },
                );
            };

        for pn in pns {
            if !is_pn_user(Some(pn)) && !is_hosted_pn_user(Some(pn)) {
                continue;
            }
            let Some(decoded) = jid_decode(pn) else {
                continue;
            };
            let pn_user = decoded.user.clone();
            if let Some(cached) = self.cache_get(&format!("pn:{}", pn_user)) {
                add_resolved_pair(pn, &decoded, &cached, &mut successful_pairs);
                continue;
            }
            pending.push((pn.clone(), pn_user, decoded));
        }

        if !pending.is_empty() {
            let pn_users: Vec<String> = pending
                .iter()
                .map(|(_, u, _)| u.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let stored = self.auth.get_keys("lid-mapping", &pn_users).await;
            for pn_user in pn_users {
                if let Some(Some(Value::String(lid_user))) = stored.get(&pn_user) {
                    self.cache_set(format!("pn:{}", pn_user), lid_user.clone());
                    self.cache_set(format!("lid:{}", lid_user), pn_user);
                }
            }

            for (pn, pn_user, decoded) in pending {
                if let Some(cached) = self.cache_get(&format!("pn:{}", pn_user)) {
                    add_resolved_pair(&pn, &decoded, &cached, &mut successful_pairs);
                } else {
                    let device = decoded.device.unwrap_or(0);
                    let mut normalized_pn = jid_normalized_user(Some(&pn));
                    if is_hosted_pn_user(Some(&normalized_pn)) {
                        normalized_pn = format!("{}@s.whatsapp.net", pn_user);
                    }
                    usync_fetch.entry(normalized_pn).or_default().push(device);
                }
            }
        }

        if !usync_fetch.is_empty() {
            if let Some(fetch_fn) = &self.pn_to_lid_func {
                let keys_to_fetch: Vec<String> = usync_fetch.keys().cloned().collect();
                let result = (fetch_fn)(keys_to_fetch).await;
                if !result.is_empty() {
                    let _ = self.store_lid_pn_mappings(&result).await;
                    for pair in result {
                        let Some(pn_user) = jid_decode(&pair.pn).map(|d| d.user) else {
                            continue;
                        };
                        let Some(lid_user) = jid_decode(&pair.lid).map(|d| d.user) else {
                            continue;
                        };
                        if let Some(devices) = usync_fetch.get(&pair.pn) {
                            for &device in devices {
                                let dev_part = if device != 0 {
                                    format!(":{}", device)
                                } else {
                                    String::new()
                                };
                                let lid_server = if device == 99 { "hosted.lid" } else { "lid" };
                                let pn_server = if device == 99 {
                                    "hosted"
                                } else {
                                    "s.whatsapp.net"
                                };
                                let device_specific_lid =
                                    format!("{}{}@{}", lid_user, dev_part, lid_server);
                                let device_specific_pn =
                                    format!("{}{}@{}", pn_user, dev_part, pn_server);
                                successful_pairs.insert(
                                    device_specific_pn.clone(),
                                    LidMapping {
                                        lid: device_specific_lid,
                                        pn: device_specific_pn,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        if successful_pairs.is_empty() {
            None
        } else {
            Some(successful_pairs.into_values().collect())
        }
    }

    pub async fn get_pn_for_lid(&self, lid: &str) -> Option<String> {
        self.get_pns_for_lids(&[lid.to_string()])
            .await
            .and_then(|mut list| list.drain(..).next().map(|m| m.pn))
    }

    pub async fn get_pns_for_lids(&self, lids: &[String]) -> Option<Vec<LidMapping>> {
        if lids.is_empty() {
            return None;
        }

        let mut successful_pairs: HashMap<String, LidMapping> = HashMap::new();
        let mut pending: Vec<(String, String, FullJid)> = Vec::new();

        let add_resolved =
            |lid: &str, decoded: &FullJid, pn_user: &str, out: &mut HashMap<String, LidMapping>| {
                if pn_user.is_empty() {
                    return;
                }
                let lid_device = decoded.device.unwrap_or(0);
                let server = if decoded.domain_type == Some(WaJidDomains::HostedLid as u32) {
                    "hosted"
                } else {
                    "s.whatsapp.net"
                };
                let pn_jid = format!("{}:{}@{}", pn_user, lid_device, server);
                out.insert(
                    lid.to_string(),
                    LidMapping {
                        lid: lid.to_string(),
                        pn: pn_jid,
                    },
                );
            };

        for lid in lids {
            if !is_lid_user(Some(lid)) {
                continue;
            }
            let Some(decoded) = jid_decode(lid) else {
                continue;
            };
            let lid_user = decoded.user.clone();
            if let Some(cached) = self.cache_get(&format!("lid:{}", lid_user)) {
                add_resolved(lid, &decoded, &cached, &mut successful_pairs);
                continue;
            }
            pending.push((lid.clone(), lid_user, decoded));
        }

        if !pending.is_empty() {
            let reverse_keys: Vec<String> = pending
                .iter()
                .map(|(_, u, _)| format!("{}_reverse", u))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let stored = self.auth.get_keys("lid-mapping", &reverse_keys).await;

            for (lid, lid_user, decoded) in pending {
                let mut pn_user = self.cache_get(&format!("lid:{}", lid_user));
                if pn_user.is_none() {
                    if let Some(Some(Value::String(found))) =
                        stored.get(&format!("{}_reverse", lid_user))
                    {
                        self.cache_set(format!("lid:{}", lid_user), found.clone());
                        self.cache_set(format!("pn:{}", found), lid_user.clone());
                        pn_user = Some(found.clone());
                    }
                }
                if let Some(user) = pn_user {
                    add_resolved(&lid, &decoded, &user, &mut successful_pairs);
                }
            }
        }

        if successful_pairs.is_empty() {
            None
        } else {
            Some(successful_pairs.into_values().collect())
        }
    }

    pub fn close(&self) {
        self.cache.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::use_multi_file_auth_state::use_multi_file_auth_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_lid_mapping_store_roundtrip() {
        let suffix: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("baileys_rs_lid_test_{}", suffix));
        let auth = Arc::new(use_multi_file_auth_state(&dir).await.unwrap());
        let store = LidMappingStore::new(Arc::clone(&auth), None);

        store
            .store_lid_pn_mappings(&[LidMapping {
                pn: "573001234567@s.whatsapp.net".to_string(),
                lid: "987654321@lid".to_string(),
            }])
            .await
            .unwrap();

        assert_eq!(
            store.get_lid_for_pn("573001234567:2@s.whatsapp.net").await,
            Some("987654321:2@lid".to_string())
        );

        store.close();

        assert_eq!(
            store.get_pn_for_lid("987654321:2@lid").await,
            Some("573001234567:2@s.whatsapp.net".to_string())
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
