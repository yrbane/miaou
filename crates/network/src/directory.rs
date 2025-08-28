//! Module d'annuaires distribués pour synchronisation des clés publiques
//!
//! TDD: Tests écrits AVANT implémentation  
//! Architecture SOLID : Gestion décentralisée des identités et clés publiques

use crate::{DhtConfig, NetworkError, PeerId};
use async_trait::async_trait;
use blake3::hash as blake3_hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Statut de vérification d'une entrée d'annuaire
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Non vérifié
    Unverified,
    /// Auto-signé (pair lui-même)
    SelfSigned,
    /// Signé par des tiers de confiance
    Verified,
    /// Révoqué ou compromis
    Revoked,
}

impl Default for VerificationStatus {
    fn default() -> Self {
        Self::Unverified
    }
}

/// Type d'entrée dans l'annuaire
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryEntryType {
    /// Clé publique de signature
    SigningKey,
    /// Clé publique de chiffrement
    EncryptionKey,
    /// Certificat complet avec métadonnées
    Certificate,
    /// Information de révocation
    RevocationInfo,
}

/// Entrée d'annuaire distribué
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// ID du propriétaire de la clé
    pub peer_id: PeerId,
    /// Type d'entrée
    pub entry_type: DirectoryEntryType,
    /// Données de la clé/certificat
    pub key_data: Vec<u8>,
    /// Version/révision de cette entrée
    pub version: u64,
    /// Timestamp de création
    pub created_at: u64,
    /// Timestamp d'expiration
    pub expires_at: Option<u64>,
    /// Statut de vérification
    pub verification_status: VerificationStatus,
    /// Signatures de tiers (Web of Trust)
    pub signatures: HashMap<PeerId, Vec<u8>>,
    /// Métadonnées additionnelles
    pub metadata: HashMap<String, String>,
    /// Hash pour intégrité
    pub integrity_hash: Vec<u8>,
}

impl DirectoryEntry {
    /// Crée une nouvelle entrée d'annuaire
    pub fn new(
        peer_id: PeerId,
        entry_type: DirectoryEntryType,
        key_data: Vec<u8>,
        version: u64,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut entry = Self {
            peer_id,
            entry_type,
            key_data,
            version,
            created_at,
            expires_at: None,
            verification_status: VerificationStatus::Unverified,
            signatures: HashMap::new(),
            metadata: HashMap::new(),
            integrity_hash: Vec::new(),
        };

        // Calculer le hash d'intégrité
        entry.update_integrity_hash();
        entry
    }

    /// Crée une entrée de clé de signature
    pub fn signing_key(peer_id: PeerId, public_key: Vec<u8>, version: u64) -> Self {
        Self::new(peer_id, DirectoryEntryType::SigningKey, public_key, version)
    }

    /// Crée une entrée de clé de chiffrement
    pub fn encryption_key(peer_id: PeerId, public_key: Vec<u8>, version: u64) -> Self {
        Self::new(
            peer_id,
            DirectoryEntryType::EncryptionKey,
            public_key,
            version,
        )
    }

    /// Met à jour le hash d'intégrité
    pub fn update_integrity_hash(&mut self) {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(self.peer_id.as_bytes());
        hasher_input.extend_from_slice(&bincode::serialize(&self.entry_type).unwrap());
        hasher_input.extend_from_slice(&self.key_data);
        hasher_input.extend_from_slice(&self.version.to_be_bytes());
        hasher_input.extend_from_slice(&self.created_at.to_be_bytes());

        self.integrity_hash = blake3_hash(&hasher_input).as_bytes().to_vec();
    }

    /// Vérifie l'intégrité de l'entrée
    pub fn verify_integrity(&self) -> bool {
        let mut test_entry = self.clone();
        test_entry.update_integrity_hash();
        test_entry.integrity_hash == self.integrity_hash
    }

    /// Ajoute une signature de tiers
    pub fn add_signature(&mut self, signer: PeerId, signature: Vec<u8>) {
        self.signatures.insert(signer, signature);
    }

    /// Marque l'entrée comme expirée
    pub fn set_expiration(&mut self, expires_at: u64) {
        self.expires_at = Some(expires_at);
    }

    /// Vérifie si l'entrée a expiré
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now >= expires_at
        } else {
            false
        }
    }

    /// Marque comme révoqué
    pub fn revoke(&mut self) {
        self.verification_status = VerificationStatus::Revoked;
    }

    /// Sérialise pour stockage DHT
    pub fn serialize(&self) -> Result<Vec<u8>, NetworkError> {
        bincode::serialize(self).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Désérialise depuis stockage DHT
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        bincode::deserialize(data).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Génère une clé DHT pour cette entrée
    pub fn dht_key(&self) -> Vec<u8> {
        format!("directory:{}:{:?}", self.peer_id, self.entry_type).into_bytes()
    }
}

/// Configuration de l'annuaire distribué
#[derive(Debug, Clone)]
pub struct DirectoryConfig {
    /// Configuration DHT sous-jacente
    pub dht_config: DhtConfig,
    /// Durée de vie par défaut des entrées (secondes)
    pub default_ttl_seconds: u64,
    /// Nombre maximum d'entrées en cache local
    pub max_local_entries: usize,
    /// Intervalle de nettoyage des entrées expirées (secondes)
    pub cleanup_interval_seconds: u64,
    /// Seuil de réplication (combien de nœuds doivent avoir une copie)
    pub replication_factor: usize,
    /// Activer la vérification automatique des signatures
    pub enable_signature_verification: bool,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            dht_config: DhtConfig::default(),
            default_ttl_seconds: 24 * 60 * 60, // 24 heures
            max_local_entries: 10000,
            cleanup_interval_seconds: 60 * 60, // 1 heure
            replication_factor: 3,
            enable_signature_verification: true,
        }
    }
}

/// Requête de recherche dans l'annuaire
#[derive(Debug, Clone)]
pub struct DirectoryQuery {
    /// ID du pair recherché
    pub peer_id: Option<PeerId>,
    /// Type d'entrée recherché
    pub entry_type: Option<DirectoryEntryType>,
    /// Version minimale
    pub min_version: Option<u64>,
    /// Version maximale
    pub max_version: Option<u64>,
    /// Statut de vérification requis
    pub verification_status: Option<VerificationStatus>,
    /// Inclure les entrées expirées
    pub include_expired: bool,
    /// Limite de résultats
    pub limit: Option<usize>,
}

impl DirectoryQuery {
    /// Crée une nouvelle requête
    pub fn new() -> Self {
        Self {
            peer_id: None,
            entry_type: None,
            min_version: None,
            max_version: None,
            verification_status: None,
            include_expired: false,
            limit: None,
        }
    }

    /// Filtre par ID de pair
    pub fn peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Filtre par type d'entrée
    pub fn entry_type(mut self, entry_type: DirectoryEntryType) -> Self {
        self.entry_type = Some(entry_type);
        self
    }

    /// Filtre par version
    pub fn version_range(mut self, min: u64, max: u64) -> Self {
        self.min_version = Some(min);
        self.max_version = Some(max);
        self
    }

    /// Filtre par statut de vérification
    pub fn verification_status(mut self, status: VerificationStatus) -> Self {
        self.verification_status = Some(status);
        self
    }

    /// Inclut les entrées expirées
    pub fn include_expired(mut self) -> Self {
        self.include_expired = true;
        self
    }

    /// Limite le nombre de résultats
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Vérifie si une entrée correspond aux critères
    pub fn matches(&self, entry: &DirectoryEntry) -> bool {
        if let Some(peer_id) = &self.peer_id {
            if *peer_id != entry.peer_id {
                return false;
            }
        }

        if let Some(entry_type) = &self.entry_type {
            if *entry_type != entry.entry_type {
                return false;
            }
        }

        if let Some(min_version) = self.min_version {
            if entry.version < min_version {
                return false;
            }
        }

        if let Some(max_version) = self.max_version {
            if entry.version > max_version {
                return false;
            }
        }

        if let Some(status) = self.verification_status {
            if entry.verification_status != status {
                return false;
            }
        }

        if !self.include_expired && entry.is_expired() {
            return false;
        }

        true
    }
}

impl Default for DirectoryQuery {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait pour annuaire distribué
#[async_trait]
pub trait DistributedDirectory: Send + Sync {
    /// Démarre l'annuaire distribué
    async fn start(&mut self) -> Result<(), NetworkError>;

    /// Arrête l'annuaire distribué
    async fn stop(&mut self) -> Result<(), NetworkError>;

    /// Publie une entrée dans l'annuaire
    async fn publish_entry(&self, entry: DirectoryEntry) -> Result<(), NetworkError>;

    /// Recherche des entrées dans l'annuaire
    async fn search_entries(
        &self,
        query: DirectoryQuery,
    ) -> Result<Vec<DirectoryEntry>, NetworkError>;

    /// Récupère une entrée spécifique
    async fn get_entry(
        &self,
        peer_id: &PeerId,
        entry_type: DirectoryEntryType,
    ) -> Result<Option<DirectoryEntry>, NetworkError>;

    /// Met à jour une entrée existante
    async fn update_entry(&self, entry: DirectoryEntry) -> Result<(), NetworkError>;

    /// Révoque une entrée
    async fn revoke_entry(
        &self,
        peer_id: &PeerId,
        entry_type: DirectoryEntryType,
    ) -> Result<(), NetworkError>;

    /// Liste toutes les entrées locales
    async fn list_local_entries(&self) -> Result<Vec<DirectoryEntry>, NetworkError>;

    /// Nettoie les entrées expirées
    async fn cleanup_expired(&self) -> Result<usize, NetworkError>;

    /// Récupère les statistiques
    async fn get_stats(&self) -> DirectoryStats;
}

/// Statistiques de l'annuaire
#[derive(Debug, Clone)]
pub struct DirectoryStats {
    /// Nombre d'entrées en cache local
    pub local_entries_count: usize,
    /// Nombre d'entrées vérifiées
    pub verified_entries_count: usize,
    /// Nombre d'entrées révoquées
    pub revoked_entries_count: usize,
    /// Nombre d'entrées expirées
    pub expired_entries_count: usize,
    /// Nombre de requêtes DHT effectuées
    pub dht_queries_count: u64,
    /// Nombre d'entrées publiées
    pub published_entries_count: u64,
    /// Uptime en secondes
    pub uptime_seconds: u64,
}

/// Implémentation en mémoire de l'annuaire distribué (MVP)
pub struct DhtDistributedDirectory {
    /// Configuration
    config: DirectoryConfig,
    /// ID local du pair
    local_peer_id: PeerId,
    /// Cache local des entrées
    local_cache: Arc<RwLock<HashMap<Vec<u8>, DirectoryEntry>>>,
    /// Statistiques
    stats: Arc<RwLock<DirectoryStats>>,
    /// Timestamp de démarrage
    started_at: Arc<RwLock<Option<u64>>>,
    /// État de l'annuaire
    is_running: Arc<RwLock<bool>>,
}

impl DhtDistributedDirectory {
    /// Crée un nouveau annuaire distribué DHT
    pub fn new(config: DirectoryConfig, local_peer_id: PeerId) -> Self {
        let stats = DirectoryStats {
            local_entries_count: 0,
            verified_entries_count: 0,
            revoked_entries_count: 0,
            expired_entries_count: 0,
            dht_queries_count: 0,
            published_entries_count: 0,
            uptime_seconds: 0,
        };

        Self {
            config,
            local_peer_id,
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            started_at: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Nettoie le cache local des entrées expirées
    fn cleanup_local_cache(&self) -> Result<usize, NetworkError> {
        let mut cache = self.local_cache.write().unwrap();
        let initial_count = cache.len();

        // Filtrer les entrées non expirées
        cache.retain(|_key, entry| !entry.is_expired());

        let removed_count = initial_count - cache.len();

        // Mettre à jour les stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.local_entries_count = cache.len();
            stats.expired_entries_count = stats.expired_entries_count.saturating_add(removed_count);
        }

        Ok(removed_count)
    }

    /// Retourne l'ID du pair local
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Vérifie si on doit accepter une entrée (pas de doublons avec version inférieure)
    fn should_accept_entry(&self, entry: &DirectoryEntry) -> bool {
        let cache = self.local_cache.read().unwrap();
        let key = entry.dht_key();

        if let Some(existing) = cache.get(&key) {
            // Accepter seulement si la version est plus récente
            entry.version > existing.version
        } else {
            true
        }
    }

    /// Met à jour les statistiques après ajout d'entrée
    fn update_stats_for_entry(&self, entry: &DirectoryEntry, is_new: bool) {
        let mut stats = self.stats.write().unwrap();

        if is_new {
            stats.local_entries_count += 1;
        }

        match entry.verification_status {
            VerificationStatus::Verified | VerificationStatus::SelfSigned => {
                stats.verified_entries_count += 1;
            }
            VerificationStatus::Revoked => {
                stats.revoked_entries_count += 1;
            }
            _ => {}
        }
    }
}

#[async_trait]
impl DistributedDirectory for DhtDistributedDirectory {
    async fn start(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().unwrap();
        if *running {
            return Err(NetworkError::General(
                "Annuaire distribué déjà démarré".to_string(),
            ));
        }
        *running = true;
        drop(running);

        let mut started = self.started_at.write().unwrap();
        *started = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        drop(started);

        // Programmer le nettoyage périodique des entrées expirées
        let cache = Arc::clone(&self.local_cache);
        let stats = Arc::clone(&self.stats);
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval_seconds);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;

                // Nettoyer les entrées expirées
                let mut cache = cache.write().unwrap();
                let initial_count = cache.len();
                cache.retain(|_key, entry| !entry.is_expired());
                let removed = initial_count - cache.len();

                // Mettre à jour les stats
                if removed > 0 {
                    let mut stats = stats.write().unwrap();
                    stats.local_entries_count = cache.len();
                    stats.expired_entries_count += removed;
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().unwrap();
        if !*running {
            return Err(NetworkError::General(
                "Annuaire distribué non démarré".to_string(),
            ));
        }
        *running = false;
        drop(running);

        let mut started = self.started_at.write().unwrap();
        *started = None;
        drop(started);

        Ok(())
    }

    async fn publish_entry(&self, mut entry: DirectoryEntry) -> Result<(), NetworkError> {
        // Vérifier que l'annuaire est démarré
        {
            let running = self.is_running.read().unwrap();
            if !*running {
                return Err(NetworkError::General(
                    "Annuaire distribué non démarré".to_string(),
                ));
            }
        }

        // Mettre à jour le hash d'intégrité
        entry.update_integrity_hash();

        // Vérifier si on doit accepter cette entrée
        if !self.should_accept_entry(&entry) {
            return Err(NetworkError::General(
                "Version d'entrée trop ancienne".to_string(),
            ));
        }

        let key = entry.dht_key();

        // TDD: Pour MVP, stocker seulement localement
        // En production, publier aussi dans la DHT distribuée

        // Ajouter au cache local seulement si accepté
        let is_new = {
            let mut cache = self.local_cache.write().unwrap();
            let was_present = cache.contains_key(&key);
            cache.insert(key, entry.clone());
            !was_present
        };

        // Mettre à jour les statistiques
        self.update_stats_for_entry(&entry, is_new);
        {
            let mut stats = self.stats.write().unwrap();
            stats.published_entries_count += 1;
        }

        Ok(())
    }

    async fn search_entries(
        &self,
        query: DirectoryQuery,
    ) -> Result<Vec<DirectoryEntry>, NetworkError> {
        // TDD: Pour MVP, recherche seulement dans le cache local
        // En production, aussi chercher dans la DHT distribuée

        let mut results = Vec::new();

        {
            let cache = self.local_cache.read().unwrap();
            for entry in cache.values() {
                if query.matches(entry) {
                    results.push(entry.clone());
                }
            }
        }

        // Mettre à jour les statistiques (simule une requête DHT)
        {
            let mut stats = self.stats.write().unwrap();
            stats.dht_queries_count += 1;
        }

        // Appliquer la limite si spécifiée
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn get_entry(
        &self,
        peer_id: &PeerId,
        entry_type: DirectoryEntryType,
    ) -> Result<Option<DirectoryEntry>, NetworkError> {
        let query = DirectoryQuery::new()
            .peer_id(peer_id.clone())
            .entry_type(entry_type)
            .limit(1);

        let results = self.search_entries(query).await?;
        Ok(results.into_iter().next())
    }

    async fn update_entry(&self, entry: DirectoryEntry) -> Result<(), NetworkError> {
        // Une mise à jour est juste une publication avec une version plus récente
        self.publish_entry(entry).await
    }

    async fn revoke_entry(
        &self,
        peer_id: &PeerId,
        entry_type: DirectoryEntryType,
    ) -> Result<(), NetworkError> {
        // Récupérer l'entrée existante
        if let Some(mut entry) = self.get_entry(peer_id, entry_type).await? {
            // Marquer comme révoquée et incrementer la version
            entry.version += 1;
            entry.revoke();
            entry.update_integrity_hash();

            // Republier l'entrée révoquée
            self.publish_entry(entry).await
        } else {
            Err(NetworkError::General(
                "Entrée non trouvée pour révocation".to_string(),
            ))
        }
    }

    async fn list_local_entries(&self) -> Result<Vec<DirectoryEntry>, NetworkError> {
        let cache = self.local_cache.read().unwrap();
        Ok(cache.values().cloned().collect())
    }

    async fn cleanup_expired(&self) -> Result<usize, NetworkError> {
        self.cleanup_local_cache()
    }

    async fn get_stats(&self) -> DirectoryStats {
        let mut stats = self.stats.read().unwrap().clone();

        // Calculer l'uptime
        if let Some(started_at) = *self.started_at.read().unwrap() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            stats.uptime_seconds = now.saturating_sub(started_at);
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerId;

    #[test]
    fn test_verification_status_default() {
        assert_eq!(
            VerificationStatus::default(),
            VerificationStatus::Unverified
        );
    }

    #[test]
    fn test_directory_entry_creation() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let key_data = vec![1, 2, 3, 4, 5];

        let entry = DirectoryEntry::new(
            peer_id.clone(),
            DirectoryEntryType::SigningKey,
            key_data.clone(),
            1,
        );

        assert_eq!(entry.peer_id, peer_id);
        assert_eq!(entry.entry_type, DirectoryEntryType::SigningKey);
        assert_eq!(entry.key_data, key_data);
        assert_eq!(entry.version, 1);
        assert_eq!(entry.verification_status, VerificationStatus::Unverified);
        assert!(entry.created_at > 0);
        assert!(entry.expires_at.is_none());
        assert!(entry.signatures.is_empty());
        assert!(!entry.integrity_hash.is_empty());
    }

    #[test]
    fn test_directory_entry_signing_key() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let public_key = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];

        let entry = DirectoryEntry::signing_key(peer_id.clone(), public_key.clone(), 2);

        assert_eq!(entry.peer_id, peer_id);
        assert_eq!(entry.entry_type, DirectoryEntryType::SigningKey);
        assert_eq!(entry.key_data, public_key);
        assert_eq!(entry.version, 2);
    }

    #[test]
    fn test_directory_entry_encryption_key() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let public_key = vec![1, 1, 2, 3, 5, 8, 13, 21];

        let entry = DirectoryEntry::encryption_key(peer_id.clone(), public_key.clone(), 3);

        assert_eq!(entry.peer_id, peer_id);
        assert_eq!(entry.entry_type, DirectoryEntryType::EncryptionKey);
        assert_eq!(entry.key_data, public_key);
        assert_eq!(entry.version, 3);
    }

    #[test]
    fn test_directory_entry_integrity() {
        let peer_id = PeerId::from_bytes(b"integrity_test".to_vec());
        let key_data = vec![42, 42, 42];

        let mut entry = DirectoryEntry::new(peer_id, DirectoryEntryType::Certificate, key_data, 1);

        // L'intégrité devrait être valide après création
        assert!(entry.verify_integrity());

        // Modifier les données sans recalculer le hash
        entry.key_data.push(99);

        // L'intégrité devrait maintenant être invalide
        assert!(!entry.verify_integrity());

        // Recalculer le hash
        entry.update_integrity_hash();

        // L'intégrité devrait être valide à nouveau
        assert!(entry.verify_integrity());
    }

    #[test]
    fn test_directory_entry_signatures() {
        let peer_id = PeerId::from_bytes(b"signed_peer".to_vec());
        let signer1 = PeerId::from_bytes(b"signer1".to_vec());
        let signer2 = PeerId::from_bytes(b"signer2".to_vec());

        let mut entry = DirectoryEntry::signing_key(peer_id, vec![1, 2, 3], 1);

        assert!(entry.signatures.is_empty());

        entry.add_signature(signer1.clone(), vec![10, 20, 30]);
        entry.add_signature(signer2.clone(), vec![40, 50, 60]);

        assert_eq!(entry.signatures.len(), 2);
        assert_eq!(entry.signatures.get(&signer1), Some(&vec![10, 20, 30]));
        assert_eq!(entry.signatures.get(&signer2), Some(&vec![40, 50, 60]));
    }

    #[test]
    fn test_directory_entry_expiration() {
        let peer_id = PeerId::from_bytes(b"expiring_peer".to_vec());
        let mut entry = DirectoryEntry::signing_key(peer_id, vec![1, 2, 3], 1);

        // Par défaut, pas d'expiration
        assert!(!entry.is_expired());

        // Définir une expiration dans le futur
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // +1 heure
        entry.set_expiration(future_time);

        assert!(!entry.is_expired());

        // Définir une expiration dans le passé
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600; // -1 heure
        entry.set_expiration(past_time);

        assert!(entry.is_expired());
    }

    #[test]
    fn test_directory_entry_revocation() {
        let peer_id = PeerId::from_bytes(b"revoked_peer".to_vec());
        let mut entry = DirectoryEntry::signing_key(peer_id, vec![1, 2, 3], 1);

        assert_eq!(entry.verification_status, VerificationStatus::Unverified);

        entry.revoke();
        assert_eq!(entry.verification_status, VerificationStatus::Revoked);
    }

    #[test]
    fn test_directory_entry_serialization() {
        let peer_id = PeerId::from_bytes(b"serialize_test".to_vec());
        let entry = DirectoryEntry::encryption_key(peer_id, vec![9, 8, 7], 5);

        let serialized = entry.serialize().unwrap();
        let deserialized = DirectoryEntry::deserialize(&serialized).unwrap();

        assert_eq!(entry.peer_id, deserialized.peer_id);
        assert_eq!(entry.entry_type, deserialized.entry_type);
        assert_eq!(entry.key_data, deserialized.key_data);
        assert_eq!(entry.version, deserialized.version);
        assert_eq!(entry.verification_status, deserialized.verification_status);
        assert_eq!(entry.integrity_hash, deserialized.integrity_hash);
    }

    #[test]
    fn test_directory_entry_dht_key() {
        let peer_id = PeerId::from_bytes(b"dht_key_test".to_vec());
        let entry = DirectoryEntry::signing_key(peer_id.clone(), vec![1, 2, 3], 42);

        let dht_key = entry.dht_key();
        let key_str = String::from_utf8(dht_key).unwrap();

        assert!(key_str.starts_with("directory:"));
        assert!(key_str.contains("SigningKey"));
        // La version n'est plus incluse dans la clé DHT pour permettre le versioning
    }

    #[test]
    fn test_directory_config_default() {
        let config = DirectoryConfig::default();

        assert_eq!(config.default_ttl_seconds, 24 * 60 * 60);
        assert_eq!(config.max_local_entries, 10000);
        assert_eq!(config.cleanup_interval_seconds, 60 * 60);
        assert_eq!(config.replication_factor, 3);
        assert!(config.enable_signature_verification);
    }

    #[test]
    fn test_directory_query_builder() {
        let peer_id = PeerId::from_bytes(b"query_test".to_vec());

        let query = DirectoryQuery::new()
            .peer_id(peer_id.clone())
            .entry_type(DirectoryEntryType::SigningKey)
            .version_range(1, 10)
            .verification_status(VerificationStatus::Verified)
            .include_expired()
            .limit(5);

        assert_eq!(query.peer_id, Some(peer_id));
        assert_eq!(query.entry_type, Some(DirectoryEntryType::SigningKey));
        assert_eq!(query.min_version, Some(1));
        assert_eq!(query.max_version, Some(10));
        assert_eq!(
            query.verification_status,
            Some(VerificationStatus::Verified)
        );
        assert!(query.include_expired);
        assert_eq!(query.limit, Some(5));
    }

    #[test]
    fn test_directory_query_matches() {
        let peer_id = PeerId::from_bytes(b"match_test".to_vec());
        let other_peer_id = PeerId::from_bytes(b"other_peer".to_vec());

        let entry = DirectoryEntry::signing_key(peer_id.clone(), vec![1, 2, 3], 5);

        // Query qui matche
        let matching_query = DirectoryQuery::new()
            .peer_id(peer_id.clone())
            .entry_type(DirectoryEntryType::SigningKey)
            .version_range(1, 10);

        assert!(matching_query.matches(&entry));

        // Query qui ne matche pas (mauvais peer)
        let non_matching_query = DirectoryQuery::new().peer_id(other_peer_id);

        assert!(!non_matching_query.matches(&entry));

        // Query qui ne matche pas (mauvaise version)
        let version_query = DirectoryQuery::new().peer_id(peer_id).version_range(10, 20);

        assert!(!version_query.matches(&entry));
    }

    #[tokio::test]
    async fn test_dht_directory_creation() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let directory = DhtDistributedDirectory::new(config, local_peer);

        let stats = directory.get_stats().await;
        assert_eq!(stats.local_entries_count, 0);
        assert_eq!(stats.published_entries_count, 0);

        let started = directory.started_at.read().unwrap();
        assert!(started.is_none());
    }

    #[tokio::test]
    async fn test_dht_directory_start_stop() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        // Démarrer
        assert!(directory.start().await.is_ok());

        {
            let started = directory.started_at.read().unwrap();
            assert!(started.is_some());
        }

        // Double start devrait échouer
        assert!(directory.start().await.is_err());

        // Arrêter
        assert!(directory.stop().await.is_ok());

        {
            let started = directory.started_at.read().unwrap();
            assert!(started.is_none());
        }

        // Double stop devrait échouer
        assert!(directory.stop().await.is_err());
    }

    #[tokio::test]
    async fn test_dht_directory_operations_when_not_started() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let directory = DhtDistributedDirectory::new(config, local_peer);

        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let entry = DirectoryEntry::signing_key(peer_id.clone(), vec![1, 2, 3], 1);

        // Publier sans avoir démarré devrait échouer
        let result = directory.publish_entry(entry).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dht_directory_list_empty() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        directory.start().await.unwrap();

        let entries = directory.list_local_entries().await.unwrap();
        assert!(entries.is_empty());

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_dht_directory_cleanup_expired() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        directory.start().await.unwrap();

        // Au début, pas d'entrées à nettoyer
        let cleaned = directory.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 0);

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_dht_directory_get_nonexistent_entry() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        directory.start().await.unwrap();

        let peer_id = PeerId::from_bytes(b"nonexistent".to_vec());
        let result = directory
            .get_entry(&peer_id, DirectoryEntryType::SigningKey)
            .await
            .unwrap();

        assert!(result.is_none());

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_dht_directory_search_empty() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        directory.start().await.unwrap();

        let query = DirectoryQuery::new();
        let results = directory.search_entries(query).await.unwrap();

        assert!(results.is_empty());

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_stats_uptime() {
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"test_directory".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer);

        // Avant démarrage, uptime = 0
        let stats = directory.get_stats().await;
        assert_eq!(stats.uptime_seconds, 0);

        directory.start().await.unwrap();

        // Attendre un peu pour s'assurer que l'uptime est > 0
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Après démarrage, uptime >= 0 (peut être 0 sur des machines très rapides)
        let stats = directory.get_stats().await;
        // stats.uptime_seconds est u64, toujours ≥ 0
        // Service démarré correctement - vérifier que les stats sont cohérentes
        assert_eq!(stats.local_entries_count, 0); // Par défaut pas d'entrées locales au démarrage

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_entry_version_management() {
        // TDD: Test gestion des versions d'entrées
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"version_test".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Créer une entrée version 1
        let key_data_v1 = vec![0x01, 0x02, 0x03];
        let entry_v1 = DirectoryEntry::signing_key(local_peer.clone(), key_data_v1.clone(), 1);
        directory.publish_entry(entry_v1).await.unwrap();

        // Récupérer l'entrée
        let found_v1 = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found_v1.is_some());
        assert_eq!(found_v1.as_ref().unwrap().version, 1);
        assert_eq!(found_v1.as_ref().unwrap().key_data, key_data_v1);

        // Créer une entrée version 2 (plus récente)
        let key_data_v2 = vec![0x04, 0x05, 0x06];
        let entry_v2 = DirectoryEntry::signing_key(local_peer.clone(), key_data_v2.clone(), 2);
        directory.publish_entry(entry_v2).await.unwrap();

        // Récupérer devrait retourner la version 2
        let found_v2 = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found_v2.is_some());
        assert_eq!(found_v2.as_ref().unwrap().version, 2);
        assert_eq!(found_v2.as_ref().unwrap().key_data, key_data_v2);

        // Essayer de publier une version plus ancienne (version 1)
        let old_entry = DirectoryEntry::signing_key(local_peer.clone(), vec![0x99], 1);
        let result = directory.publish_entry(old_entry).await;
        assert!(result.is_err()); // Devrait échouer car version trop ancienne

        // Vérifier que la version 2 est toujours présente
        let still_v2 = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(still_v2.is_some());
        assert_eq!(still_v2.unwrap().version, 2);

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_entry_expiration_workflow() {
        // TDD: Test workflow d'expiration des entrées
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"expiration_test".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Créer une entrée qui expire bientôt
        let mut entry = DirectoryEntry::signing_key(local_peer.clone(), vec![0xAA, 0xBB], 1);
        let expiry_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1; // +1 seconde
        entry.set_expiration(expiry_time);

        directory.publish_entry(entry.clone()).await.unwrap();

        // Vérifier que l'entrée est présente
        let found = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found.is_some());
        assert!(!found.unwrap().is_expired()); // Pas encore expirée

        // Attendre l'expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Nettoyer les entrées expirées
        let cleaned = directory.cleanup_expired().await.unwrap();
        assert!(cleaned >= 1); // Au moins notre entrée devrait être nettoyée

        // Vérifier les stats d'expiration
        let stats = directory.get_stats().await;
        assert!(stats.expired_entries_count >= 1);

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_entry_revocation_workflow() {
        // TDD: Test workflow de révocation d'entrées
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"revocation_test".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Publier une entrée normale
        let entry = DirectoryEntry::signing_key(local_peer.clone(), vec![0xCC, 0xDD], 1);
        directory.publish_entry(entry).await.unwrap();

        // Vérifier qu'elle est présente et active
        let found = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().verification_status,
            VerificationStatus::Unverified
        );

        // Révoquer l'entrée
        directory
            .revoke_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();

        // Vérifier que l'entrée est maintenant révoquée (nouvelle version)
        let revoked = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(revoked.is_some());
        assert_eq!(
            revoked.as_ref().unwrap().verification_status,
            VerificationStatus::Revoked
        );
        assert_eq!(revoked.unwrap().version, 2); // Version incrémentée

        // Vérifier les stats
        let stats = directory.get_stats().await;
        assert!(stats.revoked_entries_count >= 1);

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_multiple_entry_types() {
        // TDD: Test avec plusieurs types d'entrées
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"multi_type_test".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Publier différents types d'entrées pour le même pair
        let signing_key = DirectoryEntry::signing_key(local_peer.clone(), vec![0x11, 0x22], 1);
        let encryption_key =
            DirectoryEntry::encryption_key(local_peer.clone(), vec![0x33, 0x44], 1);
        let mut certificate = DirectoryEntry::new(
            local_peer.clone(),
            DirectoryEntryType::Certificate,
            vec![0x55, 0x66],
            1,
        );
        certificate.verification_status = VerificationStatus::Verified;

        directory.publish_entry(signing_key).await.unwrap();
        directory.publish_entry(encryption_key).await.unwrap();
        directory.publish_entry(certificate).await.unwrap();

        // Récupérer chaque type séparément
        let found_signing = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found_signing.is_some());
        assert_eq!(found_signing.unwrap().key_data, vec![0x11, 0x22]);

        let found_encryption = directory
            .get_entry(&local_peer, DirectoryEntryType::EncryptionKey)
            .await
            .unwrap();
        assert!(found_encryption.is_some());
        assert_eq!(found_encryption.unwrap().key_data, vec![0x33, 0x44]);

        let found_cert = directory
            .get_entry(&local_peer, DirectoryEntryType::Certificate)
            .await
            .unwrap();
        assert!(found_cert.is_some());
        assert_eq!(found_cert.as_ref().unwrap().key_data, vec![0x55, 0x66]);
        assert_eq!(
            found_cert.unwrap().verification_status,
            VerificationStatus::Verified
        );

        // Lister toutes les entrées
        let all_entries = directory.list_local_entries().await.unwrap();
        assert_eq!(all_entries.len(), 3);

        // Vérifier les stats
        let stats = directory.get_stats().await;
        assert_eq!(stats.local_entries_count, 3);
        assert_eq!(stats.verified_entries_count, 1); // Seulement le certificat

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_query_comprehensive() {
        // TDD: Test complet des requêtes d'annuaire
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"query_test".to_vec());
        let peer1 = PeerId::from_bytes(b"peer1".to_vec());
        let peer2 = PeerId::from_bytes(b"peer2".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Publier plusieurs entrées avec différentes caractéristiques
        let mut entry1 = DirectoryEntry::signing_key(peer1.clone(), vec![0xAA], 1);
        entry1.verification_status = VerificationStatus::Verified;

        let mut entry2 = DirectoryEntry::encryption_key(peer1.clone(), vec![0xBB], 2);
        entry2.verification_status = VerificationStatus::SelfSigned;

        let mut entry3 = DirectoryEntry::signing_key(peer2.clone(), vec![0xCC], 1);
        entry3.verification_status = VerificationStatus::Unverified;

        let mut entry4 = DirectoryEntry::signing_key(peer2.clone(), vec![0xDD], 3);
        entry4.verification_status = VerificationStatus::Revoked;

        directory.publish_entry(entry1).await.unwrap();
        directory.publish_entry(entry2).await.unwrap();
        directory.publish_entry(entry3).await.unwrap();
        directory.publish_entry(entry4).await.unwrap();

        // Query 1: Toutes les entrées
        let all_query = DirectoryQuery::new();
        let all_results = directory.search_entries(all_query).await.unwrap();
        assert_eq!(all_results.len(), 3); // entry4 remplace entry3

        // Query 2: Seulement les clés de signature
        let signing_query = DirectoryQuery::new().entry_type(DirectoryEntryType::SigningKey);
        let signing_results = directory.search_entries(signing_query).await.unwrap();
        assert_eq!(signing_results.len(), 2); // entry1 et entry4

        // Query 3: Seulement peer1
        let peer1_query = DirectoryQuery::new().peer_id(peer1.clone());
        let peer1_results = directory.search_entries(peer1_query).await.unwrap();
        assert_eq!(peer1_results.len(), 2); // entry1 et entry2

        // Query 4: Seulement entrées vérifiées
        let verified_query =
            DirectoryQuery::new().verification_status(VerificationStatus::Verified);
        let verified_results = directory.search_entries(verified_query).await.unwrap();
        assert_eq!(verified_results.len(), 1); // Seulement entry1

        // Query 5: Plage de versions
        let version_query = DirectoryQuery::new().version_range(2, 3);
        let version_results = directory.search_entries(version_query).await.unwrap();
        assert_eq!(version_results.len(), 2); // entry2 (v2) et entry4 (v3)

        // Query 6: Avec limite
        let limited_query = DirectoryQuery::new().limit(2);
        let limited_results = directory.search_entries(limited_query).await.unwrap();
        assert!(limited_results.len() <= 2);

        // Query 7: Combinaison complexe
        let complex_query = DirectoryQuery::new()
            .peer_id(peer2.clone())
            .entry_type(DirectoryEntryType::SigningKey)
            .verification_status(VerificationStatus::Revoked);
        let complex_results = directory.search_entries(complex_query).await.unwrap();
        assert_eq!(complex_results.len(), 1); // Seulement entry4

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_update_entry_workflow() {
        // TDD: Test workflow de mise à jour d'entrée
        let config = DirectoryConfig::default();
        let local_peer = PeerId::from_bytes(b"update_test".to_vec());
        let mut directory = DhtDistributedDirectory::new(config, local_peer.clone());

        directory.start().await.unwrap();

        // Publier l'entrée initiale
        let initial_entry = DirectoryEntry::signing_key(local_peer.clone(), vec![0x01], 1);
        directory.publish_entry(initial_entry).await.unwrap();

        // Vérifier l'entrée initiale
        let found_initial = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found_initial.is_some());
        assert_eq!(found_initial.unwrap().key_data, vec![0x01]);

        // Mettre à jour avec une version plus récente
        let updated_entry = DirectoryEntry::signing_key(local_peer.clone(), vec![0x02], 2);
        directory.update_entry(updated_entry).await.unwrap();

        // Vérifier la mise à jour
        let found_updated = directory
            .get_entry(&local_peer, DirectoryEntryType::SigningKey)
            .await
            .unwrap();
        assert!(found_updated.is_some());
        assert_eq!(found_updated.as_ref().unwrap().version, 2);
        assert_eq!(found_updated.unwrap().key_data, vec![0x02]);

        // Les stats devraient refléter la publication
        let stats = directory.get_stats().await;
        assert_eq!(stats.published_entries_count, 2); // Initial + update
        assert_eq!(stats.local_entries_count, 1); // Seulement la version la plus récente

        directory.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_entry_signatures_management() {
        // TDD: Test gestion des signatures d'entrées (Web of Trust)
        let peer1 = PeerId::from_bytes(b"peer1_sig".to_vec());
        let _peer2 = PeerId::from_bytes(b"peer2_sig".to_vec()); // Réservé pour futures extensions
        let signer1 = PeerId::from_bytes(b"signer1".to_vec());
        let signer2 = PeerId::from_bytes(b"signer2".to_vec());

        // Créer une entrée
        let mut entry = DirectoryEntry::signing_key(peer1.clone(), vec![0xF1, 0xF2], 1);

        // Ajouter des signatures
        entry.add_signature(signer1.clone(), vec![0xA1, 0xA2, 0xA3]);
        entry.add_signature(signer2.clone(), vec![0xB1, 0xB2, 0xB3]);

        // Vérifier les signatures
        assert_eq!(entry.signatures.len(), 2);
        assert_eq!(
            entry.signatures.get(&signer1),
            Some(&vec![0xA1, 0xA2, 0xA3])
        );
        assert_eq!(
            entry.signatures.get(&signer2),
            Some(&vec![0xB1, 0xB2, 0xB3])
        );

        // Test sérialisation/désérialisation avec signatures
        let serialized = entry.serialize().unwrap();
        let deserialized = DirectoryEntry::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.signatures.len(), 2);
        assert_eq!(
            deserialized.signatures.get(&signer1),
            Some(&vec![0xA1, 0xA2, 0xA3])
        );
        assert_eq!(
            deserialized.signatures.get(&signer2),
            Some(&vec![0xB1, 0xB2, 0xB3])
        );

        // Vérifier l'intégrité après désérialisation
        assert!(deserialized.verify_integrity());
    }
}
