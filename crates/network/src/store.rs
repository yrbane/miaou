//! Store offline chiffré pour messages et métadonnées  
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Persistance chiffrée + Interface abstraite

use crate::{Message, NetworkError, PeerId};
use async_trait::async_trait;
use miaou_crypto::{blake3_hash, AeadCipher, Chacha20Poly1305Cipher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Entrée dans le store offline avec métadonnées de chiffrement
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Message original
    pub message: Message,
    /// Timestamp de stockage
    pub stored_at: u64,
    /// Marqué comme lu
    pub is_read: bool,
    /// Catégorie (sent/received/draft)
    pub category: MessageCategory,
    /// Hash du contenu pour intégrité
    pub content_hash: Vec<u8>,
}

/// Catégorie de message stocké
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCategory {
    /// Message reçu
    Received,
    /// Message envoyé
    Sent,
    /// Brouillon
    Draft,
    /// Message système
    System,
}

impl StoredMessage {
    /// Crée une nouvelle entrée stockée
    pub fn new(message: Message, category: MessageCategory) -> Self {
        // Calculer hash du contenu pour intégrité
        let content_hash = blake3_hash(message.content.as_bytes()).to_vec();

        Self {
            message,
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_read: false,
            category,
            content_hash,
        }
    }

    /// Crée une entrée mock pour tests
    pub fn new_mock(message: Message, category: MessageCategory) -> Self {
        Self {
            message,
            stored_at: 1_640_995_200, // 1 Jan 2022 pour tests déterministes
            is_read: false,
            category,
            content_hash: vec![0x12, 0x34, 0x56, 0x78], // Hash mock
        }
    }

    /// Vérifie l'intégrité du message
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = blake3_hash(self.message.content.as_bytes()).to_vec();
        computed_hash == self.content_hash
    }

    /// Marque le message comme lu
    pub fn mark_read(&mut self) {
        self.is_read = true;
    }
}

/// Requête de recherche dans le store
#[derive(Clone, Debug)]
pub struct MessageQuery {
    /// Filtrer par expéditeur
    pub from: Option<PeerId>,
    /// Filtrer par destinataire  
    pub to: Option<PeerId>,
    /// Filtrer par catégorie
    pub category: Option<MessageCategory>,
    /// Filtrer messages non lus seulement
    pub unread_only: bool,
    /// Recherche dans le contenu
    pub content_search: Option<String>,
    /// Limite de résultats
    pub limit: Option<usize>,
    /// Trier par timestamp (desc = plus récent d'abord)
    pub sort_desc: bool,
}

impl Default for MessageQuery {
    fn default() -> Self {
        Self {
            from: None,
            to: None,
            category: None,
            unread_only: false,
            content_search: None,
            limit: Some(100), // Par défaut, limiter à 100 résultats
            sort_desc: true,  // Plus récents d'abord par défaut
        }
    }
}

impl MessageQuery {
    /// Crée une requête vide
    pub fn new() -> Self {
        Self::default()
    }

    /// Filtre par expéditeur
    pub fn from(mut self, peer: PeerId) -> Self {
        self.from = Some(peer);
        self
    }

    /// Filtre par destinataire
    pub fn to(mut self, peer: PeerId) -> Self {
        self.to = Some(peer);
        self
    }

    /// Filtre par catégorie
    pub fn category(mut self, cat: MessageCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Messages non lus seulement
    pub fn unread_only(mut self) -> Self {
        self.unread_only = true;
        self
    }

    /// Recherche dans le contenu
    pub fn search(mut self, term: String) -> Self {
        self.content_search = Some(term);
        self
    }

    /// Limite de résultats
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
}

/// Configuration du store offline
#[derive(Clone, Debug)]
pub struct MessageStoreConfig {
    /// Clé de chiffrement principale (32 bytes)
    pub master_key: Vec<u8>,
    /// Taille maximum du store (en nombre de messages)
    pub max_messages: usize,
    /// Durée de rétention des messages (en secondes)
    pub retention_seconds: u64,
    /// Activer la compression
    pub enable_compression: bool,
    /// Chemin du fichier de store (pour implémentations persistantes)
    pub store_path: Option<String>,
}

impl MessageStoreConfig {
    /// Crée une config avec clé aléatoire pour tests
    pub fn new_test() -> Self {
        let key_bytes = vec![0x42; 32]; // Clé déterministe pour tests
        Self {
            master_key: key_bytes,
            max_messages: 1000,
            retention_seconds: 86400 * 30, // 30 jours
            enable_compression: false,
            store_path: None,
        }
    }
}

/// Trait abstrait pour le store de messages offline
/// Architecture SOLID : Interface Segregation Principle
#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Stocke un message de manière chiffrée
    async fn store_message(
        &self,
        message: Message,
        category: MessageCategory,
    ) -> Result<String, NetworkError>;

    /// Récupère un message par ID
    async fn get_message(&self, message_id: &str) -> Result<Option<StoredMessage>, NetworkError>;

    /// Recherche des messages selon une requête
    async fn query_messages(&self, query: MessageQuery)
        -> Result<Vec<StoredMessage>, NetworkError>;

    /// Met à jour le statut d'un message (lu/non lu)
    async fn update_message_status(
        &self,
        message_id: &str,
        is_read: bool,
    ) -> Result<(), NetworkError>;

    /// Supprime un message
    async fn delete_message(&self, message_id: &str) -> Result<bool, NetworkError>;

    /// Supprime les anciens messages selon la politique de rétention
    async fn cleanup_old_messages(&self) -> Result<usize, NetworkError>;

    /// Compte le nombre de messages par catégorie
    async fn count_messages(
        &self,
        category: Option<MessageCategory>,
    ) -> Result<usize, NetworkError>;

    /// Compte les messages non lus
    async fn count_unread_messages(&self) -> Result<usize, NetworkError>;

    /// Sauvegarde le store (pour implémentations persistantes)
    async fn flush(&self) -> Result<(), NetworkError>;

    /// Configuration du store
    fn config(&self) -> &MessageStoreConfig;
}

/// Implémentation en mémoire du store de messages (avec chiffrement simulé)
pub struct InMemoryMessageStore {
    config: MessageStoreConfig,
    /// Messages stockés (chiffrés en mémoire)
    messages: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Index pour recherche rapide
    message_index: Arc<Mutex<HashMap<String, StoredMessage>>>,
    /// Cipher pour chiffrement/déchiffrement
    cipher: Chacha20Poly1305Cipher,
}

impl InMemoryMessageStore {
    /// Crée un nouveau store en mémoire
    pub fn new(config: MessageStoreConfig) -> Result<Self, NetworkError> {
        let cipher = Chacha20Poly1305Cipher::from_key_bytes(&config.master_key)
            .map_err(|e| NetworkError::General(format!("Erreur init cipher: {:?}", e)))?;

        Ok(Self {
            config,
            messages: Arc::new(Mutex::new(HashMap::new())),
            message_index: Arc::new(Mutex::new(HashMap::new())),
            cipher,
        })
    }

    /// Chiffre un message stocké
    fn encrypt_stored_message(&self, stored_msg: &StoredMessage) -> Result<Vec<u8>, NetworkError> {
        let serialized = serde_json::to_vec(stored_msg)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        // Générer une nonce aléatoire
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| NetworkError::General(format!("Erreur génération nonce: {e}")))?;

        // Chiffrer avec le cipher
        let encrypted = self
            .cipher
            .encrypt(&serialized, &nonce, b"message_store")
            .map_err(|e| NetworkError::CryptoError(format!("Chiffrement échoué: {e:?}")))?;

        // Préfixer avec la nonce pour le déchiffrement
        let mut result = nonce.to_vec();
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    /// Déchiffre un message stocké
    fn decrypt_stored_message(&self, encrypted: &[u8]) -> Result<StoredMessage, NetworkError> {
        if encrypted.len() < 12 {
            return Err(NetworkError::General(
                "Données chiffrées trop courtes".to_string(),
            ));
        }

        // Extraire la nonce (12 premiers bytes)
        let nonce: [u8; 12] = encrypted[..12]
            .try_into()
            .map_err(|_| NetworkError::General("Nonce invalide".to_string()))?;

        // Déchiffrer le reste
        let ciphertext = &encrypted[12..];
        let decrypted = self
            .cipher
            .decrypt(ciphertext, &nonce, b"message_store")
            .map_err(|e| NetworkError::CryptoError(format!("Déchiffrement échoué: {e:?}")))?;

        let stored_msg: StoredMessage = serde_json::from_slice(&decrypted)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        Ok(stored_msg)
    }

    /// Vérifie si le store est plein
    fn is_store_full(&self) -> bool {
        let index = self.message_index.lock().unwrap();
        index.len() >= self.config.max_messages
    }

    /// Applique les filtres de requête
    fn apply_query_filters(
        &self,
        messages: Vec<StoredMessage>,
        query: &MessageQuery,
    ) -> Vec<StoredMessage> {
        let mut filtered: Vec<StoredMessage> = messages
            .into_iter()
            .filter(|msg| {
                // Filtre par expéditeur
                if let Some(ref from) = query.from {
                    if msg.message.from != *from {
                        return false;
                    }
                }

                // Filtre par destinataire
                if let Some(ref to) = query.to {
                    if msg.message.to != *to {
                        return false;
                    }
                }

                // Filtre par catégorie
                if let Some(ref category) = query.category {
                    if msg.category != *category {
                        return false;
                    }
                }

                // Filtre non lus seulement
                if query.unread_only && msg.is_read {
                    return false;
                }

                // Recherche dans le contenu
                if let Some(ref search_term) = query.content_search {
                    if !msg
                        .message
                        .content
                        .to_lowercase()
                        .contains(&search_term.to_lowercase())
                    {
                        return false;
                    }
                }

                true
            })
            .collect();

        // Tri par timestamp
        if query.sort_desc {
            filtered.sort_by(|a, b| b.message.timestamp.cmp(&a.message.timestamp));
        } else {
            filtered.sort_by(|a, b| a.message.timestamp.cmp(&b.message.timestamp));
        }

        // Limite de résultats
        if let Some(limit) = query.limit {
            filtered.truncate(limit);
        }

        filtered
    }
}

#[async_trait]
impl MessageStore for InMemoryMessageStore {
    async fn store_message(
        &self,
        message: Message,
        category: MessageCategory,
    ) -> Result<String, NetworkError> {
        if self.is_store_full() {
            return Err(NetworkError::General(format!(
                "Store plein (max: {})",
                self.config.max_messages
            )));
        }

        let message_id = message.id.clone();
        let stored_msg = StoredMessage::new(message, category);

        // Chiffrer le message
        let encrypted = self.encrypt_stored_message(&stored_msg)?;

        {
            let mut messages = self.messages.lock().unwrap();
            let mut index = self.message_index.lock().unwrap();

            messages.insert(message_id.clone(), encrypted);
            index.insert(message_id.clone(), stored_msg);
        }

        Ok(message_id)
    }

    async fn get_message(&self, message_id: &str) -> Result<Option<StoredMessage>, NetworkError> {
        let messages = self.messages.lock().unwrap();

        if let Some(encrypted) = messages.get(message_id) {
            let stored_msg = self.decrypt_stored_message(encrypted)?;
            Ok(Some(stored_msg))
        } else {
            Ok(None)
        }
    }

    async fn query_messages(
        &self,
        query: MessageQuery,
    ) -> Result<Vec<StoredMessage>, NetworkError> {
        let index = self.message_index.lock().unwrap();
        let all_messages: Vec<StoredMessage> = index.values().cloned().collect();
        drop(index);

        let filtered = self.apply_query_filters(all_messages, &query);
        Ok(filtered)
    }

    async fn update_message_status(
        &self,
        message_id: &str,
        is_read: bool,
    ) -> Result<(), NetworkError> {
        let mut index = self.message_index.lock().unwrap();

        if let Some(stored_msg) = index.get_mut(message_id) {
            stored_msg.is_read = is_read;

            // Re-chiffrer avec le nouveau statut
            let encrypted = self.encrypt_stored_message(stored_msg)?;
            let mut messages = self.messages.lock().unwrap();
            messages.insert(message_id.to_string(), encrypted);

            Ok(())
        } else {
            Err(NetworkError::General(format!(
                "Message {} non trouvé",
                message_id
            )))
        }
    }

    async fn delete_message(&self, message_id: &str) -> Result<bool, NetworkError> {
        let mut messages = self.messages.lock().unwrap();
        let mut index = self.message_index.lock().unwrap();

        let deleted_encrypted = messages.remove(message_id).is_some();
        let deleted_index = index.remove(message_id).is_some();

        Ok(deleted_encrypted || deleted_index)
    }

    async fn cleanup_old_messages(&self) -> Result<usize, NetworkError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - self.config.retention_seconds;

        let mut messages = self.messages.lock().unwrap();
        let mut index = self.message_index.lock().unwrap();

        let initial_count = index.len();

        // Collecter les IDs des messages expirés
        let expired_ids: Vec<String> = index
            .iter()
            .filter(|(_, stored_msg)| stored_msg.stored_at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        // Supprimer les messages expirés
        for id in &expired_ids {
            messages.remove(id);
            index.remove(id);
        }

        Ok(initial_count - index.len())
    }

    async fn count_messages(
        &self,
        category: Option<MessageCategory>,
    ) -> Result<usize, NetworkError> {
        let index = self.message_index.lock().unwrap();

        if let Some(cat) = category {
            Ok(index.values().filter(|msg| msg.category == cat).count())
        } else {
            Ok(index.len())
        }
    }

    async fn count_unread_messages(&self) -> Result<usize, NetworkError> {
        let index = self.message_index.lock().unwrap();
        Ok(index.values().filter(|msg| !msg.is_read).count())
    }

    async fn flush(&self) -> Result<(), NetworkError> {
        // Pour implémentation en mémoire, pas d'action nécessaire
        // Dans une implémentation persistante, ici on sauvegarderait sur disque
        Ok(())
    }

    fn config(&self) -> &MessageStoreConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, PeerId};
    use tokio;

    fn create_test_message(from: &str, to: &str, content: &str) -> Message {
        let from_peer = PeerId::from_bytes(from.as_bytes().to_vec());
        let to_peer = PeerId::from_bytes(to.as_bytes().to_vec());
        Message::new(
            from_peer,
            to_peer,
            content.to_string(),
            "session_test".to_string(),
        )
    }

    fn create_test_config() -> MessageStoreConfig {
        MessageStoreConfig {
            master_key: vec![0x42; 32],
            max_messages: 10,
            retention_seconds: 3600,
            enable_compression: false,
            store_path: None,
        }
    }

    #[test]
    fn test_message_category_variants() {
        // TDD: Test variantes de MessageCategory
        assert_eq!(MessageCategory::Received, MessageCategory::Received);
        assert_ne!(MessageCategory::Sent, MessageCategory::Draft);
        assert_ne!(MessageCategory::System, MessageCategory::Received);
    }

    #[test]
    fn test_stored_message_creation() {
        // TDD: Test création de StoredMessage
        let msg = create_test_message("alice", "bob", "Hello");
        let stored = StoredMessage::new(msg.clone(), MessageCategory::Sent);

        assert_eq!(stored.message.content, "Hello");
        assert_eq!(stored.category, MessageCategory::Sent);
        assert!(!stored.is_read);
        assert!(stored.stored_at > 0);
        assert!(!stored.content_hash.is_empty());
    }

    #[test]
    fn test_stored_message_mock_creation() {
        // TDD: Test création mock de StoredMessage
        let msg = create_test_message("alice", "bob", "Mock");
        let stored = StoredMessage::new_mock(msg, MessageCategory::Received);

        assert_eq!(stored.stored_at, 1_640_995_200);
        assert_eq!(stored.content_hash, vec![0x12, 0x34, 0x56, 0x78]);
        assert!(!stored.is_read);
    }

    #[test]
    fn test_stored_message_verify_integrity() {
        // TDD: Test vérification intégrité
        let msg = create_test_message("alice", "bob", "Test");
        let stored = StoredMessage::new(msg, MessageCategory::Sent);

        // Intégrité OK avec contenu non modifié
        assert!(stored.verify_integrity());

        // Créer un message avec contenu modifié
        let mut modified_stored = stored.clone();
        modified_stored.message.content = "Modified".to_string();

        // Intégrité échoue avec contenu modifié
        assert!(!modified_stored.verify_integrity());
    }

    #[test]
    fn test_stored_message_mark_read() {
        // TDD: Test marquer comme lu
        let msg = create_test_message("alice", "bob", "Test");
        let mut stored = StoredMessage::new(msg, MessageCategory::Received);

        assert!(!stored.is_read);
        stored.mark_read();
        assert!(stored.is_read);
    }

    #[test]
    fn test_message_query_default() {
        // TDD: Test requête par défaut
        let query = MessageQuery::default();

        assert!(query.from.is_none());
        assert!(query.to.is_none());
        assert!(query.category.is_none());
        assert!(!query.unread_only);
        assert!(query.content_search.is_none());
        assert_eq!(query.limit, Some(100));
        assert!(query.sort_desc);
    }

    #[test]
    fn test_message_query_builder() {
        // TDD: Test builder pattern pour MessageQuery
        let alice = PeerId::from_bytes(b"alice".to_vec());
        let bob = PeerId::from_bytes(b"bob".to_vec());

        let query = MessageQuery::new()
            .from(alice.clone())
            .to(bob.clone())
            .category(MessageCategory::Sent)
            .unread_only()
            .search("hello".to_string())
            .limit(50);

        assert_eq!(query.from, Some(alice));
        assert_eq!(query.to, Some(bob));
        assert_eq!(query.category, Some(MessageCategory::Sent));
        assert!(query.unread_only);
        assert_eq!(query.content_search, Some("hello".to_string()));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn test_message_store_config_test() {
        // TDD: Test config de test
        let config = MessageStoreConfig::new_test();

        assert_eq!(config.master_key.len(), 32);
        assert_eq!(config.max_messages, 1000);
        assert_eq!(config.retention_seconds, 86400 * 30);
        assert!(!config.enable_compression);
        assert!(config.store_path.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_message_store_creation() {
        // TDD: Test création InMemoryMessageStore
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config);

        assert!(store.is_ok());
        let store = store.unwrap();
        assert_eq!(store.config().max_messages, 10);
    }

    #[tokio::test]
    async fn test_store_and_get_message() {
        // TDD: Test stockage et récupération de message
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let msg = create_test_message("alice", "bob", "Hello World!");
        let msg_id = msg.id.clone();

        // Stocker le message
        let stored_id = store
            .store_message(msg, MessageCategory::Sent)
            .await
            .unwrap();
        assert_eq!(stored_id, msg_id);

        // Récupérer le message
        let retrieved = store.get_message(&msg_id).await.unwrap();
        assert!(retrieved.is_some());

        let stored_msg = retrieved.unwrap();
        assert_eq!(stored_msg.message.content, "Hello World!");
        assert_eq!(stored_msg.category, MessageCategory::Sent);
        assert!(stored_msg.verify_integrity());
    }

    #[tokio::test]
    async fn test_get_nonexistent_message() {
        // TDD: Test récupération message inexistant
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let result = store.get_message("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_store_full() {
        // TDD: Test store plein
        let config = MessageStoreConfig {
            max_messages: 2,
            ..create_test_config()
        };
        let store = InMemoryMessageStore::new(config).unwrap();

        // Remplir le store
        for i in 0..2 {
            let msg = create_test_message("alice", "bob", &format!("Message {}", i));
            store
                .store_message(msg, MessageCategory::Sent)
                .await
                .unwrap();
        }

        // Tentative d'ajouter un message de plus -> erreur
        let msg = create_test_message("alice", "bob", "Overflow");
        let result = store.store_message(msg, MessageCategory::Sent).await;

        assert!(result.is_err());
        if let Err(NetworkError::General(msg)) = result {
            assert!(msg.contains("Store plein"));
        }
    }

    #[tokio::test]
    async fn test_query_messages_basic() {
        // TDD: Test requête basique
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        // Ajouter quelques messages
        let msg1 = create_test_message("alice", "bob", "Hello");
        let msg2 = create_test_message("bob", "alice", "Hi there");

        store
            .store_message(msg1, MessageCategory::Sent)
            .await
            .unwrap();
        store
            .store_message(msg2, MessageCategory::Received)
            .await
            .unwrap();

        // Requête pour tous les messages
        let query = MessageQuery::default();
        let results = store.query_messages(query).await.unwrap();

        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_query_messages_with_filters() {
        // TDD: Test requête avec filtres
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let alice = PeerId::from_bytes(b"alice".to_vec());
        let bob = PeerId::from_bytes(b"bob".to_vec());

        // Ajouter messages variés
        let msg1 = create_test_message("alice", "bob", "Hello from Alice");
        let msg2 = create_test_message("bob", "alice", "Hi from Bob");
        let msg3 = create_test_message("alice", "charlie", "Secret message");

        store
            .store_message(msg1, MessageCategory::Sent)
            .await
            .unwrap();
        store
            .store_message(msg2, MessageCategory::Received)
            .await
            .unwrap();
        store
            .store_message(msg3, MessageCategory::Draft)
            .await
            .unwrap();

        // Requête avec filtre expéditeur
        let query = MessageQuery::new().from(alice.clone());
        let results = store.query_messages(query).await.unwrap();
        assert_eq!(results.len(), 2); // msg1 + msg3

        // Requête avec filtre catégorie
        let query = MessageQuery::new().category(MessageCategory::Received);
        let results = store.query_messages(query).await.unwrap();
        assert_eq!(results.len(), 1); // msg2 seulement

        // Requête avec recherche contenu
        let query = MessageQuery::new().search("Secret".to_string());
        let results = store.query_messages(query).await.unwrap();
        assert_eq!(results.len(), 1); // msg3 seulement
    }

    #[tokio::test]
    async fn test_update_message_status() {
        // TDD: Test mise à jour statut message
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let msg = create_test_message("alice", "bob", "Test");
        let msg_id = msg.id.clone();

        store
            .store_message(msg, MessageCategory::Received)
            .await
            .unwrap();

        // Vérifier non lu initialement
        let stored = store.get_message(&msg_id).await.unwrap().unwrap();
        assert!(!stored.is_read);

        // Marquer comme lu
        store.update_message_status(&msg_id, true).await.unwrap();

        // Vérifier maintenant lu
        let updated = store.get_message(&msg_id).await.unwrap().unwrap();
        assert!(updated.is_read);
    }

    #[tokio::test]
    async fn test_delete_message() {
        // TDD: Test suppression message
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let msg = create_test_message("alice", "bob", "To be deleted");
        let msg_id = msg.id.clone();

        store
            .store_message(msg, MessageCategory::Draft)
            .await
            .unwrap();

        // Vérifier présence
        let exists = store.get_message(&msg_id).await.unwrap();
        assert!(exists.is_some());

        // Supprimer
        let deleted = store.delete_message(&msg_id).await.unwrap();
        assert!(deleted);

        // Vérifier absence
        let gone = store.get_message(&msg_id).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_count_messages() {
        // TDD: Test comptage messages
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        // Ajouter messages différentes catégories
        let msg1 = create_test_message("alice", "bob", "Sent");
        let msg2 = create_test_message("bob", "alice", "Received");
        let msg3 = create_test_message("alice", "charlie", "Draft");

        store
            .store_message(msg1, MessageCategory::Sent)
            .await
            .unwrap();
        store
            .store_message(msg2, MessageCategory::Received)
            .await
            .unwrap();
        store
            .store_message(msg3, MessageCategory::Draft)
            .await
            .unwrap();

        // Compter tous
        let total = store.count_messages(None).await.unwrap();
        assert_eq!(total, 3);

        // Compter par catégorie
        let sent_count = store
            .count_messages(Some(MessageCategory::Sent))
            .await
            .unwrap();
        assert_eq!(sent_count, 1);

        let draft_count = store
            .count_messages(Some(MessageCategory::Draft))
            .await
            .unwrap();
        assert_eq!(draft_count, 1);
    }

    #[tokio::test]
    async fn test_count_unread_messages() {
        // TDD: Test comptage messages non lus
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let msg1 = create_test_message("alice", "bob", "Unread 1");
        let msg1_id = msg1.id.clone();
        let msg2 = create_test_message("bob", "alice", "Unread 2");
        let msg3 = create_test_message("charlie", "alice", "Unread 3");

        store
            .store_message(msg1, MessageCategory::Received)
            .await
            .unwrap();
        store
            .store_message(msg2, MessageCategory::Received)
            .await
            .unwrap();
        store
            .store_message(msg3, MessageCategory::Received)
            .await
            .unwrap();

        // Tous non lus initialement
        let unread = store.count_unread_messages().await.unwrap();
        assert_eq!(unread, 3);

        // Marquer un comme lu
        store.update_message_status(&msg1_id, true).await.unwrap();

        // Plus que 2 non lus
        let unread = store.count_unread_messages().await.unwrap();
        assert_eq!(unread, 2);
    }

    #[tokio::test]
    async fn test_cleanup_old_messages() {
        // TDD: Test nettoyage anciens messages
        let config = MessageStoreConfig {
            retention_seconds: 1, // 1 seconde pour test rapide
            ..create_test_config()
        };
        let store = InMemoryMessageStore::new(config).unwrap();

        // Créer un message avec un timestamp mock (ancien)
        let msg = create_test_message("alice", "bob", "Old message");
        let old_stored_msg = StoredMessage {
            message: msg,
            stored_at: 1000, // Timestamp très ancien (1970 + 1000 secondes)
            is_read: false,
            category: MessageCategory::Sent,
            content_hash: vec![0x12, 0x34, 0x56, 0x78],
        };

        // Insérer directement dans l'index avec timestamp ancien
        {
            let mut index = store.message_index.lock().unwrap();
            let msg_id = old_stored_msg.message.id.clone();
            index.insert(msg_id.clone(), old_stored_msg);
        }

        // Nettoyer
        let cleaned = store.cleanup_old_messages().await.unwrap();
        assert_eq!(cleaned, 1);

        // Vérifier que le store est vide
        let total = store.count_messages(None).await.unwrap();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_flush() {
        // TDD: Test flush (pas d'action pour implémentation mémoire)
        let config = create_test_config();
        let store = InMemoryMessageStore::new(config).unwrap();

        let result = store.flush().await;
        assert!(result.is_ok());
    }

    // TDD: Tests d'intégration avec le trait MessageStore
    #[tokio::test]
    async fn test_message_store_trait_compatibility() {
        // TDD: Test que InMemoryMessageStore implémente correctement MessageStore
        let config = create_test_config();
        let store: Box<dyn MessageStore> = Box::new(InMemoryMessageStore::new(config).unwrap());

        // Test configuration
        assert_eq!(store.config().max_messages, 10);

        // Test méthodes du trait
        let msg = create_test_message("alice", "bob", "Trait test");
        let msg_id = msg.id.clone();

        let stored_id = store
            .store_message(msg, MessageCategory::System)
            .await
            .unwrap();
        assert_eq!(stored_id, msg_id);

        let retrieved = store.get_message(&msg_id).await.unwrap();
        assert!(retrieved.is_some());
    }
}
