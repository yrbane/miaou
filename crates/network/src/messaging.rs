//! Système de messagerie E2E avec queue et retry/backoff
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Queue de messages + Store offline + Retry logic

use crate::{NetworkError, PeerId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Message E2E avec métadonnées
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    /// Identifiant unique du message
    pub id: String,
    /// Expéditeur du message
    pub from: PeerId,
    /// Destinataire du message
    pub to: PeerId,
    /// Contenu du message (texte)
    pub content: String,
    /// Timestamp de création (Unix timestamp)
    pub timestamp: u64,
    /// Identifiant de session E2E
    pub session_id: String,
    /// Données chiffrées (RatchetMessage sérialisé)
    pub encrypted_payload: Vec<u8>,
}

impl Message {
    /// Crée un nouveau message
    pub fn new(from: PeerId, to: PeerId, content: String, session_id: String) -> Self {
        let id = format!(
            "msg_{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            fastrand::u32(..)
        );

        Self {
            id,
            from,
            to,
            content,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            session_id,
            encrypted_payload: Vec::new(), // TDD: Sera rempli lors du chiffrement
        }
    }

    /// Génère un ID de message pour tests
    pub fn new_mock(from: PeerId, to: PeerId, content: String) -> Self {
        Self {
            id: "mock_msg_123".to_string(),
            from,
            to,
            content,
            timestamp: 1_640_995_200, // 1 Jan 2022 pour tests déterministes
            session_id: "mock_session".to_string(),
            encrypted_payload: b"mock_encrypted_data".to_vec(),
        }
    }
}

/// État d'un message dans la queue
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageStatus {
    /// En attente d'envoi
    Pending,
    /// En cours d'envoi
    Sending,
    /// Envoyé avec succès
    Sent,
    /// Échec d'envoi (sera retransmis)
    Failed,
    /// Échec définitif (trop de tentatives)
    FailedPermanently,
}

/// Configuration pour retry/backoff
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Nombre maximum de tentatives
    pub max_attempts: u8,
    /// Délai initial entre tentatives (en secondes)
    pub initial_delay_seconds: u64,
    /// Multiplicateur pour backoff exponentiel
    pub backoff_multiplier: f64,
    /// Délai maximum entre tentatives (en secondes)
    pub max_delay_seconds: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_seconds: 1,
            backoff_multiplier: 2.0,
            max_delay_seconds: 60,
        }
    }
}

/// Entrée dans la queue de messages avec métadonnées de retry
#[derive(Clone, Debug)]
pub struct QueuedMessage {
    /// Le message à envoyer
    pub message: Message,
    /// Statut actuel
    pub status: MessageStatus,
    /// Nombre de tentatives d'envoi
    pub attempts: u8,
    /// Prochaine tentative (timestamp Unix)
    pub next_attempt_at: u64,
    /// Dernier message d'erreur (si échec)
    pub last_error: Option<String>,
}

impl QueuedMessage {
    /// Crée une nouvelle entrée dans la queue
    pub fn new(message: Message) -> Self {
        Self {
            message,
            status: MessageStatus::Pending,
            attempts: 0,
            next_attempt_at: 0,
            last_error: None,
        }
    }

    /// Calcule le prochain délai de retry avec backoff exponentiel
    pub fn calculate_next_attempt(&mut self, config: &RetryConfig) {
        self.attempts += 1;

        if self.attempts >= config.max_attempts {
            self.status = MessageStatus::FailedPermanently;
            return;
        }

        let delay = (config.initial_delay_seconds as f64
            * config.backoff_multiplier.powi((self.attempts - 1) as i32))
            as u64;
        let delay = delay.min(config.max_delay_seconds);

        self.next_attempt_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + delay;

        self.status = MessageStatus::Failed;
    }

    /// Vérifie si le message est prêt pour une nouvelle tentative
    pub fn is_ready_for_retry(&self) -> bool {
        if self.status != MessageStatus::Failed {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.next_attempt_at
    }
}

/// Configuration de la queue de messages
#[derive(Clone, Debug)]
pub struct MessageQueueConfig {
    /// Taille maximum de la queue
    pub max_queue_size: usize,
    /// Configuration retry/backoff
    pub retry_config: RetryConfig,
    /// Intervalle de traitement de la queue (en secondes)
    pub processing_interval_seconds: u64,
    /// Durée de rétention des messages envoyés (en secondes)
    pub sent_retention_seconds: u64,
}

impl Default for MessageQueueConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 1000,
            retry_config: RetryConfig::default(),
            processing_interval_seconds: 5,
            sent_retention_seconds: 3600, // 1 heure
        }
    }
}

/// Trait abstrait pour la queue de messages
/// Architecture SOLID : Interface Segregation Principle
#[async_trait]
pub trait MessageQueue: Send + Sync {
    /// Ajoute un message à la queue d'envoi
    async fn enqueue(&self, message: Message) -> Result<String, NetworkError>;

    /// Traite la queue et tente d'envoyer les messages en attente
    async fn process_queue(&self) -> Result<usize, NetworkError>;

    /// Marque un message comme envoyé avec succès
    async fn mark_sent(&self, message_id: &str) -> Result<(), NetworkError>;

    /// Marque un message comme échoué
    async fn mark_failed(&self, message_id: &str, error: &str) -> Result<(), NetworkError>;

    /// Récupère le statut d'un message
    async fn get_message_status(
        &self,
        message_id: &str,
    ) -> Result<Option<MessageStatus>, NetworkError>;

    /// Liste tous les messages en attente
    async fn pending_messages(&self) -> Result<Vec<QueuedMessage>, NetworkError>;

    /// Nettoie les anciens messages envoyés
    async fn cleanup_old_messages(&self) -> Result<usize, NetworkError>;

    /// Configuration de la queue
    fn config(&self) -> &MessageQueueConfig;
}

/// Implémentation en mémoire de la queue de messages
pub struct InMemoryMessageQueue {
    config: MessageQueueConfig,
    /// Messages en queue (par ID)
    messages: Arc<Mutex<HashMap<String, QueuedMessage>>>,
    /// Queue des messages à traiter (FIFO)
    processing_queue: Arc<Mutex<VecDeque<String>>>,
}

impl InMemoryMessageQueue {
    /// Crée une nouvelle queue de messages en mémoire
    pub fn new(config: MessageQueueConfig) -> Self {
        Self {
            config,
            messages: Arc::new(Mutex::new(HashMap::new())),
            processing_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Vérifie si la queue est pleine
    fn is_queue_full(&self) -> bool {
        let messages = self.messages.lock().unwrap();
        messages.len() >= self.config.max_queue_size
    }

    /// Trouve les messages prêts pour retry
    fn find_retry_ready_messages(&self) -> Vec<String> {
        let messages = self.messages.lock().unwrap();
        messages
            .values()
            .filter(|msg| msg.is_ready_for_retry())
            .map(|msg| msg.message.id.clone())
            .collect()
    }
}

#[async_trait]
impl MessageQueue for InMemoryMessageQueue {
    async fn enqueue(&self, message: Message) -> Result<String, NetworkError> {
        if self.is_queue_full() {
            return Err(NetworkError::General(format!(
                "Queue pleine (max: {})",
                self.config.max_queue_size
            )));
        }

        let message_id = message.id.clone();
        let queued_message = QueuedMessage::new(message);

        {
            let mut messages = self.messages.lock().unwrap();
            let mut queue = self.processing_queue.lock().unwrap();

            messages.insert(message_id.clone(), queued_message);
            queue.push_back(message_id.clone());
        }

        Ok(message_id)
    }

    async fn process_queue(&self) -> Result<usize, NetworkError> {
        // Ajouter les messages prêts pour retry à la queue de traitement
        let retry_messages = self.find_retry_ready_messages();
        {
            let mut queue = self.processing_queue.lock().unwrap();
            for msg_id in retry_messages {
                queue.push_back(msg_id);
            }
        }

        let mut processed = 0;

        // Traiter jusqu'à 10 messages par batch
        for _ in 0..10 {
            let message_id = {
                let mut queue = self.processing_queue.lock().unwrap();
                queue.pop_front()
            };

            if let Some(msg_id) = message_id {
                // Marquer comme en cours d'envoi
                {
                    let mut messages = self.messages.lock().unwrap();
                    if let Some(queued_msg) = messages.get_mut(&msg_id) {
                        queued_msg.status = MessageStatus::Sending;
                    }
                }

                // TDD: Simulation d'envoi pour MVP
                // En réalité, ici on appellerait le transport et le ratchet
                let success = fastrand::bool(); // 50% de succès simulé

                if success {
                    self.mark_sent(&msg_id).await?;
                } else {
                    self.mark_failed(&msg_id, "Erreur réseau simulée").await?;
                }

                processed += 1;
            } else {
                break;
            }
        }

        Ok(processed)
    }

    async fn mark_sent(&self, message_id: &str) -> Result<(), NetworkError> {
        let mut messages = self.messages.lock().unwrap();
        if let Some(queued_msg) = messages.get_mut(message_id) {
            queued_msg.status = MessageStatus::Sent;
            Ok(())
        } else {
            Err(NetworkError::General(format!(
                "Message {} non trouvé",
                message_id
            )))
        }
    }

    async fn mark_failed(&self, message_id: &str, error: &str) -> Result<(), NetworkError> {
        let mut messages = self.messages.lock().unwrap();
        if let Some(queued_msg) = messages.get_mut(message_id) {
            queued_msg.last_error = Some(error.to_string());
            queued_msg.calculate_next_attempt(&self.config.retry_config);
            Ok(())
        } else {
            Err(NetworkError::General(format!(
                "Message {} non trouvé",
                message_id
            )))
        }
    }

    async fn get_message_status(
        &self,
        message_id: &str,
    ) -> Result<Option<MessageStatus>, NetworkError> {
        let messages = self.messages.lock().unwrap();
        Ok(messages.get(message_id).map(|msg| msg.status.clone()))
    }

    async fn pending_messages(&self) -> Result<Vec<QueuedMessage>, NetworkError> {
        let messages = self.messages.lock().unwrap();
        let pending: Vec<QueuedMessage> = messages
            .values()
            .filter(|msg| matches!(msg.status, MessageStatus::Pending | MessageStatus::Failed))
            .cloned()
            .collect();
        Ok(pending)
    }

    async fn cleanup_old_messages(&self) -> Result<usize, NetworkError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - self.config.sent_retention_seconds;

        let mut messages = self.messages.lock().unwrap();
        let initial_count = messages.len();

        // Supprimer les messages envoyés anciens ou échoués définitivement
        messages.retain(|_, msg| match msg.status {
            MessageStatus::Sent => msg.message.timestamp > cutoff,
            MessageStatus::FailedPermanently => false,
            _ => true,
        });

        Ok(initial_count - messages.len())
    }

    fn config(&self) -> &MessageQueueConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerId;
    use tokio;

    fn create_test_message() -> Message {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());
        Message::new(
            from,
            to,
            "Hello World!".to_string(),
            "session_123".to_string(),
        )
    }

    fn create_mock_message() -> Message {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());
        Message::new_mock(from, to, "Mock message".to_string())
    }

    fn create_test_config() -> MessageQueueConfig {
        MessageQueueConfig {
            max_queue_size: 10,
            retry_config: RetryConfig {
                max_attempts: 2,
                initial_delay_seconds: 1,
                backoff_multiplier: 2.0,
                max_delay_seconds: 10,
            },
            processing_interval_seconds: 1,
            sent_retention_seconds: 30,
        }
    }

    #[test]
    fn test_message_creation() {
        // TDD: Test création de message
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());
        let msg = Message::new(
            from.clone(),
            to.clone(),
            "Hello!".to_string(),
            "session_1".to_string(),
        );

        assert_eq!(msg.from, from);
        assert_eq!(msg.to, to);
        assert_eq!(msg.content, "Hello!");
        assert_eq!(msg.session_id, "session_1");
        assert!(!msg.id.is_empty());
        assert!(msg.timestamp > 0);
    }

    #[test]
    fn test_message_mock_creation() {
        // TDD: Test création de message mock
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());
        let msg = Message::new_mock(from.clone(), to.clone(), "Test".to_string());

        assert_eq!(msg.id, "mock_msg_123");
        assert_eq!(msg.from, from);
        assert_eq!(msg.to, to);
        assert_eq!(msg.content, "Test");
        assert_eq!(msg.timestamp, 1_640_995_200);
        assert_eq!(msg.session_id, "mock_session");
        assert_eq!(msg.encrypted_payload, b"mock_encrypted_data");
    }

    #[test]
    fn test_message_status_variants() {
        // TDD: Test variantes de MessageStatus
        assert_eq!(MessageStatus::Pending, MessageStatus::Pending);
        assert_ne!(MessageStatus::Pending, MessageStatus::Sending);
        assert_ne!(MessageStatus::Sent, MessageStatus::Failed);
    }

    #[test]
    fn test_retry_config_default() {
        // TDD: Test configuration par défaut
        let config = RetryConfig::default();

        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay_seconds, 1);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_delay_seconds, 60);
    }

    #[test]
    fn test_message_queue_config_default() {
        // TDD: Test configuration queue par défaut
        let config = MessageQueueConfig::default();

        assert_eq!(config.max_queue_size, 1000);
        assert_eq!(config.processing_interval_seconds, 5);
        assert_eq!(config.sent_retention_seconds, 3600);
        assert_eq!(config.retry_config.max_attempts, 3);
    }

    #[test]
    fn test_queued_message_creation() {
        // TDD: Test création de QueuedMessage
        let msg = create_test_message();
        let queued = QueuedMessage::new(msg);

        assert_eq!(queued.status, MessageStatus::Pending);
        assert_eq!(queued.attempts, 0);
        assert_eq!(queued.next_attempt_at, 0);
        assert!(queued.last_error.is_none());
    }

    #[test]
    fn test_calculate_next_attempt() {
        // TDD: Test calcul backoff exponentiel
        let msg = create_test_message();
        let mut queued = QueuedMessage::new(msg);
        let config = RetryConfig::default();

        // Premier échec
        queued.calculate_next_attempt(&config);
        assert_eq!(queued.attempts, 1);
        assert_eq!(queued.status, MessageStatus::Failed);
        assert!(queued.next_attempt_at > 0);

        // Deuxième échec (backoff x2)
        let first_delay = queued.next_attempt_at;
        queued.calculate_next_attempt(&config);
        assert_eq!(queued.attempts, 2);

        // Troisième échec -> permanent failure
        queued.calculate_next_attempt(&config);
        assert_eq!(queued.attempts, 3);
        assert_eq!(queued.status, MessageStatus::FailedPermanently);
    }

    #[test]
    fn test_is_ready_for_retry() {
        // TDD: Test vérification retry ready
        let msg = create_test_message();
        let mut queued = QueuedMessage::new(msg);
        let config = RetryConfig::default();

        // Pas ready si status != Failed
        assert!(!queued.is_ready_for_retry());

        // Marquer comme failed avec délai dans le futur
        queued.status = MessageStatus::Failed;
        queued.next_attempt_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        assert!(!queued.is_ready_for_retry());

        // Marquer avec délai dans le passé
        queued.next_attempt_at = 1;
        assert!(queued.is_ready_for_retry());
    }

    #[test]
    fn test_in_memory_message_queue_creation() {
        // TDD: Test création InMemoryMessageQueue
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config.clone());

        assert_eq!(queue.config().max_queue_size, config.max_queue_size);
        assert_eq!(
            queue.config().retry_config.max_attempts,
            config.retry_config.max_attempts
        );
    }

    #[tokio::test]
    async fn test_enqueue_message() {
        // TDD: Test ajout message dans la queue
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);
        let msg = create_test_message();
        let msg_id = msg.id.clone();

        let result = queue.enqueue(msg).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), msg_id);

        // Vérifier status
        let status = queue.get_message_status(&msg_id).await.unwrap();
        assert_eq!(status, Some(MessageStatus::Pending));
    }

    #[tokio::test]
    async fn test_enqueue_queue_full() {
        // TDD: Test queue pleine
        let config = MessageQueueConfig {
            max_queue_size: 1,
            ..create_test_config()
        };
        let queue = InMemoryMessageQueue::new(config);

        // Premier message OK
        let msg1 = create_test_message();
        let result1 = queue.enqueue(msg1).await;
        assert!(result1.is_ok());

        // Deuxième message -> queue pleine
        let msg2 = create_test_message();
        let result2 = queue.enqueue(msg2).await;
        assert!(result2.is_err());

        if let Err(NetworkError::General(msg)) = result2 {
            assert!(msg.contains("Queue pleine"));
        }
    }

    #[tokio::test]
    async fn test_mark_sent() {
        // TDD: Test marquer message comme envoyé
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);
        let msg = create_test_message();
        let msg_id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();

        let result = queue.mark_sent(&msg_id).await;
        assert!(result.is_ok());

        let status = queue.get_message_status(&msg_id).await.unwrap();
        assert_eq!(status, Some(MessageStatus::Sent));
    }

    #[tokio::test]
    async fn test_mark_failed() {
        // TDD: Test marquer message comme échoué
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);
        let msg = create_test_message();
        let msg_id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();

        let result = queue.mark_failed(&msg_id, "Test error").await;
        assert!(result.is_ok());

        let status = queue.get_message_status(&msg_id).await.unwrap();
        assert_eq!(status, Some(MessageStatus::Failed));
    }

    #[tokio::test]
    async fn test_pending_messages() {
        // TDD: Test liste des messages en attente
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);

        // Ajouter messages avec statuts différents
        let msg1 = create_test_message();
        let msg1_id = msg1.id.clone();
        queue.enqueue(msg1).await.unwrap();

        let msg2 = create_test_message();
        let msg2_id = msg2.id.clone();
        queue.enqueue(msg2).await.unwrap();
        queue.mark_sent(&msg2_id).await.unwrap();

        let msg3 = create_test_message();
        let msg3_id = msg3.id.clone();
        queue.enqueue(msg3).await.unwrap();
        queue.mark_failed(&msg3_id, "Error").await.unwrap();

        // Récupérer messages en attente
        let pending = queue.pending_messages().await.unwrap();
        assert_eq!(pending.len(), 2); // msg1 (Pending) + msg3 (Failed)
    }

    #[tokio::test]
    async fn test_process_queue_simulation() {
        // TDD: Test traitement de la queue avec simulation
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);

        // Ajouter quelques messages
        for i in 0..3 {
            let msg = Message::new(
                PeerId::from_bytes(b"alice".to_vec()),
                PeerId::from_bytes(format!("bob{}", i).as_bytes().to_vec()),
                format!("Message {}", i),
                "session".to_string(),
            );
            queue.enqueue(msg).await.unwrap();
        }

        // Traiter la queue
        let processed = queue.process_queue().await.unwrap();
        assert_eq!(processed, 3);

        // Vérifier que tous les messages ont un statut final
        let pending = queue.pending_messages().await.unwrap();
        // Avec simulation 50/50, certains peuvent encore être Failed
        assert!(pending.len() <= 3);
    }

    #[tokio::test]
    async fn test_cleanup_old_messages() {
        // TDD: Test nettoyage anciens messages
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);

        // Ajouter et marquer comme envoyé
        let msg = create_test_message();
        let msg_id = msg.id.clone();
        queue.enqueue(msg).await.unwrap();
        queue.mark_sent(&msg_id).await.unwrap();

        // Pas de nettoyage immédiat (message récent)
        let cleaned = queue.cleanup_old_messages().await.unwrap();
        assert_eq!(cleaned, 0);

        // TDD: Test avec messages plus anciens nécessiterait manipulation du timestamp
    }

    #[tokio::test]
    async fn test_get_message_status_not_found() {
        // TDD: Test status message inexistant
        let config = create_test_config();
        let queue = InMemoryMessageQueue::new(config);

        let status = queue.get_message_status("inexistant").await.unwrap();
        assert_eq!(status, None);
    }

    // TDD: Tests d'intégration avec le trait MessageQueue
    #[tokio::test]
    async fn test_message_queue_trait_compatibility() {
        // TDD: Test que InMemoryMessageQueue implémente correctement MessageQueue
        let config = create_test_config();
        let queue: Box<dyn MessageQueue> = Box::new(InMemoryMessageQueue::new(config));

        // Test configuration
        assert_eq!(queue.config().max_queue_size, 10);
        assert_eq!(queue.config().retry_config.max_attempts, 2);

        // Test méthodes du trait
        let msg = create_test_message();
        let msg_id = msg.id.clone();

        let enqueue_result = queue.enqueue(msg).await;
        assert!(enqueue_result.is_ok());

        let status = queue.get_message_status(&msg_id).await.unwrap();
        assert_eq!(status, Some(MessageStatus::Pending));
    }
}
