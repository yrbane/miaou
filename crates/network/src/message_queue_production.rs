//! Message Queue Production avec retry et persistance
//!
//! TDD: Tests écrits AVANT implémentation  
//! Architecture: Queue fiable avec retry exponentiel et persistance

use crate::{NetworkError, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Configuration de la queue de messages production
#[derive(Debug, Clone)]
pub struct ProductionQueueConfig {
    /// Nombre maximal de tentatives de livraison
    pub max_retry_attempts: u32,
    /// Délai initial avant retry (millisecondes)  
    pub initial_retry_delay_ms: u64,
    /// Facteur de backoff exponentiel
    pub backoff_factor: f64,
    /// Taille maximale de la queue
    pub max_queue_size: usize,
    /// TTL des messages (millisecondes)
    pub message_ttl_ms: u64,
    /// Intervalle de nettoyage (millisecondes)
    pub cleanup_interval_ms: u64,
}

impl Default for ProductionQueueConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: 3,
            initial_retry_delay_ms: 1000, // 1 seconde
            backoff_factor: 2.0,
            max_queue_size: 1000,
            message_ttl_ms: 24 * 60 * 60 * 1000, // 24 heures
            cleanup_interval_ms: 5 * 60 * 1000,  // 5 minutes
        }
    }
}

/// Message en attente avec métadonnées de retry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// ID unique du message
    pub message_id: String,
    /// ID du destinataire
    pub recipient: PeerId,
    /// Contenu chiffré du message
    pub encrypted_payload: Vec<u8>,
    /// Priorité du message (High = 0, Normal = 1, Low = 2)
    pub priority: u8,
    /// Timestamp de création
    pub created_at: u64,
    /// Timestamp du prochain essai
    pub next_retry_at: u64,
    /// Nombre de tentatives effectuées
    pub attempts: u32,
    /// Historique des erreurs
    pub error_history: Vec<String>,
}

/// Statistiques de la queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    /// Nombre de messages en attente
    pub pending_count: usize,
    /// Nombre de messages traités avec succès
    pub success_count: u64,
    /// Nombre de messages échoués définitivement
    pub failed_count: u64,
    /// Nombre total de tentatives
    pub total_attempts: u64,
    /// Latence moyenne de livraison (millisecondes)
    pub avg_delivery_latency_ms: u64,
}

/// Message queue production avec retry et persistance
pub struct ProductionMessageQueue {
    /// Configuration
    config: ProductionQueueConfig,
    /// Messages en attente
    pending_messages: Arc<RwLock<VecDeque<QueuedMessage>>>,
    /// Index par message_id pour accès rapide
    message_index: Arc<RwLock<HashMap<String, usize>>>,
    /// Statistiques
    stats: Arc<RwLock<QueueStats>>,
    /// Callback pour envoyer message
    #[allow(clippy::type_complexity)]
    send_callback: Option<Arc<dyn Fn(&QueuedMessage) -> bool + Send + Sync>>,
}

impl ProductionMessageQueue {
    /// Crée une nouvelle queue de messages
    pub fn new(config: ProductionQueueConfig) -> Self {
        Self {
            config,
            pending_messages: Arc::new(RwLock::new(VecDeque::new())),
            message_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(QueueStats {
                pending_count: 0,
                success_count: 0,
                failed_count: 0,
                total_attempts: 0,
                avg_delivery_latency_ms: 0,
            })),
            send_callback: None,
        }
    }

    /// Configure le callback d'envoi de messages
    pub fn set_send_callback<F>(&mut self, callback: F)
    where
        F: Fn(&QueuedMessage) -> bool + Send + Sync + 'static,
    {
        self.send_callback = Some(Arc::new(callback));
    }

    /// Ajoute un message à la queue
    pub async fn enqueue_message(
        &self,
        recipient: PeerId,
        encrypted_payload: Vec<u8>,
        priority: u8,
    ) -> Result<String, NetworkError> {
        let message_id = generate_message_id();
        let now = current_timestamp();

        let queued_msg = QueuedMessage {
            message_id: message_id.clone(),
            recipient,
            encrypted_payload,
            priority,
            created_at: now,
            next_retry_at: now, // Premier essai immédiat
            attempts: 0,
            error_history: Vec::new(),
        };

        let mut queue = self.pending_messages.write().await;

        // Vérifier la taille maximale
        if queue.len() >= self.config.max_queue_size {
            return Err(NetworkError::General("Queue pleine".to_string()));
        }

        // Insérer selon la priorité (tri par priorité puis par timestamp)
        let insert_pos = queue
            .iter()
            .position(|msg| {
                msg.priority > queued_msg.priority
                    || (msg.priority == queued_msg.priority
                        && msg.created_at > queued_msg.created_at)
            })
            .unwrap_or(queue.len());

        queue.insert(insert_pos, queued_msg);

        // Mettre à jour l'index
        let mut index = self.message_index.write().await;
        index.insert(message_id.clone(), insert_pos);

        // Mettre à jour les stats
        let mut stats = self.stats.write().await;
        stats.pending_count = queue.len();

        info!(
            "📥 Message {} ajouté à la queue (priorité {})",
            message_id, priority
        );
        Ok(message_id)
    }

    /// Traite les messages en attente
    pub async fn process_pending_messages(&self) -> usize {
        let now = current_timestamp();
        let mut processed = 0;

        // Collecter les indices des messages à traiter (ordre inverse pour éviter décalage)
        let mut messages_to_process: Vec<usize> = {
            let queue = self.pending_messages.read().await;
            queue
                .iter()
                .enumerate()
                .filter(|(_, msg)| msg.next_retry_at <= now)
                .map(|(idx, _)| idx)
                .collect()
        };
        messages_to_process.sort_by(|a, b| b.cmp(a)); // Ordre décroissant

        // Traiter chaque message
        for &msg_idx in &messages_to_process {
            let mut queue = self.pending_messages.write().await;

            // Vérifier que l'index est encore valide
            if msg_idx >= queue.len() {
                continue;
            }

            let mut message = queue[msg_idx].clone();
            processed += 1;

            // Tenter l'envoi
            let success = if let Some(ref callback) = self.send_callback {
                callback(&message)
            } else {
                false // Pas de callback configuré
            };

            message.attempts += 1;

            if success {
                // Succès : supprimer le message et mettre à jour les stats
                queue.remove(msg_idx);
                drop(queue);

                let mut stats = self.stats.write().await;
                stats.success_count += 1;
                stats.total_attempts += message.attempts as u64;
                stats.pending_count = stats.pending_count.saturating_sub(1);

                let delivery_time = now - message.created_at;
                if stats.avg_delivery_latency_ms == 0 {
                    stats.avg_delivery_latency_ms = delivery_time;
                } else {
                    stats.avg_delivery_latency_ms =
                        (stats.avg_delivery_latency_ms + delivery_time) / 2;
                }

                info!(
                    "✅ Message {} livré avec succès (tentative {})",
                    message.message_id, message.attempts
                );
            } else {
                // Échec : programmer retry ou abandonner
                if message.attempts >= self.config.max_retry_attempts {
                    // Abandonner définitivement
                    queue.remove(msg_idx);
                    drop(queue);

                    let mut stats = self.stats.write().await;
                    stats.failed_count += 1;
                    stats.total_attempts += message.attempts as u64;
                    stats.pending_count = stats.pending_count.saturating_sub(1);

                    warn!(
                        "❌ Message {} abandonné après {} tentatives",
                        message.message_id, message.attempts
                    );
                } else {
                    // Programmer retry
                    let delay = self.config.initial_retry_delay_ms as f64
                        * self.config.backoff_factor.powi(message.attempts as i32 - 1);

                    message.next_retry_at = now + delay as u64;
                    message
                        .error_history
                        .push(format!("Échec tentative {}", message.attempts));

                    // Mettre à jour en place
                    queue[msg_idx] = message.clone();

                    debug!(
                        "🔄 Message {} programmé pour retry dans {}ms",
                        message.message_id, delay as u64
                    );
                }
            }
        }

        processed
    }

    /// Nettoie les messages expirés
    pub async fn cleanup_expired_messages(&self) -> usize {
        let now = current_timestamp();
        let mut removed = 0;

        let mut queue = self.pending_messages.write().await;
        let mut index = self.message_index.write().await;

        // Supprimer les messages expirés
        queue.retain(|msg| {
            let expired = (now - msg.created_at) > self.config.message_ttl_ms;
            if expired {
                removed += 1;
                index.remove(&msg.message_id);
            }
            !expired
        });

        // Mettre à jour les stats
        let mut stats = self.stats.write().await;
        stats.pending_count = queue.len();
        stats.failed_count += removed as u64;

        if removed > 0 {
            info!("🗑️ {} messages expirés supprimés", removed);
        }

        removed
    }

    /// Récupère les statistiques actuelles
    pub async fn get_stats(&self) -> QueueStats {
        self.stats.read().await.clone()
    }

    /// Récupère un message par ID
    pub async fn get_message(&self, message_id: &str) -> Option<QueuedMessage> {
        let queue = self.pending_messages.read().await;
        queue
            .iter()
            .find(|msg| msg.message_id == message_id)
            .cloned()
    }

    /// Supprime un message par ID
    pub async fn remove_message(&self, message_id: &str) -> bool {
        let mut queue = self.pending_messages.write().await;
        let mut index = self.message_index.write().await;

        if let Some(pos) = queue.iter().position(|msg| msg.message_id == message_id) {
            queue.remove(pos);
            index.remove(message_id);

            let mut stats = self.stats.write().await;
            stats.pending_count = queue.len();
            return true;
        }
        false
    }
}

// Fonctions utilitaires

fn generate_message_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let random_bytes = fastrand::u32(..);
    format!("msg_{}_{:08x}", timestamp, random_bytes)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_production_queue_creation() {
        // TDD: Test création queue production
        let config = ProductionQueueConfig::default();
        let queue = ProductionMessageQueue::new(config);

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.success_count, 0);
        assert_eq!(stats.failed_count, 0);
    }

    #[tokio::test]
    async fn test_enqueue_message() {
        // TDD: Test ajout message dans queue
        let config = ProductionQueueConfig::default();
        let queue = ProductionMessageQueue::new(config);

        let recipient = PeerId::from_bytes(b"test_recipient".to_vec());
        let payload = b"test message".to_vec();

        let msg_id = queue.enqueue_message(recipient, payload, 1).await.unwrap();

        assert!(!msg_id.is_empty());
        assert!(msg_id.starts_with("msg_"));

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 1);
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        // TDD: Test ordre de priorité des messages
        let config = ProductionQueueConfig::default();
        let queue = ProductionMessageQueue::new(config);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());

        // Ajouter messages avec différentes priorités
        let _low = queue
            .enqueue_message(recipient.clone(), b"low".to_vec(), 2)
            .await
            .unwrap();
        let _high = queue
            .enqueue_message(recipient.clone(), b"high".to_vec(), 0)
            .await
            .unwrap();
        let _normal = queue
            .enqueue_message(recipient, b"normal".to_vec(), 1)
            .await
            .unwrap();

        // Vérifier l'ordre (high, normal, low)
        let queue_data = queue.pending_messages.read().await;
        assert_eq!(queue_data[0].priority, 0); // High priority first
        assert_eq!(queue_data[1].priority, 1); // Normal priority second
        assert_eq!(queue_data[2].priority, 2); // Low priority last
    }

    #[tokio::test]
    async fn test_successful_delivery() {
        // TDD: Test livraison réussie avec callback
        let config = ProductionQueueConfig::default();
        let mut queue = ProductionMessageQueue::new(config);

        // Configurer callback qui réussit toujours
        queue.set_send_callback(|_msg| true);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let msg_id = queue
            .enqueue_message(recipient, b"test".to_vec(), 1)
            .await
            .unwrap();

        // Traiter les messages
        let processed = queue.process_pending_messages().await;
        assert_eq!(processed, 1);

        // Vérifier les stats
        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.failed_count, 0);

        // Message doit être supprimé de la queue
        assert!(queue.get_message(&msg_id).await.is_none());
    }

    #[tokio::test]
    async fn test_retry_mechanism() {
        // TDD: Test mécanisme de retry avec backoff
        let config = ProductionQueueConfig {
            max_retry_attempts: 3,
            initial_retry_delay_ms: 100,
            backoff_factor: 2.0,
            ..Default::default()
        };
        let mut queue = ProductionMessageQueue::new(config);

        // Configurer callback qui échoue toujours
        queue.set_send_callback(|_msg| false);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let msg_id = queue
            .enqueue_message(recipient, b"failing_msg".to_vec(), 1)
            .await
            .unwrap();

        // Premier traitement (échec immédiat)
        let processed = queue.process_pending_messages().await;
        assert_eq!(processed, 1);

        // Message doit être encore en queue avec next_retry_at programmé
        let message = queue.get_message(&msg_id).await.unwrap();
        assert_eq!(message.attempts, 1);
        assert!(message.next_retry_at > current_timestamp());

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 1);
        assert_eq!(stats.success_count, 0);
    }

    #[tokio::test]
    async fn test_max_retries_exhausted() {
        // TDD: Test abandon après épuisement des retries
        let config = ProductionQueueConfig {
            max_retry_attempts: 2,
            initial_retry_delay_ms: 0, // Pas de délai pour test
            ..Default::default()
        };
        let mut queue = ProductionMessageQueue::new(config);

        // Configurer callback qui échoue toujours
        queue.set_send_callback(|_msg| false);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let msg_id = queue
            .enqueue_message(recipient, b"failing_msg".to_vec(), 1)
            .await
            .unwrap();

        // Premier traitement
        queue.process_pending_messages().await;
        let message = queue.get_message(&msg_id).await.unwrap();
        assert_eq!(message.attempts, 1);

        // Deuxième traitement (dernier retry)
        queue.process_pending_messages().await;

        // Message doit être supprimé définitivement
        assert!(queue.get_message(&msg_id).await.is_none());

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.failed_count, 1);
    }

    #[tokio::test]
    async fn test_queue_size_limit() {
        // TDD: Test limite de taille de queue
        let config = ProductionQueueConfig {
            max_queue_size: 2,
            ..Default::default()
        };
        let queue = ProductionMessageQueue::new(config);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());

        // Remplir la queue jusqu'à la limite
        assert!(queue
            .enqueue_message(recipient.clone(), b"msg1".to_vec(), 1)
            .await
            .is_ok());
        assert!(queue
            .enqueue_message(recipient.clone(), b"msg2".to_vec(), 1)
            .await
            .is_ok());

        // Tentative d'ajout supplémentaire doit échouer
        let result = queue.enqueue_message(recipient, b"msg3".to_vec(), 1).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Queue pleine"));
    }

    #[tokio::test]
    async fn test_cleanup_expired_messages() {
        // TDD: Test nettoyage messages expirés
        let config = ProductionQueueConfig {
            message_ttl_ms: 100, // TTL très court pour test
            ..Default::default()
        };
        let queue = ProductionMessageQueue::new(config);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let _msg_id = queue
            .enqueue_message(recipient, b"expiring_msg".to_vec(), 1)
            .await
            .unwrap();

        // Attendre l'expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        // Nettoyer
        let removed = queue.cleanup_expired_messages().await;
        assert_eq!(removed, 1);

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.failed_count, 1);
    }

    #[tokio::test]
    async fn test_message_removal() {
        // TDD: Test suppression manuelle de message
        let config = ProductionQueueConfig::default();
        let queue = ProductionMessageQueue::new(config);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let msg_id = queue
            .enqueue_message(recipient, b"removable_msg".to_vec(), 1)
            .await
            .unwrap();

        // Vérifier que le message existe
        assert!(queue.get_message(&msg_id).await.is_some());

        // Supprimer le message
        let removed = queue.remove_message(&msg_id).await;
        assert!(removed);

        // Vérifier que le message n'existe plus
        assert!(queue.get_message(&msg_id).await.is_none());

        let stats = queue.get_stats().await;
        assert_eq!(stats.pending_count, 0);
    }

    #[tokio::test]
    async fn test_backoff_calculation() {
        // TDD: Test calcul du backoff exponentiel
        let config = ProductionQueueConfig {
            initial_retry_delay_ms: 50, // Plus court pour test rapide
            backoff_factor: 2.0,
            max_retry_attempts: 4,
            ..Default::default()
        };
        let mut queue = ProductionMessageQueue::new(config.clone());

        // Configurer callback qui échoue toujours
        queue.set_send_callback(|_msg| false);

        let recipient = PeerId::from_bytes(b"recipient".to_vec());
        let msg_id = queue
            .enqueue_message(recipient, b"backoff_test".to_vec(), 1)
            .await
            .unwrap();

        let initial_time = current_timestamp();

        // Premier échec
        queue.process_pending_messages().await;
        let message = queue.get_message(&msg_id).await.unwrap();
        let first_delay = message.next_retry_at - initial_time;

        // Le délai devrait être proche de initial_retry_delay_ms
        assert!((50..=100).contains(&first_delay));

        // Simuler passage du temps et deuxième échec
        tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
        queue.process_pending_messages().await;

        let message = queue.get_message(&msg_id).await.unwrap();
        assert_eq!(message.attempts, 2);

        // Le prochain délai devrait être environ 2x le premier (backoff exponentiel)
        let second_delay_expected =
            (config.initial_retry_delay_ms as f64 * config.backoff_factor) as u64;
        let second_delay_actual = message.next_retry_at - current_timestamp();
        assert!(
            second_delay_actual >= second_delay_expected - 20
                && second_delay_actual <= second_delay_expected + 20
        );
    }
}
