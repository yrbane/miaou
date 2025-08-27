//! Production Message Queue with persistent storage and delivery guarantees
//!
//! TDD GREEN: Real implementation for production messaging
//! SOLID Architecture: Each component has single responsibility

use crate::{NetworkError, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Message with metadata for queue management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique message ID
    pub id: MessageId,
    /// Sender peer ID
    pub from: PeerId,
    /// Recipient peer ID
    pub to: PeerId,
    /// Message content (encrypted)
    pub content: Vec<u8>,
    /// Creation timestamp
    pub timestamp: u64,
    /// Delivery attempts
    pub attempts: u32,
    /// Message priority
    pub priority: MessagePriority,
}

/// Message ID for tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Generate new unique message ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Production Message Queue - SOLID Single Responsibility
pub struct MessageQueue {
    /// Outbound message queue (to be sent)
    outbound: Arc<Mutex<VecDeque<QueuedMessage>>>,
    /// Inbound message queue (received)
    inbound: Arc<Mutex<VecDeque<QueuedMessage>>>,
    /// Message store for persistence
    store: Arc<dyn MessageStore>,
    /// Queue statistics
    stats: Arc<RwLock<QueueStats>>,
}

impl MessageQueue {
    /// Create new message queue with store (SOLID DIP - Dependency Injection)
    pub fn new(store: Arc<dyn MessageStore>) -> Self {
        Self {
            outbound: Arc::new(Mutex::new(VecDeque::new())),
            inbound: Arc::new(Mutex::new(VecDeque::new())),
            store,
            stats: Arc::new(RwLock::new(QueueStats::default())),
        }
    }

    /// Send message (add to outbound queue)
    pub async fn send_message(
        &self,
        to: PeerId,
        content: Vec<u8>,
        priority: MessagePriority,
    ) -> Result<MessageId, NetworkError> {
        let message = QueuedMessage {
            id: MessageId::generate(),
            from: self.get_local_peer_id().await?,
            to,
            content,
            timestamp: get_timestamp(),
            attempts: 0,
            priority,
        };

        // Add to outbound queue
        {
            let mut outbound = self.outbound.lock().await;
            outbound.push_back(message.clone());
            // Sort by priority (highest first)
            let mut messages: Vec<_> = outbound.drain(..).collect();
            messages.sort_by_key(|m| std::cmp::Reverse(m.priority));
            *outbound = messages.into();
        }

        // Persist to store
        self.store.store_message(&message).await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.messages_queued += 1;
        }

        Ok(message.id)
    }

    /// Receive message (get from inbound queue)
    pub async fn receive_message(&self) -> Result<Option<QueuedMessage>, NetworkError> {
        let mut inbound = self.inbound.lock().await;
        let message = inbound.pop_front();

        if message.is_some() {
            let mut stats = self.stats.write().await;
            stats.messages_received += 1;
        }

        Ok(message)
    }

    /// Get next outbound message for delivery
    pub async fn get_next_outbound(&self) -> Result<Option<QueuedMessage>, NetworkError> {
        let mut outbound = self.outbound.lock().await;
        outbound.pop_front().map_or(Ok(None), |mut msg| {
            msg.attempts += 1;
            Ok(Some(msg))
        })
    }

    /// Mark message as delivered (remove from store)
    pub async fn mark_delivered(&self, message_id: &MessageId) -> Result<(), NetworkError> {
        self.store.remove_message(message_id).await?;
        
        let mut stats = self.stats.write().await;
        stats.messages_delivered += 1;
        
        Ok(())
    }

    /// Requeue message for retry (after failed delivery)
    pub async fn requeue_message(&self, message: QueuedMessage) -> Result<(), NetworkError> {
        const MAX_ATTEMPTS: u32 = 3;
        
        if message.attempts >= MAX_ATTEMPTS {
            // Move to dead letter queue
            self.store.store_failed_message(&message).await?;
            return Ok(());
        }

        // Add back to outbound with delay
        {
            let mut outbound = self.outbound.lock().await;
            outbound.push_back(message.clone());
        }

        // Update in store
        self.store.store_message(&message).await?;

        Ok(())
    }

    /// Add incoming message to inbound queue
    pub async fn add_incoming(&self, message: QueuedMessage) -> Result<(), NetworkError> {
        // Check for duplicates
        if self.store.message_exists(&message.id).await? {
            return Ok(()); // Duplicate, ignore
        }

        // Add to inbound queue
        {
            let mut inbound = self.inbound.lock().await;
            inbound.push_back(message.clone());
        }

        // Persist to store
        self.store.store_message(&message).await?;

        Ok(())
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> QueueStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Load persisted messages on startup
    pub async fn load_persisted_messages(&self) -> Result<(), NetworkError> {
        let messages = self.store.load_all_messages().await?;
        
        let mut outbound = self.outbound.lock().await;
        let mut inbound = self.inbound.lock().await;

        for message in messages {
            if message.from == self.get_local_peer_id().await? {
                // Outbound message
                outbound.push_back(message);
            } else {
                // Inbound message
                inbound.push_back(message);
            }
        }

        Ok(())
    }

    /// Get local peer ID (would be injected in real implementation)
    async fn get_local_peer_id(&self) -> Result<PeerId, NetworkError> {
        // TODO: Inject this via dependency injection
        Ok(PeerId::from_bytes(b"local-peer".to_vec()))
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    pub messages_queued: u64,
    pub messages_received: u64,
    pub messages_delivered: u64,
    pub messages_failed: u64,
}

/// Message Store abstraction (SOLID DIP)
#[async_trait::async_trait]
pub trait MessageStore: Send + Sync {
    /// Store message persistently
    async fn store_message(&self, message: &QueuedMessage) -> Result<(), NetworkError>;
    
    /// Remove message from store
    async fn remove_message(&self, id: &MessageId) -> Result<(), NetworkError>;
    
    /// Check if message exists
    async fn message_exists(&self, id: &MessageId) -> Result<bool, NetworkError>;
    
    /// Load all persisted messages
    async fn load_all_messages(&self) -> Result<Vec<QueuedMessage>, NetworkError>;
    
    /// Store failed message (dead letter queue)
    async fn store_failed_message(&self, message: &QueuedMessage) -> Result<(), NetworkError>;
}

/// File-based message store implementation
pub struct FileMessageStore {
    storage_dir: PathBuf,
    messages: Arc<RwLock<HashMap<MessageId, QueuedMessage>>>,
}

impl FileMessageStore {
    /// Create new file-based store
    pub async fn new(storage_dir: PathBuf) -> Result<Self, NetworkError> {
        // Ensure directory exists
        fs::create_dir_all(&storage_dir).await
            .map_err(|e| NetworkError::StorageError(format!("Failed to create storage dir: {}", e)))?;

        let store = Self {
            storage_dir,
            messages: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing messages
        store.load_from_disk().await?;

        Ok(store)
    }

    /// Load messages from disk
    async fn load_from_disk(&self) -> Result<(), NetworkError> {
        let messages_file = self.storage_dir.join("messages.json");
        
        if !messages_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&messages_file).await
            .map_err(|e| NetworkError::StorageError(format!("Failed to read messages: {}", e)))?;

        let messages: HashMap<MessageId, QueuedMessage> = serde_json::from_str(&content)
            .map_err(|e| NetworkError::StorageError(format!("Failed to parse messages: {}", e)))?;

        let mut store_messages = self.messages.write().await;
        *store_messages = messages;

        Ok(())
    }

    /// Save messages to disk
    async fn save_to_disk(&self) -> Result<(), NetworkError> {
        let messages = self.messages.read().await;
        let messages_file = self.storage_dir.join("messages.json");

        let content = serde_json::to_string_pretty(&*messages)
            .map_err(|e| NetworkError::StorageError(format!("Failed to serialize messages: {}", e)))?;

        fs::write(&messages_file, content).await
            .map_err(|e| NetworkError::StorageError(format!("Failed to write messages: {}", e)))?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MessageStore for FileMessageStore {
    async fn store_message(&self, message: &QueuedMessage) -> Result<(), NetworkError> {
        {
            let mut messages = self.messages.write().await;
            messages.insert(message.id.clone(), message.clone());
        }
        
        self.save_to_disk().await
    }

    async fn remove_message(&self, id: &MessageId) -> Result<(), NetworkError> {
        {
            let mut messages = self.messages.write().await;
            messages.remove(id);
        }
        
        self.save_to_disk().await
    }

    async fn message_exists(&self, id: &MessageId) -> Result<bool, NetworkError> {
        let messages = self.messages.read().await;
        Ok(messages.contains_key(id))
    }

    async fn load_all_messages(&self) -> Result<Vec<QueuedMessage>, NetworkError> {
        let messages = self.messages.read().await;
        Ok(messages.values().cloned().collect())
    }

    async fn store_failed_message(&self, message: &QueuedMessage) -> Result<(), NetworkError> {
        let failed_file = self.storage_dir.join("failed_messages.json");
        
        let mut failed_messages: Vec<QueuedMessage> = if failed_file.exists() {
            let content = fs::read_to_string(&failed_file).await
                .map_err(|e| NetworkError::StorageError(format!("Failed to read failed messages: {}", e)))?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };

        failed_messages.push(message.clone());

        let content = serde_json::to_string_pretty(&failed_messages)
            .map_err(|e| NetworkError::StorageError(format!("Failed to serialize failed messages: {}", e)))?;

        fs::write(&failed_file, content).await
            .map_err(|e| NetworkError::StorageError(format!("Failed to write failed messages: {}", e)))?;

        Ok(())
    }
}

/// Get current timestamp in seconds
fn get_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mock message store for testing
    pub struct MockMessageStore {
        messages: Arc<RwLock<HashMap<MessageId, QueuedMessage>>>,
        failed_messages: Arc<RwLock<Vec<QueuedMessage>>>,
    }

    impl MockMessageStore {
        pub fn new() -> Self {
            Self {
                messages: Arc::new(RwLock::new(HashMap::new())),
                failed_messages: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl MessageStore for MockMessageStore {
        async fn store_message(&self, message: &QueuedMessage) -> Result<(), NetworkError> {
            let mut messages = self.messages.write().await;
            messages.insert(message.id.clone(), message.clone());
            Ok(())
        }

        async fn remove_message(&self, id: &MessageId) -> Result<(), NetworkError> {
            let mut messages = self.messages.write().await;
            messages.remove(id);
            Ok(())
        }

        async fn message_exists(&self, id: &MessageId) -> Result<bool, NetworkError> {
            let messages = self.messages.read().await;
            Ok(messages.contains_key(id))
        }

        async fn load_all_messages(&self) -> Result<Vec<QueuedMessage>, NetworkError> {
            let messages = self.messages.read().await;
            Ok(messages.values().cloned().collect())
        }

        async fn store_failed_message(&self, message: &QueuedMessage) -> Result<(), NetworkError> {
            let mut failed = self.failed_messages.write().await;
            failed.push(message.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_message_queue_send_receive() {
        let store = Arc::new(MockMessageStore::new());
        let queue = MessageQueue::new(store);

        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());
        let content = b"Hello, World!".to_vec();

        // Send message
        let message_id = queue.send_message(peer_id.clone(), content.clone(), MessagePriority::Normal).await.unwrap();

        // Verify message in outbound queue
        let outbound = queue.get_next_outbound().await.unwrap();
        assert!(outbound.is_some());
        let message = outbound.unwrap();
        assert_eq!(message.to, peer_id);
        assert_eq!(message.content, content);
        assert_eq!(message.priority, MessagePriority::Normal);
    }

    #[tokio::test]
    async fn test_message_priority_ordering() {
        let store = Arc::new(MockMessageStore::new());
        let queue = MessageQueue::new(store);

        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());

        // Send messages with different priorities
        queue.send_message(peer_id.clone(), b"Low".to_vec(), MessagePriority::Low).await.unwrap();
        queue.send_message(peer_id.clone(), b"Critical".to_vec(), MessagePriority::Critical).await.unwrap();
        queue.send_message(peer_id.clone(), b"Normal".to_vec(), MessagePriority::Normal).await.unwrap();

        // Should get Critical first
        let message1 = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message1.content, b"Critical");
        assert_eq!(message1.priority, MessagePriority::Critical);

        // Then Normal
        let message2 = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message2.content, b"Normal");
        assert_eq!(message2.priority, MessagePriority::Normal);

        // Then Low
        let message3 = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message3.content, b"Low");
        assert_eq!(message3.priority, MessagePriority::Low);
    }

    #[tokio::test]
    async fn test_message_delivery_tracking() {
        let store = Arc::new(MockMessageStore::new());
        let queue = MessageQueue::new(store.clone());

        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());
        let content = b"Test message".to_vec();

        // Send message
        let message_id = queue.send_message(peer_id, content, MessagePriority::Normal).await.unwrap();

        // Verify message is stored
        assert!(store.message_exists(&message_id).await.unwrap());

        // Mark as delivered
        queue.mark_delivered(&message_id).await.unwrap();

        // Verify message is removed from store
        assert!(!store.message_exists(&message_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_message_retry_mechanism() {
        let store = Arc::new(MockMessageStore::new());
        let queue = MessageQueue::new(store.clone());

        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());
        let content = b"Retry test".to_vec();

        // Send message
        queue.send_message(peer_id.clone(), content, MessagePriority::Normal).await.unwrap();

        // Get message for delivery
        let mut message = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message.attempts, 1);

        // Simulate failed delivery and requeue
        queue.requeue_message(message.clone()).await.unwrap();

        // Get message again
        message = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message.attempts, 2);

        // After 3 attempts, should go to dead letter queue
        queue.requeue_message(message.clone()).await.unwrap();
        message = queue.get_next_outbound().await.unwrap().unwrap();
        assert_eq!(message.attempts, 3);

        // This should move to dead letter queue
        queue.requeue_message(message).await.unwrap();

        // No more messages in queue
        let next = queue.get_next_outbound().await.unwrap();
        assert!(next.is_none());
    }
}