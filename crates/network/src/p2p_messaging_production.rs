//! P2P Messaging Production avec encryption E2E
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture: Messaging sécurisé avec ChaCha20Poly1305

use crate::{Connection, NetworkError, PeerId};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Message P2P chiffré
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// ID unique du message
    pub id: String,
    /// Expéditeur
    pub from: PeerId,
    /// Destinataire
    pub to: PeerId,
    /// Nonce pour déchiffrement
    pub nonce: Vec<u8>,
    /// Payload chiffré
    pub ciphertext: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Signature (optionnelle)
    pub signature: Option<Vec<u8>>,
}

/// Configuration messagerie production
#[derive(Debug, Clone)]
pub struct ProductionMessagingConfig {
    /// Taille max des messages (bytes)
    pub max_message_size: usize,
    /// TTL des messages (secondes)
    pub message_ttl_secs: u64,
    /// Activer retry automatique
    pub enable_retry: bool,
    /// Nombre max de retry
    pub max_retries: u32,
}

impl Default for ProductionMessagingConfig {
    fn default() -> Self {
        Self {
            max_message_size: 65536, // 64KB
            message_ttl_secs: 3600,  // 1 heure
            enable_retry: true,
            max_retries: 3,
        }
    }
}

/// Gestionnaire de messagerie P2P production
pub struct ProductionP2pMessaging {
    /// Notre PeerId
    local_peer: PeerId,
    /// Configuration
    config: ProductionMessagingConfig,
    /// Sessions de chiffrement par pair
    encryption_sessions: Arc<RwLock<HashMap<PeerId, EncryptionSession>>>,
    /// Messages en attente de livraison
    pending_messages: Arc<RwLock<Vec<EncryptedMessage>>>,
    /// Connexions actives
    connections: Arc<RwLock<HashMap<PeerId, Connection>>>,
}

/// Session de chiffrement avec un pair
struct EncryptionSession {
    /// Clé partagée dérivée
    shared_key: [u8; 32],
    /// Cipher ChaCha20Poly1305
    cipher: ChaCha20Poly1305,
    /// Compteur de messages envoyés
    send_counter: u64,
    /// Compteur de messages reçus
    recv_counter: u64,
}

impl ProductionP2pMessaging {
    /// Crée un nouveau gestionnaire de messagerie
    pub fn new(local_peer: PeerId, config: ProductionMessagingConfig) -> Self {
        Self {
            local_peer,
            config,
            encryption_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_messages: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Établit une session de chiffrement avec un pair
    pub async fn establish_encryption_session(
        &self,
        peer_id: &PeerId,
        shared_secret: &[u8],
    ) -> Result<(), NetworkError> {
        if shared_secret.len() < 32 {
            return Err(NetworkError::General(
                "Secret partagé trop court".to_string(),
            ));
        }

        // Dériver la clé de chiffrement du secret partagé
        let mut shared_key = [0u8; 32];
        shared_key.copy_from_slice(&shared_secret[..32]);

        let cipher = ChaCha20Poly1305::new_from_slice(&shared_key)
            .map_err(|e| NetworkError::General(format!("Erreur création cipher: {}", e)))?;

        let session = EncryptionSession {
            shared_key,
            cipher,
            send_counter: 0,
            recv_counter: 0,
        };

        let mut sessions = self.encryption_sessions.write().await;
        sessions.insert(peer_id.clone(), session);

        info!(
            "🔐 Session de chiffrement établie avec {}",
            peer_id.to_hex()
        );
        Ok(())
    }

    /// Envoie un message chiffré à un pair
    pub async fn send_encrypted_message(
        &self,
        to: &PeerId,
        plaintext: &[u8],
    ) -> Result<String, NetworkError> {
        // Vérifier taille
        if plaintext.len() > self.config.max_message_size {
            return Err(NetworkError::General(format!(
                "Message trop grand: {} bytes",
                plaintext.len()
            )));
        }

        // Obtenir session de chiffrement
        let mut sessions = self.encryption_sessions.write().await;
        let session = sessions
            .get_mut(to)
            .ok_or_else(|| NetworkError::General(format!("Pas de session avec {}", to.to_hex())))?;

        // Générer nonce unique
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Chiffrer le message
        let ciphertext = session
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| NetworkError::General(format!("Erreur chiffrement: {}", e)))?;

        // Créer message chiffré
        let message_id = format!("msg-{}-{}", session.send_counter, to.to_hex());
        let encrypted_msg = EncryptedMessage {
            id: message_id.clone(),
            from: self.local_peer.clone(),
            to: to.clone(),
            nonce: nonce.to_vec(),
            ciphertext,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: None, // TODO: Ajouter signature Ed25519
        };

        session.send_counter += 1;

        // Envoyer via connexion si disponible
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(to) {
            let serialized = bincode::serialize(&encrypted_msg)
                .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

            connection.send_message(&serialized).await?;
            info!(
                "📤 Message chiffré envoyé à {}: {} bytes",
                to.to_hex(),
                serialized.len()
            );
        } else {
            // Mettre en attente si pas de connexion
            let mut pending = self.pending_messages.write().await;
            pending.push(encrypted_msg);
            debug!("⏳ Message mis en attente pour {}", to.to_hex());
        }

        Ok(message_id)
    }

    /// Reçoit et déchiffre un message
    pub async fn receive_encrypted_message(
        &self,
        encrypted_msg: &EncryptedMessage,
    ) -> Result<Vec<u8>, NetworkError> {
        // Vérifier qu'on est bien le destinataire
        if encrypted_msg.to != self.local_peer {
            return Err(NetworkError::General(
                "Message pas destiné à nous".to_string(),
            ));
        }

        // Obtenir session de chiffrement
        let mut sessions = self.encryption_sessions.write().await;
        let session = sessions.get_mut(&encrypted_msg.from).ok_or_else(|| {
            NetworkError::General(format!(
                "Pas de session avec {}",
                encrypted_msg.from.to_hex()
            ))
        })?;

        // Reconstituer le nonce
        let nonce = Nonce::from_slice(&encrypted_msg.nonce);

        // Déchiffrer
        let plaintext = session
            .cipher
            .decrypt(nonce, encrypted_msg.ciphertext.as_ref())
            .map_err(|e| NetworkError::General(format!("Erreur déchiffrement: {}", e)))?;

        session.recv_counter += 1;

        info!(
            "📥 Message déchiffré de {}: {} bytes",
            encrypted_msg.from.to_hex(),
            plaintext.len()
        );

        Ok(plaintext)
    }

    /// Ajoute une connexion active
    pub async fn add_connection(&self, peer_id: PeerId, connection: Connection) {
        let mut connections = self.connections.write().await;
        connections.insert(peer_id.clone(), connection);

        // Envoyer messages en attente pour ce pair
        let mut pending = self.pending_messages.write().await;
        let mut to_send = Vec::new();

        pending.retain(|msg| {
            if msg.to == peer_id {
                to_send.push(msg.clone());
                false
            } else {
                true
            }
        });

        drop(pending);

        for msg in to_send {
            if let Ok(serialized) = bincode::serialize(&msg) {
                let connections = self.connections.read().await;
                if let Some(conn) = connections.get(&peer_id) {
                    let _ = conn.send_message(&serialized).await;
                    debug!("📤 Message en attente envoyé à {}", peer_id.to_hex());
                }
            }
        }
    }

    /// Traite les messages en attente avec retry
    pub async fn process_pending_messages(&self) -> Result<usize, NetworkError> {
        if !self.config.enable_retry {
            return Ok(0);
        }

        let pending = self.pending_messages.read().await;
        let count = pending.len();

        if count > 0 {
            info!("⏳ {} messages en attente de livraison", count);
        }

        // TODO: Implémenter logique de retry avec backoff exponentiel

        Ok(count)
    }

    /// Nettoie les messages expirés
    pub async fn cleanup_expired_messages(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut pending = self.pending_messages.write().await;
        let before = pending.len();

        pending.retain(|msg| {
            let age = now - msg.timestamp;
            age < self.config.message_ttl_secs
        });

        let removed = before - pending.len();
        if removed > 0 {
            debug!("🗑️ {} messages expirés supprimés", removed);
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_production_messaging_creation() {
        // TDD: Test création gestionnaire messagerie
        let peer_id = PeerId::from_bytes(b"test-messaging-peer".to_vec());
        let config = ProductionMessagingConfig::default();

        let messaging = ProductionP2pMessaging::new(peer_id.clone(), config);
        assert_eq!(messaging.local_peer, peer_id);
    }

    #[tokio::test]
    async fn test_establish_encryption_session() {
        // TDD: Test établissement session chiffrement
        let peer_id = PeerId::from_bytes(b"local-peer".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote-peer".to_vec());
        let config = ProductionMessagingConfig::default();

        let messaging = ProductionP2pMessaging::new(peer_id, config);

        // Secret partagé de test (normalement dérivé via ECDH)
        let shared_secret = [42u8; 32];

        let result = messaging
            .establish_encryption_session(&remote_peer, &shared_secret)
            .await;

        assert!(result.is_ok());

        // Vérifier que session existe
        let sessions = messaging.encryption_sessions.read().await;
        assert!(sessions.contains_key(&remote_peer));
    }

    #[tokio::test]
    async fn test_send_receive_encrypted_message() {
        // TDD: Test envoi/réception message chiffré
        let alice = PeerId::from_bytes(b"alice".to_vec());
        let bob = PeerId::from_bytes(b"bob".to_vec());

        let alice_messaging =
            ProductionP2pMessaging::new(alice.clone(), ProductionMessagingConfig::default());
        let bob_messaging =
            ProductionP2pMessaging::new(bob.clone(), ProductionMessagingConfig::default());

        // Établir sessions avec même secret partagé
        let shared_secret = [99u8; 32];
        alice_messaging
            .establish_encryption_session(&bob, &shared_secret)
            .await
            .unwrap();
        bob_messaging
            .establish_encryption_session(&alice, &shared_secret)
            .await
            .unwrap();

        // Alice envoie message (sera mis en attente car pas de connexion)
        let plaintext = b"Hello Bob, this is encrypted!";
        let msg_id = alice_messaging
            .send_encrypted_message(&bob, plaintext)
            .await
            .unwrap();

        assert!(!msg_id.is_empty());

        // Récupérer message depuis pending
        let pending = alice_messaging.pending_messages.read().await;
        assert_eq!(pending.len(), 1);
        let encrypted_msg = pending[0].clone();
        drop(pending);

        // Bob déchiffre le message
        let decrypted = bob_messaging
            .receive_encrypted_message(&encrypted_msg)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_message_too_large() {
        // TDD: Test rejet message trop grand
        let peer_id = PeerId::from_bytes(b"sender".to_vec());
        let remote = PeerId::from_bytes(b"receiver".to_vec());

        let config = ProductionMessagingConfig {
            max_message_size: 100, // Limite très basse
            ..Default::default()
        };

        let messaging = ProductionP2pMessaging::new(peer_id, config);

        let shared_secret = [88u8; 32];
        messaging
            .establish_encryption_session(&remote, &shared_secret)
            .await
            .unwrap();

        // Message trop grand
        let large_message = vec![0u8; 200];
        let result = messaging
            .send_encrypted_message(&remote, &large_message)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trop grand"));
    }

    #[tokio::test]
    async fn test_cleanup_expired_messages() {
        // TDD: Test nettoyage messages expirés
        let peer_id = PeerId::from_bytes(b"cleaner".to_vec());
        let config = ProductionMessagingConfig {
            message_ttl_secs: 0, // Expire immédiatement
            ..Default::default()
        };

        let messaging = ProductionP2pMessaging::new(peer_id.clone(), config);

        // Ajouter message déjà expiré
        let old_msg = EncryptedMessage {
            id: "old-msg".to_string(),
            from: peer_id.clone(),
            to: PeerId::from_bytes(b"dest".to_vec()),
            nonce: vec![0; 12],
            ciphertext: vec![],
            timestamp: 0, // Très vieux
            signature: None,
        };

        {
            let mut pending = messaging.pending_messages.write().await;
            pending.push(old_msg);
        }

        // Nettoyer
        let removed = messaging.cleanup_expired_messages().await;
        assert_eq!(removed, 1);

        let pending = messaging.pending_messages.read().await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_add_connection_sends_pending() {
        // TDD: Test que l'ajout de connexion envoie messages en attente
        let alice = PeerId::from_bytes(b"alice2".to_vec());
        let bob = PeerId::from_bytes(b"bob2".to_vec());

        let messaging =
            ProductionP2pMessaging::new(alice.clone(), ProductionMessagingConfig::default());

        // Établir session
        let shared_secret = [77u8; 32];
        messaging
            .establish_encryption_session(&bob, &shared_secret)
            .await
            .unwrap();

        // Envoyer message (sera mis en attente)
        let plaintext = b"Pending message";
        messaging
            .send_encrypted_message(&bob, plaintext)
            .await
            .unwrap();

        // Vérifier message en attente
        {
            let pending = messaging.pending_messages.read().await;
            assert_eq!(pending.len(), 1);
        }

        // Ajouter connexion
        let connection = Connection::new(Some(bob.clone()));
        connection.set_state(crate::connection::ConnectionState::Connected);
        messaging.add_connection(bob.clone(), connection).await;

        // Message devrait être envoyé et retiré de pending
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let pending = messaging.pending_messages.read().await;
        assert_eq!(pending.len(), 0, "Message devrait être retiré après envoi");
    }

    #[tokio::test]
    async fn test_no_encryption_session_error() {
        // TDD: Test erreur si pas de session de chiffrement
        let peer_id = PeerId::from_bytes(b"no-session".to_vec());
        let remote = PeerId::from_bytes(b"unknown".to_vec());

        let messaging = ProductionP2pMessaging::new(peer_id, ProductionMessagingConfig::default());

        // Essayer d'envoyer sans session
        let result = messaging.send_encrypted_message(&remote, b"test").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Pas de session"));
    }

    #[tokio::test]
    async fn test_wrong_recipient_error() {
        // TDD: Test rejet message pas pour nous
        let alice = PeerId::from_bytes(b"alice3".to_vec());
        let bob = PeerId::from_bytes(b"bob3".to_vec());
        let charlie = PeerId::from_bytes(b"charlie3".to_vec());

        let bob_messaging =
            ProductionP2pMessaging::new(bob.clone(), ProductionMessagingConfig::default());

        // Message destiné à Charlie, pas Bob
        let msg = EncryptedMessage {
            id: "wrong-dest".to_string(),
            from: alice,
            to: charlie,
            nonce: vec![0; 12],
            ciphertext: vec![],
            timestamp: 0,
            signature: None,
        };

        let result = bob_messaging.receive_encrypted_message(&msg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pas destiné"));
    }
}
