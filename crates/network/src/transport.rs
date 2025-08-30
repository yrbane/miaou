//! Module de transport abstrait pour connexions P2P
//!
//! Principe SOLID : Interface Segregation & Dependency Inversion
//! Les implémentations concrètes (WebRTC, TLS) dépendent de cette abstraction

use crate::{Connection, NetworkError, PeerInfo};
use async_trait::async_trait;
use std::time::Duration;

/// Configuration générique pour les transports
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Timeout pour établir une connexion
    pub connection_timeout: Duration,
    /// Nombre maximum de tentatives
    pub max_retries: u32,
    /// Taille maximale des messages
    pub max_message_size: usize,
    /// Activer le keep-alive
    pub enable_keep_alive: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            max_retries: 3,
            max_message_size: 1024 * 1024, // 1 MB
            enable_keep_alive: true,
        }
    }
}

/// Trait principal pour les implémentations de transport
///
/// # Principe SOLID : Open/Closed
/// Nouvelles implémentations peuvent être ajoutées sans modifier ce trait
#[async_trait]
pub trait Transport: Send + Sync {
    /// Établit une connexion vers un pair
    ///
    /// # Errors
    /// Retourne une erreur si la connexion échoue
    async fn connect(&self, peer: &PeerInfo) -> Result<Connection, NetworkError>;

    /// Accepte une connexion entrante
    ///
    /// # Errors
    /// Retourne une erreur si aucune connexion n'est disponible
    async fn accept(&self) -> Result<Connection, NetworkError>;

    /// Ferme le transport et libère les ressources
    ///
    /// # Errors
    /// Retourne une erreur si la fermeture échoue
    async fn close(&self) -> Result<(), NetworkError>;

    /// Retourne la configuration du transport
    fn config(&self) -> &TransportConfig;

    /// Vérifie si le transport est actif
    fn is_active(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio;

    // Mock implementation pour les tests (TDD)
    struct MockTransport {
        config: TransportConfig,
        active: Arc<Mutex<bool>>,
        #[allow(dead_code)]
        connections: Arc<Mutex<Vec<Connection>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                config: TransportConfig::default(),
                active: Arc::new(Mutex::new(true)),
                connections: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn connect(&self, _peer: &PeerInfo) -> Result<Connection, NetworkError> {
            if !self.is_active() {
                return Err(NetworkError::TransportError(
                    "Transport inactif".to_string(),
                ));
            }

            // Simuler une connexion réussie
            Ok(Connection::new_mock())
        }

        async fn accept(&self) -> Result<Connection, NetworkError> {
            if !self.is_active() {
                return Err(NetworkError::TransportError(
                    "Transport inactif".to_string(),
                ));
            }

            // Simuler l'acceptation d'une connexion
            Ok(Connection::new_mock())
        }

        async fn close(&self) -> Result<(), NetworkError> {
            let mut active = self.active.lock().unwrap();
            *active = false;
            Ok(())
        }

        fn config(&self) -> &TransportConfig {
            &self.config
        }

        fn is_active(&self) -> bool {
            *self.active.lock().unwrap()
        }
    }

    #[tokio::test]
    async fn test_transport_connect_success() {
        let transport = MockTransport::new();
        let peer = PeerInfo::new_mock();

        let result = transport.connect(&peer).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transport_accept_success() {
        let transport = MockTransport::new();

        let result = transport.accept().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_transport_close() {
        let transport = MockTransport::new();
        assert!(transport.is_active());

        let result = transport.close().await;
        assert!(result.is_ok());
        assert!(!transport.is_active());
    }

    #[tokio::test]
    async fn test_transport_connect_when_closed() {
        let transport = MockTransport::new();
        transport.close().await.unwrap();

        let peer = PeerInfo::new_mock();
        let result = transport.connect(&peer).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(config.enable_keep_alive);
    }
}
