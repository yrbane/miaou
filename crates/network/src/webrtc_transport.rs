//! WebRTC Transport pour connexions P2P
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Implémentation concrète du trait Transport

use crate::{Connection, NetworkError, PeerInfo, Transport, TransportConfig};
use async_trait::async_trait;

/// WebRTC Transport pour connexions P2P desktop
pub struct WebRtcTransport {
    config: TransportConfig,
    active: bool,
}

impl WebRtcTransport {
    /// Crée un nouveau transport WebRTC
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            active: false,
        }
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    async fn connect(&self, _peer: &PeerInfo) -> Result<Connection, NetworkError> {
        // TDD: Implémentation après tests
        Err(NetworkError::TransportError("Non implémenté".to_string()))
    }

    async fn accept(&self) -> Result<Connection, NetworkError> {
        // TDD: Implémentation après tests
        Err(NetworkError::TransportError("Non implémenté".to_string()))
    }

    async fn close(&self) -> Result<(), NetworkError> {
        // TDD: Implémentation après tests
        Ok(())
    }

    fn config(&self) -> &TransportConfig {
        &self.config
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio;

    fn create_test_config() -> TransportConfig {
        TransportConfig {
            connection_timeout: Duration::from_secs(5),
            max_retries: 2,
            max_message_size: 1024,
            enable_keep_alive: true,
        }
    }

    #[test]
    fn test_webrtc_transport_creation() {
        // TDD: Test création transport WebRTC
        let config = create_test_config();
        let transport = WebRtcTransport::new(config.clone());

        assert_eq!(
            transport.config().connection_timeout,
            config.connection_timeout
        );
        assert_eq!(transport.config().max_retries, config.max_retries);
        assert!(!transport.is_active());
    }

    #[test]
    fn test_webrtc_transport_config() {
        // TDD: Test accès configuration
        let config = create_test_config();
        let transport = WebRtcTransport::new(config);

        let retrieved_config = transport.config();
        assert_eq!(retrieved_config.max_message_size, 1024);
        assert!(retrieved_config.enable_keep_alive);
    }

    #[tokio::test]
    async fn test_webrtc_transport_connect_not_implemented() {
        // TDD: Test que connect retourne erreur "non implémenté" pour l'instant
        let config = create_test_config();
        let transport = WebRtcTransport::new(config);
        let peer = PeerInfo::new_mock();

        let result = transport.connect(&peer).await;
        assert!(result.is_err());

        if let Err(NetworkError::TransportError(msg)) = result {
            assert_eq!(msg, "Non implémenté");
        } else {
            panic!("Expected TransportError");
        }
    }

    #[tokio::test]
    async fn test_webrtc_transport_accept_not_implemented() {
        // TDD: Test que accept retourne erreur "non implémenté" pour l'instant
        let config = create_test_config();
        let transport = WebRtcTransport::new(config);

        let result = transport.accept().await;
        assert!(result.is_err());

        if let Err(NetworkError::TransportError(msg)) = result {
            assert_eq!(msg, "Non implémenté");
        } else {
            panic!("Expected TransportError");
        }
    }

    #[tokio::test]
    async fn test_webrtc_transport_close_succeeds() {
        // TDD: Test que close réussit (implémentation basique)
        let config = create_test_config();
        let transport = WebRtcTransport::new(config);

        let result = transport.close().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_webrtc_transport_is_active_default_false() {
        // TDD: Test que le transport commence inactif
        let config = create_test_config();
        let transport = WebRtcTransport::new(config);

        assert!(!transport.is_active());
    }

    // TDD: Tests d'intégration avec le trait Transport
    #[tokio::test]
    async fn test_webrtc_transport_trait_compatibility() {
        // TDD: Test que WebRtcTransport implémente correctement Transport
        let config = create_test_config();
        let transport: Box<dyn Transport> = Box::new(WebRtcTransport::new(config));

        // Test trait methods compilation
        assert!(!transport.is_active());
        assert!(transport.config().enable_keep_alive);

        // Test async methods compilation
        let peer = PeerInfo::new_mock();
        let connect_result = transport.connect(&peer).await;
        assert!(connect_result.is_err());

        let accept_result = transport.accept().await;
        assert!(accept_result.is_err());

        let close_result = transport.close().await;
        assert!(close_result.is_ok());
    }
}
