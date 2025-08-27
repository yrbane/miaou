//! Types d'erreur pour le module réseau

use miaou_core::MiaouError;
use thiserror::Error;

/// Erreurs possibles dans les opérations réseau
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Erreur de connexion
    #[error("Échec de connexion : {0}")]
    ConnectionFailed(String),

    /// Pair non trouvé
    #[error("Pair non trouvé : {0}")]
    PeerNotFound(String),

    /// Erreur de handshake
    #[error("Échec du handshake : {0}")]
    HandshakeFailed(String),

    /// Timeout
    #[error("Timeout après {0} secondes")]
    Timeout(u64),

    /// Erreur de transport
    #[error("Erreur de transport : {0}")]
    TransportError(String),

    /// Erreur de découverte
    #[error("Erreur de découverte : {0}")]
    DiscoveryError(String),

    /// Erreur de sérialisation
    #[error("Erreur de sérialisation : {0}")]
    SerializationError(String),

    /// Erreur générale
    #[error("Erreur réseau : {0}")]
    General(String),
}

impl From<NetworkError> for MiaouError {
    fn from(err: NetworkError) -> Self {
        MiaouError::Network(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_error_display() {
        let err = NetworkError::ConnectionFailed("hôte inaccessible".to_string());
        assert_eq!(err.to_string(), "Échec de connexion : hôte inaccessible");
    }

    #[test]
    fn test_network_error_to_miaou_error() {
        let err = NetworkError::PeerNotFound("12345".to_string());
        let miaou_err: MiaouError = err.into();
        assert!(miaou_err.to_string().contains("Pair non trouvé"));
    }
}
