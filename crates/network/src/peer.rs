//! Gestion des identités et informations de pairs
//!
//! Principe SOLID : Single Responsibility
//! Ce module ne gère QUE les identités et métadonnées des pairs

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;

/// Identifiant unique d'un pair dans le réseau
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(Vec<u8>);

impl PeerId {
    /// Crée un nouvel identifiant de pair à partir de bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Retourne les bytes de l'identifiant
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Retourne une version courte pour affichage
    pub fn short(&self) -> String {
        if self.0.len() >= 8 {
            format!(
                "{}...{}",
                hex::encode(&self.0[..4]),
                hex::encode(&self.0[self.0.len() - 4..])
            )
        } else {
            hex::encode(&self.0)
        }
    }

    #[cfg(test)]
    pub(crate) fn new_mock() -> Self {
        Self(vec![1, 2, 3, 4, 5, 6, 7, 8])
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Informations complètes sur un pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Identifiant unique du pair
    pub id: PeerId,
    /// Clé publique du pair
    pub public_key: Option<Vec<u8>>,
    /// Adresses connues du pair
    pub addresses: Vec<SocketAddr>,
    /// Protocoles supportés
    pub protocols: Vec<String>,
    /// Métadonnées additionnelles
    pub metadata: PeerMetadata,
}

/// Métadonnées d'un pair
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerMetadata {
    /// Version du protocole Miaou
    pub protocol_version: String,
    /// Nom d'affichage (optionnel)
    pub display_name: Option<String>,
    /// Capacités du pair
    pub capabilities: Vec<String>,
    /// Score de réputation (0-100)
    pub reputation: u8,
}

impl PeerInfo {
    /// Crée une nouvelle info de pair
    pub fn new(id: PeerId) -> Self {
        Self {
            id,
            public_key: None,
            addresses: Vec::new(),
            protocols: vec!["miaou/0.2.0".to_string()],
            metadata: PeerMetadata::default(),
        }
    }

    /// Ajoute une adresse au pair
    pub fn add_address(&mut self, addr: SocketAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Vérifie si le pair supporte un protocole
    pub fn supports_protocol(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }

    #[cfg(test)]
    pub(crate) fn new_mock() -> Self {
        let mut info = Self::new(PeerId::new_mock());
        info.add_address("127.0.0.1:9999".parse().unwrap());
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_creation() {
        let id = PeerId::from_bytes(vec![1, 2, 3, 4]);
        assert_eq!(id.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_peer_id_short_display() {
        let id = PeerId::from_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let short = id.short();
        assert!(short.contains("..."));
        assert!(short.len() < 20);
    }

    #[test]
    fn test_peer_id_short_display_small() {
        // Tester avec un ID plus petit que 8 bytes
        let id = PeerId::from_bytes(vec![1, 2, 3, 4]);
        let short = id.short();
        assert!(!short.contains("..."));
        assert_eq!(short, "01020304");
    }

    #[test]
    fn test_peer_id_display_trait() {
        let id = PeerId::from_bytes(vec![0xAB, 0xCD, 0xEF]);
        let display_str = format!("{}", id);
        assert_eq!(display_str, "abcdef");

        let display_str2 = id.to_string();
        assert_eq!(display_str2, "abcdef");
    }

    #[test]
    fn test_peer_info_add_address() {
        let mut info = PeerInfo::new(PeerId::new_mock());
        assert_eq!(info.addresses.len(), 0);

        let addr = "127.0.0.1:8080".parse().unwrap();
        info.add_address(addr);
        assert_eq!(info.addresses.len(), 1);

        // Pas de doublons
        info.add_address(addr);
        assert_eq!(info.addresses.len(), 1);
    }

    #[test]
    fn test_peer_info_protocol_support() {
        let info = PeerInfo::new(PeerId::new_mock());
        assert!(info.supports_protocol("miaou/0.2.0"));
        assert!(!info.supports_protocol("unknown"));
    }
}
