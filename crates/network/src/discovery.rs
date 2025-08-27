//! Module de découverte de pairs
//!
//! Principe SOLID : Open/Closed & Interface Segregation
//! Différentes méthodes de découverte peuvent être ajoutées sans modifier le code existant

use crate::{NetworkError, PeerId, PeerInfo};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Méthodes de découverte disponibles
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiscoveryMethod {
    /// Découverte mDNS sur le réseau local
    Mdns,
    /// Nœuds bootstrap préconfigurés
    Bootstrap,
    /// DHT (préparation future)
    Dht,
    /// Ajout manuel
    Manual,
}

/// Configuration de découverte
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Méthodes activées
    pub methods: Vec<DiscoveryMethod>,
    /// Intervalle entre les annonces
    pub announce_interval: Duration,
    /// Timeout pour la découverte
    pub discovery_timeout: Duration,
    /// Nombre maximum de pairs à découvrir
    pub max_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            methods: vec![DiscoveryMethod::Mdns, DiscoveryMethod::Bootstrap],
            announce_interval: Duration::from_secs(30),
            discovery_timeout: Duration::from_secs(60),
            max_peers: 100,
        }
    }
}

/// Trait principal pour la découverte de pairs
///
/// # Principe SOLID : Dependency Inversion
/// Les implémentations concrètes dépendent de cette abstraction
#[async_trait]
pub trait Discovery: Send + Sync {
    /// Démarre la découverte de pairs
    ///
    /// # Errors
    /// Retourne une erreur si le démarrage échoue
    async fn start(&self) -> Result<(), NetworkError>;

    /// Arrête la découverte
    ///
    /// # Errors
    /// Retourne une erreur si l'arrêt échoue
    async fn stop(&self) -> Result<(), NetworkError>;

    /// Annonce notre présence sur le réseau
    ///
    /// # Errors
    /// Retourne une erreur si l'annonce échoue
    async fn announce(&self, peer_info: &PeerInfo) -> Result<(), NetworkError>;

    /// Recherche un pair spécifique
    ///
    /// # Errors
    /// Retourne une erreur si la recherche échoue
    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerInfo>, NetworkError>;

    /// Liste tous les pairs découverts
    async fn discovered_peers(&self) -> Vec<PeerInfo>;

    /// Retourne la configuration
    fn config(&self) -> &DiscoveryConfig;
}

/// Gestionnaire de découverte multi-méthodes
pub struct DiscoveryManager {
    config: DiscoveryConfig,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    active: Arc<RwLock<bool>>,
}

impl DiscoveryManager {
    /// Crée un nouveau gestionnaire de découverte
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            active: Arc::new(RwLock::new(false)),
        }
    }

    /// Ajoute un pair découvert
    pub async fn add_discovered_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().await;
        if peers.len() < self.config.max_peers {
            peers.insert(peer.id.clone(), peer);
        }
    }

    /// Supprime un pair
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
    }

    /// Vérifie si la découverte est active
    pub async fn is_active(&self) -> bool {
        *self.active.read().await
    }
}

#[async_trait]
impl Discovery for DiscoveryManager {
    async fn start(&self) -> Result<(), NetworkError> {
        let mut active = self.active.write().await;
        if *active {
            return Err(NetworkError::DiscoveryError(
                "Découverte déjà active".to_string(),
            ));
        }

        *active = true;

        // Démarrer les différentes méthodes de découverte
        for method in &self.config.methods {
            match method {
                DiscoveryMethod::Mdns => {
                    // TODO: Implémenter mDNS
                }
                DiscoveryMethod::Bootstrap => {
                    // TODO: Implémenter bootstrap
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        let mut active = self.active.write().await;
        *active = false;
        Ok(())
    }

    async fn announce(&self, _peer_info: &PeerInfo) -> Result<(), NetworkError> {
        if !self.is_active().await {
            return Err(NetworkError::DiscoveryError(
                "Découverte non active".to_string(),
            ));
        }

        // Annoncer via les méthodes actives
        for method in &self.config.methods {
            if method == &DiscoveryMethod::Mdns {
                // TODO: Annoncer via mDNS
            }
        }

        Ok(())
    }

    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerInfo>, NetworkError> {
        let peers = self.peers.read().await;
        Ok(peers.get(peer_id).cloned())
    }

    async fn discovered_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    fn config(&self) -> &DiscoveryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_discovery_manager_lifecycle() {
        let config = DiscoveryConfig::default();
        let manager = DiscoveryManager::new(config);

        assert!(!manager.is_active().await);

        let result = manager.start().await;
        assert!(result.is_ok());
        assert!(manager.is_active().await);

        // Démarrage double devrait échouer
        let result = manager.start().await;
        assert!(result.is_err());

        let result = manager.stop().await;
        assert!(result.is_ok());
        assert!(!manager.is_active().await);
    }

    #[tokio::test]
    async fn test_discovery_add_peer() {
        let manager = DiscoveryManager::new(DiscoveryConfig::default());

        let peer = PeerInfo::new_mock();
        manager.add_discovered_peer(peer.clone()).await;

        let peers = manager.discovered_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, peer.id);
    }

    #[tokio::test]
    async fn test_discovery_find_peer() {
        let manager = DiscoveryManager::new(DiscoveryConfig::default());

        let peer = PeerInfo::new_mock();
        let peer_id = peer.id.clone();
        manager.add_discovered_peer(peer).await;

        let found = manager.find_peer(&peer_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, peer_id);

        let not_found = manager
            .find_peer(&PeerId::from_bytes(vec![99]))
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_discovery_max_peers() {
        let config = DiscoveryConfig {
            max_peers: 2,
            ..Default::default()
        };
        let manager = DiscoveryManager::new(config);

        for i in 0..3 {
            let mut peer = PeerInfo::new_mock();
            peer.id = PeerId::from_bytes(vec![i]);
            manager.add_discovered_peer(peer).await;
        }

        let peers = manager.discovered_peers().await;
        assert_eq!(peers.len(), 2); // Limité à max_peers
    }

    #[tokio::test]
    async fn test_discovery_remove_peer() {
        let manager = DiscoveryManager::new(DiscoveryConfig::default());

        let peer = PeerInfo::new_mock();
        let peer_id = peer.id.clone();
        manager.add_discovered_peer(peer).await;

        assert_eq!(manager.discovered_peers().await.len(), 1);

        manager.remove_peer(&peer_id).await;
        assert_eq!(manager.discovered_peers().await.len(), 0);
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.methods.len(), 2);
        assert!(config.methods.contains(&DiscoveryMethod::Mdns));
        assert!(config.methods.contains(&DiscoveryMethod::Bootstrap));
        assert_eq!(config.max_peers, 100);
    }

    #[tokio::test]
    async fn test_announce_when_inactive() {
        let manager = DiscoveryManager::new(DiscoveryConfig::default());
        let peer = PeerInfo::new_mock();

        // Le manager commence inactif
        assert!(!manager.is_active().await);

        let result = manager.announce(&peer).await;
        assert!(result.is_err());

        if let Err(NetworkError::DiscoveryError(msg)) = result {
            assert_eq!(msg, "Découverte non active");
        } else {
            panic!("Expected DiscoveryError");
        }
    }

    #[tokio::test]
    async fn test_announce_when_active() {
        let manager = DiscoveryManager::new(DiscoveryConfig::default());
        let peer = PeerInfo::new_mock();

        // Activer le manager
        manager.start().await.unwrap();
        assert!(manager.is_active().await);

        // L'announce doit réussir (même si elle ne fait rien pour le moment)
        let result = manager.announce(&peer).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_discovery_manager_config() {
        let config = DiscoveryConfig {
            max_peers: 42,
            ..Default::default()
        };
        let manager = DiscoveryManager::new(config);

        let retrieved_config = manager.config();
        assert_eq!(retrieved_config.max_peers, 42);
        assert_eq!(retrieved_config.methods.len(), 2);
    }
}
