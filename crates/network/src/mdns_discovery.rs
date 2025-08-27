//! mDNS Discovery pour réseau local
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Implémentation concrète du trait Discovery

use crate::{Discovery, DiscoveryConfig, NetworkError, PeerId, PeerInfo};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// mDNS Discovery pour découverte sur réseau local
pub struct MdnsDiscovery {
    config: DiscoveryConfig,
    peers: Arc<Mutex<HashMap<PeerId, PeerInfo>>>,
    active: Arc<Mutex<bool>>,
}

impl MdnsDiscovery {
    /// Crée une nouvelle instance mDNS Discovery
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            peers: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(false)),
        }
    }

    /// Vérifie si la découverte est active
    pub fn is_active(&self) -> bool {
        *self.active.lock().unwrap()
    }

    /// Ajoute un pair découvert
    pub fn add_discovered_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.lock().unwrap();
        if peers.len() < self.config.max_peers {
            peers.insert(peer.id.clone(), peer);
        }
    }
}

#[async_trait]
impl Discovery for MdnsDiscovery {
    async fn start(&self) -> Result<(), NetworkError> {
        let mut active = self.active.lock().unwrap();
        if *active {
            return Err(NetworkError::DiscoveryError(
                "mDNS discovery déjà active".to_string(),
            ));
        }

        // TDD: Implémentation réelle après tests
        *active = true;
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        let mut active = self.active.lock().unwrap();
        *active = false;
        Ok(())
    }

    async fn announce(&self, _peer_info: &PeerInfo) -> Result<(), NetworkError> {
        if !self.is_active() {
            return Err(NetworkError::DiscoveryError(
                "mDNS discovery non active".to_string(),
            ));
        }

        // TDD: Implémentation libmdns après tests
        Ok(())
    }

    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerInfo>, NetworkError> {
        let peers = self.peers.lock().unwrap();
        Ok(peers.get(peer_id).cloned())
    }

    async fn discovered_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }

    fn config(&self) -> &DiscoveryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscoveryMethod;
    use std::time::Duration;
    use tokio;

    fn create_test_config() -> DiscoveryConfig {
        DiscoveryConfig {
            methods: vec![DiscoveryMethod::Mdns],
            announce_interval: Duration::from_secs(10),
            discovery_timeout: Duration::from_secs(30),
            max_peers: 50,
        }
    }

    #[test]
    fn test_mdns_discovery_creation() {
        // TDD: Test création mDNS discovery
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config.clone());

        assert_eq!(discovery.config().max_peers, config.max_peers);
        assert_eq!(
            discovery.config().announce_interval,
            config.announce_interval
        );
        assert!(!discovery.is_active());
    }

    #[test]
    fn test_mdns_discovery_config() {
        // TDD: Test accès configuration
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);

        let retrieved_config = discovery.config();
        assert_eq!(retrieved_config.max_peers, 50);
        assert_eq!(retrieved_config.methods.len(), 1);
        assert!(retrieved_config.methods.contains(&DiscoveryMethod::Mdns));
    }

    #[tokio::test]
    async fn test_mdns_discovery_lifecycle() {
        // TDD: Test start/stop lifecycle
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);

        assert!(!discovery.is_active());

        // Start should succeed
        let result = discovery.start().await;
        assert!(result.is_ok());
        assert!(discovery.is_active());

        // Double start should fail
        let result = discovery.start().await;
        assert!(result.is_err());
        if let Err(NetworkError::DiscoveryError(msg)) = result {
            assert_eq!(msg, "mDNS discovery déjà active");
        }

        // Stop should succeed
        let result = discovery.stop().await;
        assert!(result.is_ok());
        assert!(!discovery.is_active());
    }

    #[tokio::test]
    async fn test_mdns_discovery_announce_when_inactive() {
        // TDD: Test announce quand discovery inactive
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);
        let peer = PeerInfo::new_mock();

        assert!(!discovery.is_active());

        let result = discovery.announce(&peer).await;
        assert!(result.is_err());
        if let Err(NetworkError::DiscoveryError(msg)) = result {
            assert_eq!(msg, "mDNS discovery non active");
        }
    }

    #[tokio::test]
    async fn test_mdns_discovery_announce_when_active() {
        // TDD: Test announce quand discovery active
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);
        let peer = PeerInfo::new_mock();

        discovery.start().await.unwrap();
        assert!(discovery.is_active());

        let result = discovery.announce(&peer).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_add_and_find_peer() {
        // TDD: Test ajout et recherche de pair
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);
        let peer = PeerInfo::new_mock();
        let peer_id = peer.id.clone();

        // Au début, aucun pair
        let found = discovery.find_peer(&peer_id).await.unwrap();
        assert!(found.is_none());

        // Ajouter le pair
        discovery.add_discovered_peer(peer);

        // Maintenant on devrait le trouver
        let found = discovery.find_peer(&peer_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, peer_id);
    }

    #[tokio::test]
    async fn test_mdns_discovery_discovered_peers() {
        // TDD: Test listage des pairs découverts
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);

        // Au début, liste vide
        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 0);

        // Ajouter des pairs
        let peer_info1 = PeerInfo::new_mock();
        let mut peer_info2 = PeerInfo::new_mock();
        peer_info2.id = PeerId::from_bytes(vec![9, 8, 7, 6]);

        discovery.add_discovered_peer(peer_info1.clone());
        discovery.add_discovered_peer(peer_info2.clone());

        // Vérifier la liste
        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 2);

        let peer_ids: std::collections::HashSet<_> = peers.iter().map(|p| &p.id).collect();
        assert!(peer_ids.contains(&peer_info1.id));
        assert!(peer_ids.contains(&peer_info2.id));
    }

    #[tokio::test]
    async fn test_mdns_discovery_max_peers_limit() {
        // TDD: Test limite max_peers
        let config = DiscoveryConfig {
            methods: vec![DiscoveryMethod::Mdns],
            announce_interval: Duration::from_secs(10),
            discovery_timeout: Duration::from_secs(30),
            max_peers: 2, // Limite basse pour test
        };
        let discovery = MdnsDiscovery::new(config);

        // Ajouter 3 pairs mais limite à 2
        for i in 0..3 {
            let mut peer = PeerInfo::new_mock();
            peer.id = PeerId::from_bytes(vec![i]);
            discovery.add_discovered_peer(peer);
        }

        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 2); // Limité par max_peers
    }

    // TDD: Tests d'intégration avec le trait Discovery
    #[tokio::test]
    async fn test_mdns_discovery_trait_compatibility() {
        // TDD: Test que MdnsDiscovery implémente correctement Discovery
        let config = create_test_config();
        let discovery: Box<dyn Discovery> = Box::new(MdnsDiscovery::new(config));

        // Test trait methods compilation
        assert_eq!(discovery.config().max_peers, 50);

        // Test async methods compilation
        let peer = PeerInfo::new_mock();
        let start_result = discovery.start().await;
        assert!(start_result.is_ok());

        let announce_result = discovery.announce(&peer).await;
        assert!(announce_result.is_ok());

        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 0);

        let find_result = discovery.find_peer(&peer.id).await;
        assert!(find_result.is_ok());
        assert!(find_result.unwrap().is_none());

        let stop_result = discovery.stop().await;
        assert!(stop_result.is_ok());
    }
}
