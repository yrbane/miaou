//! Module de découverte unifiée intégrant mDNS et DHT
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Gestionnaire unifié pour toutes les méthodes de découverte

use crate::{
    DhtConfig, Discovery, DiscoveryConfig, DiscoveryMethod, DistributedHashTable, KademliaDht,
    MdnsDiscovery, NetworkError, PeerId, PeerInfo,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// État de découverte par méthode
/// État d'une méthode de découverte
#[derive(Debug, Clone)]
pub struct MethodState {
    /// Est-ce que cette méthode est active?
    pub active: bool,
    /// Nombre de pairs découverts par cette méthode
    pub peers_found: usize,
    /// Dernière erreur rencontrée (si applicable)
    pub last_error: Option<String>,
}

/// Gestionnaire unifié de découverte P2P
pub struct UnifiedDiscovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Notre ID de pair
    local_peer_id: PeerId,
    /// Notre info de pair
    local_peer_info: PeerInfo,
    /// Pairs découverts (fusionnés de toutes sources)
    discovered_peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    /// État par méthode
    method_states: Arc<RwLock<HashMap<DiscoveryMethod, MethodState>>>,
    /// Instance mDNS (optionnelle) avec interior mutability
    mdns_discovery: Arc<tokio::sync::Mutex<Option<Arc<MdnsDiscovery>>>>,
    /// Instance DHT Kademlia (optionnelle)
    dht: Option<Arc<RwLock<KademliaDht>>>,
    /// Bootstrap nodes pour DHT
    bootstrap_nodes: Vec<(PeerId, SocketAddr)>,
    /// Est-ce que la découverte est active globalement?
    is_running: Arc<RwLock<bool>>,
}

impl UnifiedDiscovery {
    /// Crée un nouveau gestionnaire unifié
    pub fn new(config: DiscoveryConfig, local_peer_id: PeerId, local_peer_info: PeerInfo) -> Self {
        let mut method_states = HashMap::new();

        // Initialiser l'état pour chaque méthode configurée
        for method in &config.methods {
            method_states.insert(
                method.clone(),
                MethodState {
                    active: false,
                    peers_found: 0,
                    last_error: None,
                },
            );
        }

        Self {
            config,
            local_peer_id,
            local_peer_info,
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            method_states: Arc::new(RwLock::new(method_states)),
            mdns_discovery: Arc::new(tokio::sync::Mutex::new(None)),
            dht: None,
            bootstrap_nodes: Vec::new(),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Configure les bootstrap nodes pour le DHT
    pub fn set_bootstrap_nodes(&mut self, nodes: Vec<(PeerId, SocketAddr)>) {
        self.bootstrap_nodes = nodes;
    }

    /// Démarre mDNS avec interior mutability
    async fn start_mdns_internal(&self) -> Result<(), NetworkError> {
        info!("🔍 Démarrage découverte mDNS...");
        
        let mdns = MdnsDiscovery::new(self.config.clone());
        mdns.start().await?;
        
        // Stocker l'instance pour pouvoir l'utiliser dans announce()
        {
            let mut mdns_guard = self.mdns_discovery.lock().await;
            *mdns_guard = Some(Arc::new(mdns));
        }
        
        // Mettre à jour l'état
        let mut states = self.method_states.write().await;
        if let Some(state) = states.get_mut(&DiscoveryMethod::Mdns) {
            state.active = true;
        }
        
        info!("✅ mDNS découverte démarrée et stockée");
        Ok(())
    }

    /// Démarre une méthode de découverte spécifique
    async fn start_method(&mut self, method: &DiscoveryMethod) -> Result<(), NetworkError> {
        match method {
            DiscoveryMethod::Mdns => {
                info!("🔍 Démarrage découverte mDNS...");

                // Créer instance mDNS si pas déjà fait
                {
                    let mut mdns_guard = self.mdns_discovery.lock().await;
                    if mdns_guard.is_none() {
                        let mdns = MdnsDiscovery::new(self.config.clone());
                        *mdns_guard = Some(Arc::new(mdns));
                    }
                }

                // Démarrer mDNS
                let mdns_guard = self.mdns_discovery.lock().await;
                if let Some(mdns) = &*mdns_guard {
                    mdns.start().await?;

                    // Mettre à jour l'état
                    let mut states = self.method_states.write().await;
                    if let Some(state) = states.get_mut(&DiscoveryMethod::Mdns) {
                        state.active = true;
                    }

                    info!("✅ mDNS découverte démarrée");
                }
            }

            DiscoveryMethod::Dht => {
                info!("🌐 Démarrage DHT Kademlia...");

                // Créer instance DHT si pas déjà fait
                if self.dht.is_none() {
                    let dht_config = DhtConfig::default();
                    let mut dht = KademliaDht::new(self.local_peer_id.clone(), dht_config);

                    // Démarrer le DHT
                    dht.start().await?;

                    // Bootstrap si on a des nodes
                    if !self.bootstrap_nodes.is_empty() {
                        info!("📡 Bootstrap DHT avec {} nœuds", self.bootstrap_nodes.len());
                        dht.bootstrap(self.bootstrap_nodes.clone()).await?;
                    }

                    // Annoncer notre présence
                    dht.announce().await?;

                    self.dht = Some(Arc::new(RwLock::new(dht)));
                }

                // Mettre à jour l'état
                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Dht) {
                    state.active = true;
                }

                info!("✅ DHT Kademlia démarré");
            }

            DiscoveryMethod::Bootstrap => {
                info!("🚀 Connexion aux nœuds bootstrap...");

                // Pour l'instant, on ajoute simplement les bootstrap nodes comme pairs découverts
                for (peer_id, addr) in &self.bootstrap_nodes {
                    let mut peer_info = PeerInfo::new(peer_id.clone());
                    peer_info.add_address(*addr);

                    let mut peers = self.discovered_peers.write().await;
                    peers.insert(peer_id.clone(), peer_info);
                }

                // Mettre à jour l'état
                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Bootstrap) {
                    state.active = true;
                    state.peers_found = self.bootstrap_nodes.len();
                }

                info!("✅ {} nœuds bootstrap ajoutés", self.bootstrap_nodes.len());
            }

            DiscoveryMethod::Manual => {
                debug!("📝 Mode manuel activé (pas d'action automatique)");

                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Manual) {
                    state.active = true;
                }
            }
        }

        Ok(())
    }

    /// Arrête une méthode de découverte spécifique
    async fn stop_method(&mut self, method: &DiscoveryMethod) -> Result<(), NetworkError> {
        match method {
            DiscoveryMethod::Mdns => {
                {
                    let mdns_guard = self.mdns_discovery.lock().await;
                    if let Some(mdns) = &*mdns_guard {
                        mdns.stop().await?;
                    }
                }

                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Mdns) {
                    state.active = false;
                }
            }

            DiscoveryMethod::Dht => {
                if let Some(dht) = &self.dht {
                    let mut dht = dht.write().await;
                    dht.stop().await?;
                }

                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Dht) {
                    state.active = false;
                }
            }

            _ => {
                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(method) {
                    state.active = false;
                }
            }
        }

        Ok(())
    }

    /// Collecte les pairs depuis toutes les sources actives
    pub async fn collect_peers(&self) -> Result<(), NetworkError> {
        let mut all_peers = HashMap::new();

        // Collecter depuis mDNS
        {
            let mdns_guard = self.mdns_discovery.lock().await;
            if let Some(mdns) = &*mdns_guard {
                let mdns_peers = mdns.discovered_peers().await;
                for peer in mdns_peers {
                    all_peers.insert(peer.id.clone(), peer);
                }

                // Mettre à jour les stats
                let mut states = self.method_states.write().await;
                if let Some(state) = states.get_mut(&DiscoveryMethod::Mdns) {
                    state.peers_found = all_peers.len();
                }
            }
        }

        // Collecter depuis DHT
        if let Some(dht) = &self.dht {
            let dht = dht.read().await;
            // Pour l'instant on récupère juste les pairs les plus proches
            let closest = dht.find_node(&self.local_peer_id).await?;

            for (peer_id, peer_info) in closest {
                all_peers.insert(peer_id, peer_info);
            }

            let mut states = self.method_states.write().await;
            if let Some(state) = states.get_mut(&DiscoveryMethod::Dht) {
                state.peers_found = all_peers.len();
            }
        }

        // Fusionner avec les pairs existants
        let mut peers = self.discovered_peers.write().await;
        for (id, info) in all_peers {
            peers.entry(id).or_insert(info);
        }

        Ok(())
    }

    /// Ajoute un pair manuellement
    pub async fn add_manual_peer(&self, peer_info: PeerInfo) -> Result<(), NetworkError> {
        let mut peers = self.discovered_peers.write().await;

        // Vérifier la limite
        if peers.len() >= self.config.max_peers {
            return Err(NetworkError::General(
                "Limite de pairs atteinte".to_string(),
            ));
        }

        peers.insert(peer_info.id.clone(), peer_info);

        // Mettre à jour les stats
        let mut states = self.method_states.write().await;
        if let Some(state) = states.get_mut(&DiscoveryMethod::Manual) {
            state.peers_found += 1;
        }

        Ok(())
    }

    /// Récupère les statistiques de découverte
    pub async fn get_stats(&self) -> HashMap<DiscoveryMethod, MethodState> {
        let states = self.method_states.read().await;
        states.clone()
    }

    /// Retourne l'info du pair local
    pub fn local_peer_info(&self) -> &PeerInfo {
        &self.local_peer_info
    }
}

#[async_trait]
impl Discovery for UnifiedDiscovery {
    async fn start(&self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().await;
        if *running {
            // Idempotent: déjà démarré, pas d'erreur
            return Ok(());
        }
        *running = true;

        info!(
            "🚀 Démarrage découverte unifiée avec méthodes: {:?}",
            self.config.methods
        );

        // Démarrer chaque méthode configurée
        for method in &self.config.methods {
            match method {
                DiscoveryMethod::Mdns => {
                    // Appeler la méthode d'aide qui gère mDNS avec interior mutability
                    self.start_mdns_internal().await?;
                }
                DiscoveryMethod::Dht => {
                    info!("🌐 Démarrage DHT Kademlia...");
                    // TODO: Implémenter DHT start dans le contexte sans &mut
                }
                DiscoveryMethod::Bootstrap => {
                    info!("🔗 Ajout des pairs bootstrap...");
                    // TODO: Implémenter bootstrap start dans le contexte sans &mut
                }
                DiscoveryMethod::Manual => {
                    info!("📝 Mode manuel - pas de démarrage automatique");
                    // Rien à faire pour le mode manuel
                }
            }
        }

        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().await;
        if !*running {
            // Idempotent: déjà arrêté, pas d'erreur
            return Ok(());
        }
        *running = false;

        info!("🛑 Arrêt découverte unifiée");

        Ok(())
    }

    async fn announce(&self, peer_info: &PeerInfo) -> Result<(), NetworkError> {
        let running = self.is_running.read().await;
        if !*running {
            return Err(NetworkError::General("Découverte non active".to_string()));
        }

        // Annoncer via toutes les méthodes actives
        let states = self.method_states.read().await;

        // mDNS
        if states
            .get(&DiscoveryMethod::Mdns)
            .map_or(false, |s| s.active)
        {
            let mdns_guard = self.mdns_discovery.lock().await;
            if let Some(mdns) = &*mdns_guard {
                info!("📢 Appel announce() sur instance mDNS");
                mdns.announce(peer_info).await?;
            } else {
                warn!("⚠️ mDNS actif mais instance non trouvée");
            }
        }

        // DHT
        if states
            .get(&DiscoveryMethod::Dht)
            .map_or(false, |s| s.active)
        {
            if let Some(dht) = &self.dht {
                let dht = dht.read().await;
                dht.announce().await?;
            }
        }

        Ok(())
    }

    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerInfo>, NetworkError> {
        // Chercher d'abord localement
        let peers = self.discovered_peers.read().await;
        if let Some(info) = peers.get(peer_id) {
            return Ok(Some(info.clone()));
        }
        drop(peers);

        // Chercher via DHT si actif
        let states = self.method_states.read().await;
        if states
            .get(&DiscoveryMethod::Dht)
            .map_or(false, |s| s.active)
        {
            if let Some(dht) = &self.dht {
                let dht = dht.read().await;

                // Chercher dans le DHT
                let key = peer_id.as_bytes().to_vec();
                if let Some(value) = dht.get(&key).await? {
                    // Désérialiser PeerInfo
                    if let Ok(peer_info) = serde_json::from_slice::<PeerInfo>(&value) {
                        // Ajouter au cache local
                        let mut peers = self.discovered_peers.write().await;
                        peers.insert(peer_id.clone(), peer_info.clone());
                        return Ok(Some(peer_info));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn discovered_peers(&self) -> Vec<PeerInfo> {
        let peers = self.discovered_peers.read().await;
        peers.values().cloned().collect()
    }

    fn config(&self) -> &DiscoveryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> DiscoveryConfig {
        DiscoveryConfig {
            methods: vec![
                DiscoveryMethod::Mdns,
                DiscoveryMethod::Dht,
                DiscoveryMethod::Bootstrap,
            ],
            max_peers: 10,
            ..Default::default()
        }
    }

    fn create_test_peer_info() -> PeerInfo {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let mut info = PeerInfo::new(peer_id);
        info.add_address("127.0.0.1:8080".parse().unwrap());
        info
    }

    #[tokio::test]
    async fn test_unified_discovery_creation() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        let stats = discovery.get_stats().await;
        assert_eq!(stats.len(), 3);
        assert!(stats.contains_key(&DiscoveryMethod::Mdns));
        assert!(stats.contains_key(&DiscoveryMethod::Dht));
        assert!(stats.contains_key(&DiscoveryMethod::Bootstrap));
    }

    #[tokio::test]
    async fn test_unified_start_stop() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Démarrer
        assert!(discovery.start().await.is_ok());

        // Double start est maintenant idempotent
        assert!(discovery.start().await.is_ok());

        // Arrêter
        assert!(discovery.stop().await.is_ok());

        // Double stop est maintenant idempotent
        assert!(discovery.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_add_manual_peer() {
        let config = DiscoveryConfig {
            methods: vec![DiscoveryMethod::Manual],
            max_peers: 10,
            ..Default::default()
        };
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        let peer_info = create_test_peer_info();
        assert!(discovery.add_manual_peer(peer_info.clone()).await.is_ok());

        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, peer_info.id);

        // Vérifier les stats
        let stats = discovery.get_stats().await;
        assert_eq!(stats[&DiscoveryMethod::Manual].peers_found, 1);
    }

    #[tokio::test]
    async fn test_max_peers_limit() {
        let config = DiscoveryConfig {
            methods: vec![DiscoveryMethod::Manual],
            max_peers: 2,
            ..Default::default()
        };

        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Ajouter 2 pairs (limite)
        for i in 0..2 {
            let peer_id = PeerId::from_bytes(vec![i]);
            let info = PeerInfo::new(peer_id);
            assert!(discovery.add_manual_peer(info).await.is_ok());
        }

        // Le 3ème devrait échouer
        let extra_peer = PeerInfo::new(PeerId::from_bytes(vec![99]));
        assert!(discovery.add_manual_peer(extra_peer).await.is_err());

        assert_eq!(discovery.discovered_peers().await.len(), 2);
    }

    #[tokio::test]
    async fn test_find_peer_local_cache() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        let peer_info = create_test_peer_info();
        let peer_id = peer_info.id.clone();

        discovery.add_manual_peer(peer_info.clone()).await.unwrap();

        // Devrait trouver dans le cache local
        let found = discovery.find_peer(&peer_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, peer_id);

        // Pair inexistant
        let not_found = discovery
            .find_peer(&PeerId::from_bytes(vec![255]))
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_bootstrap_nodes_configuration() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        let bootstrap_nodes = vec![
            (
                PeerId::from_bytes(b"boot1".to_vec()),
                "127.0.0.1:8001".parse().unwrap(),
            ),
            (
                PeerId::from_bytes(b"boot2".to_vec()),
                "127.0.0.1:8002".parse().unwrap(),
            ),
        ];

        discovery.set_bootstrap_nodes(bootstrap_nodes.clone());
        assert_eq!(discovery.bootstrap_nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_announce_when_inactive() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id.clone(), local_info);

        let peer_info = PeerInfo::new(local_id);
        let result = discovery.announce(&peer_info).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_announce_when_active() {
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let local_info = PeerInfo::new(local_id.clone());

        let discovery = UnifiedDiscovery::new(config, local_id.clone(), local_info);

        discovery.start().await.unwrap();

        let peer_info = PeerInfo::new(local_id);
        // Announce devrait réussir même si les méthodes individuelles ne sont pas implémentées
        let result = discovery.announce(&peer_info).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unified_start_stop_individual_methods() {
        // TDD: Test démarrage/arrêt méthodes individuelles
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Mdns];
        let local_id = PeerId::from_bytes(b"local_method".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Test start_method pour mDNS
        let result = discovery.start_method(&DiscoveryMethod::Mdns).await;
        assert!(result.is_ok());

        // Vérifier que l'état est mis à jour
        {
            let states = discovery.method_states.read().await;
            if let Some(state) = states.get(&DiscoveryMethod::Mdns) {
                assert!(state.active);
            }
        }

        // Test stop_method pour mDNS
        let result = discovery.stop_method(&DiscoveryMethod::Mdns).await;
        assert!(result.is_ok());

        let states = discovery.method_states.read().await;
        if let Some(state) = states.get(&DiscoveryMethod::Mdns) {
            assert!(!state.active);
        }
    }

    #[tokio::test]
    async fn test_unified_start_dht_method() {
        // TDD: Test démarrage spécifique DHT
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Dht];
        let local_id = PeerId::from_bytes(b"local_dht".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Ajouter des bootstrap nodes
        let bootstrap_nodes = vec![
            (
                PeerId::from_bytes(b"boot1".to_vec()),
                "192.168.1.1:8000".parse().unwrap(),
            ),
            (
                PeerId::from_bytes(b"boot2".to_vec()),
                "192.168.1.2:8000".parse().unwrap(),
            ),
        ];
        discovery.set_bootstrap_nodes(bootstrap_nodes);

        // Test start_method pour DHT
        let result = discovery.start_method(&DiscoveryMethod::Dht).await;
        assert!(result.is_ok());

        // Vérifier que l'état est mis à jour
        {
            let states = discovery.method_states.read().await;
            if let Some(state) = states.get(&DiscoveryMethod::Dht) {
                assert!(state.active);
            }
        }

        // Test stop_method pour DHT
        let result = discovery.stop_method(&DiscoveryMethod::Dht).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unified_bootstrap_method() {
        // TDD: Test méthode bootstrap
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Bootstrap];
        let local_id = PeerId::from_bytes(b"local_bootstrap".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Ajouter des bootstrap nodes
        let bootstrap_peer1 = PeerId::from_bytes(b"bootstrap1".to_vec());
        let bootstrap_peer2 = PeerId::from_bytes(b"bootstrap2".to_vec());
        let bootstrap_nodes = vec![
            (bootstrap_peer1.clone(), "203.0.113.1:8080".parse().unwrap()),
            (bootstrap_peer2.clone(), "203.0.113.2:8080".parse().unwrap()),
        ];
        discovery.set_bootstrap_nodes(bootstrap_nodes);

        // Au début, pas de pairs découverts
        let peers = discovery.discovered_peers().await;
        assert!(peers.is_empty());

        // Test start_method pour Bootstrap
        let result = discovery.start_method(&DiscoveryMethod::Bootstrap).await;
        assert!(result.is_ok());

        // Maintenant on devrait avoir les bootstrap nodes comme pairs découverts
        let peers = discovery.discovered_peers().await;
        assert_eq!(peers.len(), 2);

        let peer_ids: std::collections::HashSet<_> = peers.iter().map(|p| &p.id).collect();
        assert!(peer_ids.contains(&bootstrap_peer1));
        assert!(peer_ids.contains(&bootstrap_peer2));

        // Vérifier l'état
        let states = discovery.method_states.read().await;
        if let Some(state) = states.get(&DiscoveryMethod::Bootstrap) {
            assert!(state.active);
        }
    }

    #[tokio::test]
    async fn test_unified_get_stats() {
        // TDD: Test récupération statistiques
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local_stats".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        let stats = discovery.get_stats().await;

        // Vérifier qu'on a des stats pour chaque méthode configurée
        assert!(stats.contains_key(&DiscoveryMethod::Mdns));
        assert!(stats.contains_key(&DiscoveryMethod::Dht));
        assert!(stats.contains_key(&DiscoveryMethod::Bootstrap));

        // Au début, toutes les méthodes sont inactives
        for (_, state) in stats.iter() {
            assert!(!state.active);
        }
    }

    #[tokio::test]
    async fn test_unified_double_start_stop() {
        // TDD: Test double start/stop
        let config = create_test_config();
        let local_id = PeerId::from_bytes(b"local_double".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Premier start
        assert!(discovery.start().await.is_ok());
        assert!(*discovery.is_running.read().await);

        // Double start devrait réussir (idempotent)
        assert!(discovery.start().await.is_ok());
        assert!(*discovery.is_running.read().await);

        // Premier stop
        assert!(discovery.stop().await.is_ok());
        assert!(!*discovery.is_running.read().await);

        // Double stop devrait réussir (idempotent)
        assert!(discovery.stop().await.is_ok());
        assert!(!*discovery.is_running.read().await);
    }

    #[tokio::test]
    async fn test_unified_empty_bootstrap_nodes() {
        // TDD: Test avec bootstrap nodes vides
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Dht];
        let local_id = PeerId::from_bytes(b"local_empty".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Bootstrap nodes vides par défaut
        assert!(discovery.bootstrap_nodes.is_empty());

        // Démarrer DHT sans bootstrap nodes devrait fonctionner
        let result = discovery.start_method(&DiscoveryMethod::Dht).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unified_stop_method_when_already_stopped() {
        // TDD: Test stop_method sur méthode déjà arrêtée
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Mdns];
        let local_id = PeerId::from_bytes(b"local_stopped".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Stop sans avoir démarré devrait fonctionner
        let result = discovery.stop_method(&DiscoveryMethod::Mdns).await;
        assert!(result.is_ok());

        // L'état devrait rester inactif
        let states = discovery.method_states.read().await;
        if let Some(state) = states.get(&DiscoveryMethod::Mdns) {
            assert!(!state.active);
        }
    }

    #[tokio::test]
    async fn test_unified_find_peer_via_dht() {
        // TDD: Test recherche pair via DHT
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Dht];
        let local_id = PeerId::from_bytes(b"local_find".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Démarrer DHT
        assert!(discovery.start_method(&DiscoveryMethod::Dht).await.is_ok());

        // Chercher un pair qui n'existe pas
        let target_peer = PeerId::from_bytes(b"target_peer".to_vec());
        let found = discovery.find_peer(&target_peer).await.unwrap();
        assert!(found.is_none());

        // Test avec pair existant dans cache local
        let test_peer = create_test_peer_info();
        discovery.add_manual_peer(test_peer.clone()).await.unwrap();

        let found = discovery.find_peer(&test_peer.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, test_peer.id);
    }

    #[tokio::test]
    async fn test_unified_specific_method_configurations() {
        // TDD: Test configurations spécifiques par méthode

        // Test avec seulement mDNS
        let mut config = create_test_config();
        config.methods = vec![DiscoveryMethod::Mdns];
        let local_id = PeerId::from_bytes(b"local_mdns_only".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let mut mdns_discovery = UnifiedDiscovery::new(config.clone(), local_id, local_info);

        assert!(mdns_discovery.start().await.is_ok());
        let stats = mdns_discovery.get_stats().await;
        assert_eq!(stats.len(), 1); // Une seule méthode configurée (mDNS)
        assert!(mdns_discovery.stop().await.is_ok());

        // Test avec seulement DHT
        config.methods = vec![DiscoveryMethod::Dht];
        let local_id2 = PeerId::from_bytes(b"local_dht_only".to_vec());
        let local_info2 = PeerInfo::new(local_id2.clone());
        let mut dht_discovery = UnifiedDiscovery::new(config.clone(), local_id2, local_info2);

        assert!(dht_discovery.start().await.is_ok());
        assert!(dht_discovery.stop().await.is_ok());

        // Test avec seulement Bootstrap
        config.methods = vec![DiscoveryMethod::Bootstrap];
        let local_id3 = PeerId::from_bytes(b"local_boot_only".to_vec());
        let local_info3 = PeerInfo::new(local_id3.clone());
        let mut bootstrap_discovery = UnifiedDiscovery::new(config, local_id3, local_info3);

        assert!(bootstrap_discovery.start().await.is_ok());
        assert!(bootstrap_discovery.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_start_mdns_internal_stores_instance() {
        // TDD: Test que start_mdns_internal stocke bien l'instance mDNS
        let mut config = DiscoveryConfig::default();
        config.methods = vec![DiscoveryMethod::Mdns];
        
        let local_id = PeerId::from_bytes(b"test_peer".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Au début, pas d'instance mDNS
        {
            let mdns_guard = discovery.mdns_discovery.lock().await;
            assert!(mdns_guard.is_none());
        }

        // Appeler start_mdns_internal
        let result = discovery.start_mdns_internal().await;
        assert!(result.is_ok());

        // Maintenant l'instance doit être stockée
        {
            let mdns_guard = discovery.mdns_discovery.lock().await;
            assert!(mdns_guard.is_some());
        }

        // L'état doit être actif
        let states = discovery.method_states.read().await;
        let mdns_state = states.get(&DiscoveryMethod::Mdns).unwrap();
        assert!(mdns_state.active);
    }

    #[tokio::test] 
    async fn test_unified_discovery_announce_with_stored_mdns() {
        // TDD: Test que announce() utilise bien l'instance mDNS stockée
        let mut config = DiscoveryConfig::default();
        config.methods = vec![DiscoveryMethod::Mdns];
        
        let local_id = PeerId::from_bytes(b"test_peer".to_vec());
        let mut local_info = PeerInfo::new(local_id.clone());
        local_info.add_address("127.0.0.1:4242".parse().unwrap());
        let discovery = UnifiedDiscovery::new(config, local_id, local_info.clone());

        // Démarrer la découverte pour stocker l'instance
        assert!(discovery.start().await.is_ok());

        // Maintenant announce() doit fonctionner
        let result = discovery.announce(&local_info).await;
        assert!(result.is_ok());

        // Arrêter proprement
        assert!(discovery.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_unified_discovery_start_calls_mdns_internal() {
        // TDD: Test que start() appelle bien start_mdns_internal pour mDNS
        let mut config = DiscoveryConfig::default();
        config.methods = vec![DiscoveryMethod::Mdns];
        
        let local_id = PeerId::from_bytes(b"test_peer".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // start() doit créer et stocker l'instance mDNS
        assert!(discovery.start().await.is_ok());

        // Vérifier que l'instance est bien stockée
        {
            let mdns_guard = discovery.mdns_discovery.lock().await;
            assert!(mdns_guard.is_some());
        }

        // Et que l'état est actif
        let states = discovery.method_states.read().await;
        let mdns_state = states.get(&DiscoveryMethod::Mdns).unwrap();
        assert!(mdns_state.active);

        // Arrêter proprement
        assert!(discovery.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_collect_peers_with_stored_mdns_instance() {
        // TDD: Test que collect_peers fonctionne avec l'instance mDNS stockée
        let mut config = DiscoveryConfig::default();
        config.methods = vec![DiscoveryMethod::Mdns];
        
        let local_id = PeerId::from_bytes(b"test_peer".to_vec());
        let local_info = PeerInfo::new(local_id.clone());
        let discovery = UnifiedDiscovery::new(config, local_id, local_info);

        // Démarrer pour avoir l'instance mDNS
        assert!(discovery.start().await.is_ok());

        // collect_peers ne doit pas échouer même si aucun pair découvert
        let result = discovery.collect_peers().await;
        assert!(result.is_ok());

        // Les pairs découverts doivent être vides au début
        let peers = discovery.discovered_peers().await;
        assert!(peers.is_empty());

        // Arrêter proprement
        assert!(discovery.stop().await.is_ok());
    }
}
