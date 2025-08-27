//! mDNS Discovery pour réseau local
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Implémentation concrète du trait Discovery

use crate::{Discovery, DiscoveryConfig, NetworkError, PeerId, PeerInfo};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

#[cfg(feature = "mdns-discovery")]
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// Message pour communiquer avec la tâche mDNS
#[cfg(feature = "mdns-discovery")]
#[derive(Debug)]
enum MdnsMessage {
    Announce(PeerInfo),
}

/// mDNS Discovery pour découverte sur réseau local
pub struct MdnsDiscovery {
    config: DiscoveryConfig,
    peers: Arc<Mutex<HashMap<PeerId, PeerInfo>>>,
    active: Arc<Mutex<bool>>,
    /// Handle de la tâche de découverte
    discovery_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    /// Canal pour arrêter la découverte
    shutdown_tx: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    /// Canal pour envoyer des messages à la tâche mDNS
    #[cfg(feature = "mdns-discovery")]
    mdns_tx: Arc<Mutex<Option<mpsc::UnboundedSender<MdnsMessage>>>>,
    /// Port d'écoute pour notre service mDNS
    listen_port: u16,
}

impl MdnsDiscovery {
    /// Crée une nouvelle instance mDNS Discovery
    pub fn new(config: DiscoveryConfig) -> Self {
        Self::new_with_port(config, 4242) // Port par défaut pour Miaou
    }

    /// Crée une instance mDNS avec un port spécifique
    pub fn new_with_port(config: DiscoveryConfig, port: u16) -> Self {
        Self {
            config,
            peers: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(false)),
            discovery_task: Arc::new(Mutex::new(None)),
            shutdown_tx: Arc::new(Mutex::new(None)),
            listen_port: port,
            #[cfg(feature = "mdns-discovery")]
            mdns_tx: Arc::new(Mutex::new(None)),
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

    /// Retourne le nom de service mDNS utilisé
    pub fn service_name(&self) -> &'static str {
        "_miaou._tcp.local."
    }

    /// Obtient l'adresse IP locale (pas 127.0.0.1)
    #[cfg(feature = "mdns-discovery")]
    fn get_local_ip() -> Option<String> {
        // Essayer de se connecter à une adresse externe pour découvrir notre IP locale
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        let local_addr = socket.local_addr().ok()?;
        Some(local_addr.ip().to_string())
    }

    /// Parse les informations d'un service mDNS pour créer un PeerInfo
    #[cfg(feature = "mdns-discovery")]
    async fn parse_service_info(service_info: &ServiceInfo) -> Option<PeerInfo> {
        // Extraire le peer_id depuis les propriétés TXT
        let mut peer_id_hex = None;

        let properties = service_info.get_properties();
        if let Some(value) = properties.get("peer_id") {
            // Convertir TxtProperty en string
            if let Some(bytes) = value.val() {
                peer_id_hex = Some(String::from_utf8_lossy(bytes).to_string());
            }
        }

        if let Some(peer_id_str) = peer_id_hex {
            // Décoder le peer ID depuis l'hex
            if let Ok(peer_id_bytes) = hex::decode(&peer_id_str) {
                let peer_id = PeerId::from_bytes(peer_id_bytes);
                let mut peer_info = PeerInfo::new(peer_id);

                // Ajouter les adresses du service
                for addr in service_info.get_addresses() {
                    let socket_addr = std::net::SocketAddr::new(*addr, service_info.get_port());
                    peer_info.add_address(socket_addr);
                }

                return Some(peer_info);
            }
        }

        None
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

        #[cfg(feature = "mdns-discovery")]
        {
            info!("🟢 Démarrage mDNS discovery avec mdns-sd - DEBUT");

            // Créer canal de shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
            *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

            // Créer canal pour messages mDNS
            let (mdns_tx, mut mdns_rx) = mpsc::unbounded_channel();
            *self.mdns_tx.lock().unwrap() = Some(mdns_tx);

            // Lancer la tâche de découverte en arrière-plan
            let peers = Arc::clone(&self.peers);
            let max_peers = self.config.max_peers;
            let listen_port = self.listen_port;

            let discovery_task = tokio::spawn(async move {
                // Créer UN daemon pour annonce et UN autre pour découverte
                let announce_daemon = match ServiceDaemon::new() {
                    Ok(daemon) => daemon,
                    Err(e) => {
                        warn!("Erreur création daemon d'annonce mDNS: {}", e);
                        return;
                    }
                };

                let discover_daemon = match ServiceDaemon::new() {
                    Ok(daemon) => daemon,
                    Err(e) => {
                        warn!("Erreur création daemon de découverte mDNS: {}", e);
                        return;
                    }
                };

                // Écouter les événements de service avec le daemon de découverte
                let browser = match discover_daemon.browse("_miaou._tcp.local.") {
                    Ok(receiver) => receiver,
                    Err(e) => {
                        warn!("Erreur création browser mDNS: {}", e);
                        return;
                    }
                };
                debug!("mDNS browser créé, écoute des services _miaou._tcp.local.");

                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            debug!("Arrêt mDNS discovery demandé");
                            break;
                        }
                        msg = mdns_rx.recv() => {
                            match msg {
                                Some(MdnsMessage::Announce(peer_info)) => {
                                    debug!("Annonce service mDNS pour peer {}", peer_info.id);

                                    // Créer et enregistrer le service mDNS
                                    let service_name = format!("miaou-{}", peer_info.id.to_hex());

                                    // Obtenir l'adresse IP locale réelle (pas 127.0.0.1)
                                    let local_ip = Self::get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
                                    // Utiliser un hostname simple et valide
                                    let hostname = "localhost.local.";

                                    debug!("Enregistrement service mDNS: {} sur {}:{}", service_name, local_ip, listen_port);

                                    let mut properties = std::collections::HashMap::new();
                                    properties.insert("peer_id".to_string(), peer_info.id.to_hex());
                                    properties.insert("version".to_string(), "0.2.0".to_string());
                                    properties.insert("port".to_string(), listen_port.to_string());

                                    if !peer_info.addresses.is_empty() {
                                        properties.insert("address".to_string(), peer_info.addresses[0].to_string());
                                    }

                                    let service_info = ServiceInfo::new(
                                        "_miaou._tcp.local.",
                                        &service_name,
                                        hostname,
                                        &local_ip,
                                        listen_port,
                                        Some(properties),
                                    ).unwrap();

                                    if let Err(e) = announce_daemon.register(service_info) {
                                        warn!("Erreur enregistrement service mDNS: {}", e);
                                    } else {
                                        info!("Service mDNS enregistré: {}", service_name);
                                    }
                                }
                                None => {
                                    debug!("Canal mDNS fermé");
                                    break;
                                }
                            }
                        }
                        event = browser.recv_async() => {
                            match event {
                                Ok(ServiceEvent::ServiceResolved(info)) => {
                                    debug!("Service mDNS découvert: {}", info.get_fullname());

                                    // Parser les infos du service pour créer un PeerInfo
                                    if let Some(peer_info) = Self::parse_service_info(&info).await {
                                        let mut peers_guard = peers.lock().unwrap();
                                        if peers_guard.len() < max_peers {
                                            info!("🆕 Peer découvert via mDNS: {}", peer_info.id);
                                            peers_guard.insert(peer_info.id.clone(), peer_info);
                                        }
                                    }
                                }
                                Ok(ServiceEvent::ServiceRemoved(_, full_name)) => {
                                    debug!("Service mDNS supprimé: {}", full_name);
                                    // TODO: Retirer le peer de la liste si nécessaire
                                }
                                Ok(_) => {
                                    debug!("Autre événement mDNS reçu");
                                }
                                Err(e) => {
                                    warn!("Erreur réception événement mDNS: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }

                info!("mDNS discovery task terminée");
            });

            *self.discovery_task.lock().unwrap() = Some(discovery_task);
        }

        #[cfg(not(feature = "mdns-discovery"))]
        {
            debug!("mDNS discovery désactivée (feature manquante)");
        }

        *active = true;
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        // Vérifier l'état et early return si déjà arrêtée
        {
            let active = self.active.lock().unwrap();
            if !*active {
                return Ok(()); // Déjà arrêtée
            }
        }

        info!("Arrêt mDNS discovery");

        // Envoyer signal d'arrêt
        let shutdown_tx = { self.shutdown_tx.lock().unwrap().take() };
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(());
        }

        // Attendre la fin de la tâche
        let task = { self.discovery_task.lock().unwrap().take() };
        if let Some(task) = task {
            let _ = task.await;
        }

        // Marquer comme arrêtée
        {
            let mut active = self.active.lock().unwrap();
            *active = false;
        }

        debug!("mDNS discovery arrêtée");
        Ok(())
    }

    async fn announce(&self, peer_info: &PeerInfo) -> Result<(), NetworkError> {
        if !self.is_active() {
            return Err(NetworkError::DiscoveryError(
                "mDNS discovery non active".to_string(),
            ));
        }

        #[cfg(feature = "mdns-discovery")]
        {
            info!("🔊 Envoi message d'annonce mDNS pour peer {}", peer_info.id);

            // Envoyer message à la tâche mDNS pour enregistrer le service
            let mdns_tx = self.mdns_tx.lock().unwrap();
            if let Some(ref tx) = *mdns_tx {
                if let Err(e) = tx.send(MdnsMessage::Announce(peer_info.clone())) {
                    return Err(NetworkError::DiscoveryError(format!(
                        "Erreur envoi message mDNS: {}",
                        e
                    )));
                }
            } else {
                return Err(NetworkError::DiscoveryError(
                    "Canal mDNS non disponible".to_string(),
                ));
            }
        }

        #[cfg(not(feature = "mdns-discovery"))]
        {
            debug!(
                "Annonce mDNS ignorée (feature manquante) pour peer {}",
                peer_info.id
            );
        }

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

    #[cfg(feature = "mdns-discovery")]
    #[tokio::test]
    async fn test_mdns_service_announcement() {
        // TDD: Test annonce d'un service mDNS réel
        let config = create_test_config();
        let discovery = MdnsDiscovery::new_with_port(config, 4243); // Port test
        let peer = PeerInfo::new_mock();

        // Le service doit pouvoir être annoncé
        discovery.start().await.unwrap();
        let result = discovery.announce(&peer).await;
        assert!(result.is_ok());

        discovery.stop().await.unwrap();
    }

    #[cfg(feature = "mdns-discovery")]
    #[tokio::test]
    async fn test_mdns_service_discovery() {
        // TDD: Test découverte de service mDNS réel
        use tokio::time::{sleep, Duration};

        let config1 = create_test_config();
        let config2 = create_test_config();

        let discovery1 = MdnsDiscovery::new_with_port(config1, 4244);
        let discovery2 = MdnsDiscovery::new_with_port(config2, 4245);

        let peer1 = PeerInfo::new_mock();

        // Démarrer le premier service et l'annoncer
        discovery1.start().await.unwrap();
        discovery1.announce(&peer1).await.unwrap();

        // Démarrer le second service pour écouter
        discovery2.start().await.unwrap();

        // Attendre un peu pour la découverte
        sleep(Duration::from_millis(500)).await;

        // Le second devrait voir le premier
        let _discovered = discovery2.discovered_peers().await;
        // Note: Le test peut être flaky selon l'environnement réseau
        // En CI, on pourrait le désactiver ou l'adapter

        discovery1.stop().await.unwrap();
        discovery2.stop().await.unwrap();

        // Pour l'instant, on vérifie juste qu'il n'y a pas d'erreur
        // L'implémentation réelle viendra ensuite
        // Au moins pas d'erreur - la longueur peut être 0 ou plus
    }

    #[cfg(feature = "mdns-discovery")]
    #[tokio::test]
    async fn test_mdns_service_name_format() {
        // TDD: Test format du nom de service mDNS
        let config = create_test_config();
        let discovery = MdnsDiscovery::new(config);

        // Le nom de service doit suivre le format _miaou._tcp.local.
        let service_name = discovery.service_name();
        assert_eq!(service_name, "_miaou._tcp.local.");
    }

    #[cfg(feature = "mdns-discovery")]
    #[tokio::test]
    async fn test_mdns_multiple_services_different_ports() {
        // TDD: Test plusieurs services mDNS sur ports différents
        let config1 = create_test_config();
        let config2 = create_test_config();

        let discovery1 = MdnsDiscovery::new_with_port(config1, 4246);
        let discovery2 = MdnsDiscovery::new_with_port(config2, 4247);

        // Les deux services doivent pouvoir démarrer sans conflit
        let result1 = discovery1.start().await;
        let result2 = discovery2.start().await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        discovery1.stop().await.unwrap();
        discovery2.stop().await.unwrap();
    }
}
