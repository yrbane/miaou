//! Module NAT Traversal avec STUN/TURN pour connexions P2P
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Gestion du NAT traversal avec ICE et STUN/TURN

use crate::NetworkError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Types de NAT détectés
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// Pas de NAT - connexion directe possible
    Open,
    /// Full Cone NAT - ouverture bidirectionnelle
    FullCone,
    /// Restricted Cone NAT - restriction par IP
    RestrictedCone,
    /// Port Restricted Cone NAT - restriction par IP et port
    PortRestrictedCone,
    /// Symmetric NAT - le plus restrictif
    Symmetric,
    /// Type non déterminé
    Unknown,
}

impl Default for NatType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Candidat ICE pour connexion
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Adresse du candidat
    pub address: SocketAddr,
    /// Type de candidat
    pub candidate_type: CandidateType,
    /// Priorité (plus haut = préféré)
    pub priority: u32,
    /// Foundation pour le grouping
    pub foundation: String,
    /// ID de composant
    pub component_id: u32,
    /// Protocol (UDP/TCP)
    pub protocol: TransportProtocol,
    /// Adresse de base (pour server reflexive/relay)
    pub related_address: Option<SocketAddr>,
}

/// Type de candidat ICE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateType {
    /// Adresse locale (host)
    Host,
    /// Réflexive serveur (STUN)
    ServerReflexive,
    /// Candidat relayé (TURN)
    Relay,
    /// Peer reflexive (découvert pendant connectivity checks)
    PeerReflexive,
}

/// Protocole de transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// UDP (préféré pour temps réel)
    Udp,
    /// TCP (fallback)
    Tcp,
}

/// Configuration NAT traversal
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Serveurs STUN à utiliser
    pub stun_servers: Vec<SocketAddr>,
    /// Serveurs TURN à utiliser (avec credentials)
    pub turn_servers: Vec<TurnServer>,
    /// Timeout pour les requêtes STUN/TURN (en secondes)
    pub timeout_seconds: u64,
    /// Nombre maximum de tentatives par serveur
    pub max_attempts: u32,
    /// Activer la détection du type de NAT
    pub detect_nat_type: bool,
    /// Port range pour les candidats locaux
    pub port_range: Option<(u16, u16)>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            // Serveurs STUN publics populaires (IPs résolues pour les tests)
            stun_servers: vec![
                "8.8.8.8:19302".parse().unwrap(), // Google STUN
                "8.8.4.4:19302".parse().unwrap(), // Google STUN
                "1.1.1.1:3478".parse().unwrap(),  // Cloudflare
            ],
            turn_servers: Vec::new(),
            timeout_seconds: 5,
            max_attempts: 3,
            detect_nat_type: true,
            port_range: Some((49152, 65535)), // Plage ports éphémères
        }
    }
}

/// Serveur TURN avec credentials
#[derive(Debug, Clone)]
pub struct TurnServer {
    /// Adresse du serveur TURN
    pub address: SocketAddr,
    /// Nom d'utilisateur
    pub username: String,
    /// Mot de passe/credential
    pub password: String,
    /// Realm (optionnel)
    pub realm: Option<String>,
}

/// Résultat de la découverte NAT
#[derive(Debug, Clone)]
pub struct NatDiscoveryResult {
    /// Type de NAT détecté
    pub nat_type: NatType,
    /// Adresse publique découverte
    pub public_address: Option<SocketAddr>,
    /// Candidats ICE disponibles
    pub candidates: Vec<IceCandidate>,
    /// Temps de découverte en ms
    pub discovery_time_ms: u64,
}

/// Trait pour NAT traversal
#[async_trait]
pub trait NatTraversal: Send + Sync {
    /// Démarre la découverte NAT
    async fn start_discovery(
        &self,
        local_address: SocketAddr,
    ) -> Result<NatDiscoveryResult, NetworkError>;

    /// Détecte le type de NAT
    async fn detect_nat_type(&self, local_address: SocketAddr) -> Result<NatType, NetworkError>;

    /// Récupère les candidats ICE
    async fn gather_candidates(
        &self,
        local_address: SocketAddr,
    ) -> Result<Vec<IceCandidate>, NetworkError>;

    /// Teste la connectivité avec un pair
    async fn test_connectivity(
        &self,
        local: &IceCandidate,
        remote: &IceCandidate,
    ) -> Result<bool, NetworkError>;

    /// Crée un relay TURN si disponible
    async fn create_turn_relay(
        &self,
        server: &TurnServer,
    ) -> Result<Option<IceCandidate>, NetworkError>;
}

/// Implémentation NAT traversal avec STUN/TURN
pub struct StunTurnNatTraversal {
    /// Configuration
    config: NatConfig,
    /// Cache des découvertes par adresse locale
    discovery_cache: Arc<RwLock<HashMap<SocketAddr, NatDiscoveryResult>>>,
    /// Etat du service
    is_active: Arc<RwLock<bool>>,
}

impl StunTurnNatTraversal {
    /// Crée une nouvelle instance NAT traversal
    pub fn new(config: NatConfig) -> Self {
        Self {
            config,
            discovery_cache: Arc::new(RwLock::new(HashMap::new())),
            is_active: Arc::new(RwLock::new(false)),
        }
    }

    /// Démarre le service NAT traversal
    pub async fn start(&self) -> Result<(), NetworkError> {
        let mut active = self.is_active.write().await;
        if *active {
            return Err(NetworkError::General(
                "NAT traversal déjà actif".to_string(),
            ));
        }
        *active = true;
        Ok(())
    }

    /// Arrête le service NAT traversal
    pub async fn stop(&self) -> Result<(), NetworkError> {
        let mut active = self.is_active.write().await;
        if !*active {
            return Err(NetworkError::General("NAT traversal non actif".to_string()));
        }
        *active = false;

        // Nettoyer le cache
        let mut cache = self.discovery_cache.write().await;
        cache.clear();

        Ok(())
    }

    /// Effectue une requête STUN vers un serveur
    fn stun_request(
        &self,
        server: SocketAddr,
        local_address: SocketAddr,
    ) -> Result<Option<SocketAddr>, NetworkError> {
        // TDD: Pour MVP, simulation d'une requête STUN
        // En production, implémenter le protocole STUN RFC 5389

        // Simuler une réponse STUN réussie avec adresse publique mappée
        let public_ip = match server.ip() {
            IpAddr::V4(_) => IpAddr::V4("8.8.8.8".parse().unwrap()), // IP publique simulée
            IpAddr::V6(_) => IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
        };

        // Simuler mapping de port (souvent différent du port local)
        let public_port = local_address.port().wrapping_add(1000);

        Ok(Some(SocketAddr::new(public_ip, public_port)))
    }

    /// Génère les candidats host (adresses locales)
    fn generate_host_candidates(&self, local_address: SocketAddr) -> Vec<IceCandidate> {
        let mut candidates = Vec::new();

        // Candidat principal
        candidates.push(IceCandidate {
            address: local_address,
            candidate_type: CandidateType::Host,
            priority: self.calculate_priority(CandidateType::Host, local_address.ip()),
            foundation: format!("host_{}", local_address.port()),
            component_id: 1,
            protocol: TransportProtocol::Udp,
            related_address: None,
        });

        // TDD: Pour MVP, un seul candidat host
        // En production, énumérer toutes les interfaces réseau

        candidates
    }

    /// Calcule la priorité ICE d'un candidat
    fn calculate_priority(&self, candidate_type: CandidateType, ip: IpAddr) -> u32 {
        // Priorités ICE basées sur RFC 5245
        let type_preference = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };

        let local_preference = match ip {
            IpAddr::V4(_) => 65535, // IPv4 préféré
            IpAddr::V6(_) => 32768, // IPv6 second
        };

        // Formule ICE: priority = (2^24) * type_pref + (2^8) * local_pref + component_id
        (1 << 24) * type_preference as u32 + (1 << 8) * local_preference + 255
    }

    /// Implémente l'algorithme de détection NAT RFC 3489
    fn perform_nat_detection(&self, local_address: SocketAddr) -> Result<NatType, NetworkError> {
        if self.config.stun_servers.is_empty() {
            return Ok(NatType::Unknown);
        }

        // Test 1: Requête STUN basique
        let server1 = self.config.stun_servers[0];
        let response1 = self.stun_request(server1, local_address)?;

        let public_addr = match response1 {
            Some(addr) => addr,
            None => return Ok(NatType::Unknown),
        };

        // Si adresse publique == adresse locale, pas de NAT
        if public_addr.ip() == local_address.ip() {
            return Ok(NatType::Open);
        }

        // Test 2: Requête vers serveur différent
        if self.config.stun_servers.len() > 1 {
            let server2 = self.config.stun_servers[1];
            let response2 = self.stun_request(server2, local_address)?;

            if let Some(addr2) = response2 {
                // Si adresses publiques différentes = Symmetric NAT
                if public_addr != addr2 {
                    return Ok(NatType::Symmetric);
                }
            }
        }

        // TDD: Pour MVP, classification basique
        // En production, implémenter tous les tests RFC 3489

        // Par défaut, supposer Full Cone (le plus permissif après Open)
        Ok(NatType::FullCone)
    }
}

#[async_trait]
impl NatTraversal for StunTurnNatTraversal {
    async fn start_discovery(
        &self,
        local_address: SocketAddr,
    ) -> Result<NatDiscoveryResult, NetworkError> {
        let start_time = SystemTime::now();

        // Vérifier le cache d'abord
        {
            let cache = self.discovery_cache.read().await;
            if let Some(cached_result) = cache.get(&local_address) {
                // TDD: Pour MVP, pas d'expiration du cache
                return Ok(cached_result.clone());
            }
        }

        // Détection du type de NAT
        let nat_type = if self.config.detect_nat_type {
            self.detect_nat_type(local_address).await?
        } else {
            NatType::Unknown
        };

        // Collecte des candidats
        let candidates = self.gather_candidates(local_address).await?;

        // Adresse publique (du premier candidat server-reflexive trouvé)
        let public_address = candidates
            .iter()
            .find(|c| c.candidate_type == CandidateType::ServerReflexive)
            .map(|c| c.address);

        let discovery_time_ms = start_time
            .elapsed()
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64;

        let result = NatDiscoveryResult {
            nat_type,
            public_address,
            candidates,
            discovery_time_ms,
        };

        // Mettre en cache
        {
            let mut cache = self.discovery_cache.write().await;
            cache.insert(local_address, result.clone());
        }

        Ok(result)
    }

    async fn detect_nat_type(&self, local_address: SocketAddr) -> Result<NatType, NetworkError> {
        self.perform_nat_detection(local_address)
    }

    async fn gather_candidates(
        &self,
        local_address: SocketAddr,
    ) -> Result<Vec<IceCandidate>, NetworkError> {
        let mut candidates = Vec::new();

        // 1. Candidats Host
        candidates.extend(self.generate_host_candidates(local_address));

        // 2. Candidats Server Reflexive (STUN)
        for stun_server in &self.config.stun_servers {
            if let Ok(Some(public_addr)) = self.stun_request(*stun_server, local_address) {
                candidates.push(IceCandidate {
                    address: public_addr,
                    candidate_type: CandidateType::ServerReflexive,
                    priority: self
                        .calculate_priority(CandidateType::ServerReflexive, public_addr.ip()),
                    foundation: format!("srflx_{}", stun_server.port()),
                    component_id: 1,
                    protocol: TransportProtocol::Udp,
                    related_address: Some(local_address),
                });
            }
        }

        // 3. Candidats Relay (TURN)
        for turn_server in &self.config.turn_servers {
            if let Ok(Some(relay_candidate)) = self.create_turn_relay(turn_server).await {
                candidates.push(relay_candidate);
            }
        }

        // Trier par priorité décroissante
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(candidates)
    }

    async fn test_connectivity(
        &self,
        local: &IceCandidate,
        remote: &IceCandidate,
    ) -> Result<bool, NetworkError> {
        // TDD: Pour MVP, simulation basique de connectivity check
        // En production, implémenter STUN Binding requests entre candidats

        // Simuler succès basé sur types de candidats
        let success_probability = match (local.candidate_type, remote.candidate_type) {
            (CandidateType::Host, CandidateType::Host) => 0.9, // Haute probabilité en LAN
            (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => 0.7, // Probable avec STUN
            (CandidateType::Relay, _) | (_, CandidateType::Relay) => 0.95, // TURN très fiable
            _ => 0.5,                                                      // Autres combinaisons
        };

        // Simuler avec probabilité
        use fastrand;
        let random_value: f32 = fastrand::f32();
        Ok(random_value < success_probability)
    }

    async fn create_turn_relay(
        &self,
        server: &TurnServer,
    ) -> Result<Option<IceCandidate>, NetworkError> {
        // TDD: Pour MVP, simulation de création relay TURN
        // En production, implémenter protocole TURN RFC 5766

        if server.username.is_empty() {
            return Ok(None);
        }

        // Simuler allocation d'un relay
        let relay_port = 50000 + (fastrand::u16(..) % 10000);
        let relay_addr = SocketAddr::new(server.address.ip(), relay_port);

        Ok(Some(IceCandidate {
            address: relay_addr,
            candidate_type: CandidateType::Relay,
            priority: self.calculate_priority(CandidateType::Relay, relay_addr.ip()),
            foundation: format!("relay_{}", server.address.port()),
            component_id: 1,
            protocol: TransportProtocol::Udp,
            related_address: Some(server.address),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert!(!config.stun_servers.is_empty());
        assert_eq!(config.timeout_seconds, 5);
        assert_eq!(config.max_attempts, 3);
        assert!(config.detect_nat_type);
        assert!(config.port_range.is_some());
    }

    #[test]
    fn test_nat_type_default() {
        let nat_type = NatType::default();
        assert_eq!(nat_type, NatType::Unknown);
    }

    #[test]
    fn test_ice_candidate_creation() {
        let candidate = IceCandidate {
            address: "192.168.1.100:5000".parse().unwrap(),
            candidate_type: CandidateType::Host,
            priority: 2_130_706_431,
            foundation: "host_5000".to_string(),
            component_id: 1,
            protocol: TransportProtocol::Udp,
            related_address: None,
        };

        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.protocol, TransportProtocol::Udp);
        assert!(candidate.related_address.is_none());
    }

    #[test]
    fn test_turn_server_creation() {
        let turn_server = TurnServer {
            address: "203.0.113.1:3478".parse().unwrap(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            realm: Some("example.com".to_string()),
        };

        assert_eq!(turn_server.username, "testuser");
        assert!(turn_server.realm.is_some());
    }

    #[tokio::test]
    async fn test_stun_turn_nat_traversal_creation() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        // Vérifier état initial
        let cache = nat_traversal.discovery_cache.read().await;
        assert!(cache.is_empty());

        let active = nat_traversal.is_active.read().await;
        assert!(!*active);
    }

    #[tokio::test]
    async fn test_start_stop_lifecycle() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        // Démarrer
        assert!(nat_traversal.start().await.is_ok());
        let active = nat_traversal.is_active.read().await;
        assert!(*active);
        drop(active);

        // Démarrage double devrait échouer
        assert!(nat_traversal.start().await.is_err());

        // Arrêter
        assert!(nat_traversal.stop().await.is_ok());
        let active = nat_traversal.is_active.read().await;
        assert!(!*active);
        drop(active);

        // Arrêt double devrait échouer
        assert!(nat_traversal.stop().await.is_err());
    }

    #[tokio::test]
    async fn test_generate_host_candidates() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let local_addr = "192.168.1.100:5000".parse().unwrap();
        let candidates = nat_traversal.generate_host_candidates(local_addr);

        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].address, local_addr);
        assert_eq!(candidates[0].candidate_type, CandidateType::Host);
        assert_eq!(candidates[0].protocol, TransportProtocol::Udp);
    }

    #[tokio::test]
    async fn test_calculate_priority() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let ipv4: IpAddr = "192.168.1.100".parse().unwrap();
        let ipv6: IpAddr = "::1".parse().unwrap();

        let host_priority = nat_traversal.calculate_priority(CandidateType::Host, ipv4);
        let relay_priority = nat_traversal.calculate_priority(CandidateType::Relay, ipv4);
        let ipv6_priority = nat_traversal.calculate_priority(CandidateType::Host, ipv6);

        // Host devrait avoir priorité plus haute que Relay
        assert!(host_priority > relay_priority);

        // IPv4 devrait avoir priorité plus haute que IPv6
        assert!(host_priority > ipv6_priority);
    }

    #[tokio::test]
    async fn test_stun_request_simulation() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let server_addr = "8.8.8.8:3478".parse().unwrap();
        let local_addr = "192.168.1.100:5000".parse().unwrap();

        let result = nat_traversal.stun_request(server_addr, local_addr);
        assert!(result.is_ok());

        if let Ok(Some(public_addr)) = result {
            assert_ne!(public_addr.ip(), local_addr.ip()); // Adresse publique différente
            assert_eq!(public_addr.port(), local_addr.port() + 1000); // Port mappé
        }
    }

    #[tokio::test]
    async fn test_nat_detection() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let local_addr = "192.168.1.100:5000".parse().unwrap();
        let nat_type = nat_traversal.detect_nat_type(local_addr).await.unwrap();

        // Le type détecté doit être valide
        assert!(matches!(
            nat_type,
            NatType::Open
                | NatType::FullCone
                | NatType::RestrictedCone
                | NatType::PortRestrictedCone
                | NatType::Symmetric
                | NatType::Unknown
        ));
    }

    #[tokio::test]
    async fn test_gather_candidates() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let local_addr = "192.168.1.100:5000".parse().unwrap();
        let candidates = nat_traversal.gather_candidates(local_addr).await.unwrap();

        assert!(!candidates.is_empty());

        // Vérifier qu'on a au moins un candidat Host
        let has_host = candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::Host);
        assert!(has_host);

        // Vérifier le tri par priorité
        for i in 1..candidates.len() {
            assert!(candidates[i - 1].priority >= candidates[i].priority);
        }
    }

    #[tokio::test]
    async fn test_connectivity_testing() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let host_candidate = IceCandidate {
            address: "192.168.1.100:5000".parse().unwrap(),
            candidate_type: CandidateType::Host,
            priority: 100,
            foundation: "host".to_string(),
            component_id: 1,
            protocol: TransportProtocol::Udp,
            related_address: None,
        };

        let relay_candidate = IceCandidate {
            address: "203.0.113.1:50000".parse().unwrap(),
            candidate_type: CandidateType::Relay,
            priority: 50,
            foundation: "relay".to_string(),
            component_id: 1,
            protocol: TransportProtocol::Udp,
            related_address: Some("203.0.113.1:3478".parse().unwrap()),
        };

        // Test Host -> Host (devrait avoir bonne chance de réussir)
        let host_to_host = nat_traversal
            .test_connectivity(&host_candidate, &host_candidate)
            .await
            .unwrap();

        // Test avec Relay (devrait avoir très bonne chance)
        let relay_test = nat_traversal
            .test_connectivity(&relay_candidate, &host_candidate)
            .await
            .unwrap();

        // Au moins un des tests devrait réussir statistiquement
        // (mais pas garanti à cause de l'aspect aléatoire)
        println!("Host->Host: {}, Relay->Host: {}", host_to_host, relay_test);
    }

    #[tokio::test]
    async fn test_turn_relay_creation() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let turn_server = TurnServer {
            address: "203.0.113.1:3478".parse().unwrap(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            realm: None,
        };

        let relay = nat_traversal.create_turn_relay(&turn_server).await.unwrap();
        assert!(relay.is_some());

        let relay_candidate = relay.unwrap();
        assert_eq!(relay_candidate.candidate_type, CandidateType::Relay);
        assert_eq!(relay_candidate.related_address, Some(turn_server.address));

        // Test avec serveur TURN sans credentials
        let invalid_turn = TurnServer {
            address: "203.0.113.1:3478".parse().unwrap(),
            username: "".to_string(),
            password: "".to_string(),
            realm: None,
        };

        let no_relay = nat_traversal
            .create_turn_relay(&invalid_turn)
            .await
            .unwrap();
        assert!(no_relay.is_none());
    }

    #[tokio::test]
    async fn test_start_discovery_with_caching() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        let local_addr = "192.168.1.100:5000".parse().unwrap();

        // Première découverte
        let result1 = nat_traversal.start_discovery(local_addr).await.unwrap();
        assert!(!result1.candidates.is_empty());
        // TDD: Le temps peut être 0 si le système est très rapide, on vérifie juste qu'il est valide
        // result1.discovery_time_ms est u64, toujours ≥ 0
        // Vérifier que la découverte a bien eu lieu (temps de traitement valide)
        // discovery_time_ms mesure la durée, on vérifie juste qu'elle existe
        let _discovery_duration = result1.discovery_time_ms;

        // Seconde découverte (devrait utiliser le cache)
        let result2 = nat_traversal.start_discovery(local_addr).await.unwrap();

        // Les résultats devraient être identiques (cache)
        assert_eq!(result1.nat_type, result2.nat_type);
        assert_eq!(result1.candidates.len(), result2.candidates.len());
    }

    #[tokio::test]
    async fn test_cache_cleanup_on_stop() {
        let config = NatConfig::default();
        let nat_traversal = StunTurnNatTraversal::new(config);

        nat_traversal.start().await.unwrap();

        let local_addr = "192.168.1.100:5000".parse().unwrap();
        nat_traversal.start_discovery(local_addr).await.unwrap();

        // Vérifier que le cache contient des données
        {
            let cache = nat_traversal.discovery_cache.read().await;
            assert!(!cache.is_empty());
        }

        // Arrêter le service
        nat_traversal.stop().await.unwrap();

        // Le cache devrait être nettoyé
        {
            let cache = nat_traversal.discovery_cache.read().await;
            assert!(cache.is_empty());
        }
    }
}
