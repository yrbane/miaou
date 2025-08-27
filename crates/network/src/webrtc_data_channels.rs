//! Module WebRTC Data Channels pour communication P2P temps réel
//!
//! TDD: Tests écrits AVANT implémentation  
//! Architecture SOLID : Gestion WebRTC avec ICE et Data Channels

use crate::{IceCandidate, NatConfig, NatTraversal, NetworkError, PeerId, StunTurnNatTraversal};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// État d'une connexion WebRTC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Nouvelle connexion
    New,
    /// Connexion en cours d'établissement
    Connecting,
    /// ICE gathering en cours
    Gathering,
    /// Connexion établie avec succès
    Connected,
    /// Connexion fermée proprement
    Closed,
    /// Connexion échouée
    Failed,
    /// Connexion déconnectée (récupérable)
    Disconnected,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::New
    }
}

/// Type de données transmises sur le Data Channel
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataChannelMessageType {
    /// Message texte
    Text,
    /// Données binaires
    Binary,
    /// Message de contrôle (ping, pong, etc.)
    Control,
    /// Message chiffré E2E
    Encrypted,
}

/// Message transmis via Data Channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataChannelMessage {
    /// ID unique du message
    pub id: String,
    /// ID de l'expéditeur
    pub from: PeerId,
    /// ID du destinataire
    pub to: PeerId,
    /// Type de message
    pub message_type: DataChannelMessageType,
    /// Payload du message
    pub payload: Vec<u8>,
    /// Timestamp de création
    pub timestamp: u64,
    /// Métadonnées optionnelles
    pub metadata: HashMap<String, String>,
}

impl DataChannelMessage {
    /// Crée un nouveau message
    pub fn new(
        from: PeerId,
        to: PeerId,
        message_type: DataChannelMessageType,
        payload: Vec<u8>,
    ) -> Self {
        let id = format!(
            "dc_{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            fastrand::u32(..)
        );

        Self {
            id,
            from,
            to,
            message_type,
            payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: HashMap::new(),
        }
    }

    /// Crée un message texte
    pub fn text(from: PeerId, to: PeerId, text: &str) -> Self {
        Self::new(
            from,
            to,
            DataChannelMessageType::Text,
            text.as_bytes().to_vec(),
        )
    }

    /// Crée un message binaire
    pub fn binary(from: PeerId, to: PeerId, data: Vec<u8>) -> Self {
        Self::new(from, to, DataChannelMessageType::Binary, data)
    }

    /// Crée un message de contrôle
    pub fn control(from: PeerId, to: PeerId, command: &str) -> Self {
        Self::new(
            from,
            to,
            DataChannelMessageType::Control,
            command.as_bytes().to_vec(),
        )
    }

    /// Récupère le contenu comme texte
    pub fn as_text(&self) -> Result<String, NetworkError> {
        String::from_utf8(self.payload.clone())
            .map_err(|e| NetworkError::General(format!("Invalid UTF-8: {}", e)))
    }

    /// Sérialise le message pour transmission
    pub fn serialize(&self) -> Result<Vec<u8>, NetworkError> {
        bincode::serialize(self).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Désérialise un message reçu
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        bincode::deserialize(data).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }
}

/// Configuration WebRTC Data Channel
#[derive(Debug, Clone)]
pub struct DataChannelConfig {
    /// Nom du data channel
    pub label: String,
    /// Canal ordonné (TCP-like) ou non (UDP-like)
    pub ordered: bool,
    /// Nombre maximum de retransmissions
    pub max_retransmits: Option<u16>,
    /// Timeout de retransmission en ms
    pub max_packet_life_time: Option<u16>,
    /// Protocole utilisé
    pub protocol: String,
    /// Buffer size pour les messages
    pub buffer_size: usize,
}

impl Default for DataChannelConfig {
    fn default() -> Self {
        Self {
            label: "miaou-datachannel".to_string(),
            ordered: true, // TCP-like pour fiabilité
            max_retransmits: Some(5),
            max_packet_life_time: None,
            protocol: "miaou/0.2.0".to_string(),
            buffer_size: 65536, // 64KB buffer
        }
    }
}

/// Configuration de connexion WebRTC
#[derive(Debug, Clone)]
pub struct WebRtcConnectionConfig {
    /// Configuration NAT traversal
    pub nat_config: NatConfig,
    /// Configuration Data Channel
    pub datachannel_config: DataChannelConfig,
    /// Timeout pour l'établissement de connexion (secondes)
    pub connection_timeout_seconds: u64,
    /// Timeout pour ICE gathering (secondes)
    pub ice_gathering_timeout_seconds: u64,
    /// Garder la connexion active avec des pings
    pub enable_keepalive: bool,
    /// Intervalle de keepalive (secondes)
    pub keepalive_interval_seconds: u64,
}

impl Default for WebRtcConnectionConfig {
    fn default() -> Self {
        Self {
            nat_config: NatConfig::default(),
            datachannel_config: DataChannelConfig::default(),
            connection_timeout_seconds: 30,
            ice_gathering_timeout_seconds: 10,
            enable_keepalive: true,
            keepalive_interval_seconds: 30,
        }
    }
}

/// Informations sur une connexion WebRTC active
#[derive(Debug, Clone)]
pub struct WebRtcConnection {
    /// ID de la connexion
    pub connection_id: String,
    /// Pair connecté
    pub peer_id: PeerId,
    /// État de la connexion
    pub state: ConnectionState,
    /// Adresse négociée
    pub negotiated_address: Option<SocketAddr>,
    /// Candidats ICE utilisés
    pub local_candidate: Option<IceCandidate>,
    /// Candidat ICE distant (si disponible)
    pub remote_candidate: Option<IceCandidate>,
    /// Timestamp de connexion
    pub connected_at: Option<u64>,
    /// Statistiques de transfert
    pub bytes_sent: u64,
    /// Nombre de bytes reçus
    pub bytes_received: u64,
    /// Nombre de messages envoyés
    pub messages_sent: u64,
    /// Nombre de messages reçus
    pub messages_received: u64,
}

impl WebRtcConnection {
    /// Crée une nouvelle connexion
    pub fn new(connection_id: String, peer_id: PeerId) -> Self {
        Self {
            connection_id,
            peer_id,
            state: ConnectionState::New,
            negotiated_address: None,
            local_candidate: None,
            remote_candidate: None,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// Marque la connexion comme connectée
    pub fn mark_connected(&mut self, local: IceCandidate, remote: IceCandidate) {
        self.state = ConnectionState::Connected;
        self.local_candidate = Some(local);
        self.remote_candidate = Some(remote);
        self.connected_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    }

    /// Met à jour les statistiques d'envoi
    pub fn update_send_stats(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.messages_sent += 1;
    }

    /// Met à jour les statistiques de réception
    pub fn update_receive_stats(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.messages_received += 1;
    }

    /// Vérifie si la connexion est active
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Connected
    }
}

/// Trait pour gestionnaire WebRTC Data Channels
#[async_trait]
pub trait WebRtcDataChannels: Send + Sync {
    /// Démarre le gestionnaire WebRTC
    async fn start(&mut self) -> Result<(), NetworkError>;

    /// Arrête le gestionnaire WebRTC
    async fn stop(&mut self) -> Result<(), NetworkError>;

    /// Initie une connexion vers un pair
    async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        remote_address: SocketAddr,
    ) -> Result<String, NetworkError>;

    /// Accepte une connexion entrante
    async fn accept_connection(&self, connection_id: &str) -> Result<(), NetworkError>;

    /// Envoie un message via Data Channel
    async fn send_message(
        &self,
        connection_id: &str,
        message: DataChannelMessage,
    ) -> Result<(), NetworkError>;

    /// Ferme une connexion
    async fn close_connection(&self, connection_id: &str) -> Result<(), NetworkError>;

    /// Liste les connexions actives
    async fn list_connections(&self) -> Vec<WebRtcConnection>;

    /// Récupère une connexion par ID
    async fn get_connection(&self, connection_id: &str) -> Option<WebRtcConnection>;

    /// Canal de réception des messages
    fn message_receiver(&self) -> mpsc::UnboundedReceiver<DataChannelMessage>;
}

/// Gestionnaire WebRTC avec support ICE et Data Channels
pub struct WebRtcDataChannelManager {
    /// Configuration
    config: WebRtcConnectionConfig,
    /// ID local du pair
    local_peer_id: PeerId,
    /// Gestionnaire NAT traversal
    nat_traversal: Arc<StunTurnNatTraversal>,
    /// Connexions actives (par ID de connexion)
    connections: Arc<RwLock<HashMap<String, WebRtcConnection>>>,
    /// Canal pour les messages entrants
    message_sender: mpsc::UnboundedSender<DataChannelMessage>,
    message_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<DataChannelMessage>>>>,
    /// État du gestionnaire
    is_running: Arc<RwLock<bool>>,
}

impl WebRtcDataChannelManager {
    /// Crée un nouveau gestionnaire WebRTC
    pub fn new(config: WebRtcConnectionConfig, local_peer_id: PeerId) -> Self {
        let nat_traversal = Arc::new(StunTurnNatTraversal::new(config.nat_config.clone()));
        let (message_sender, message_receiver) = mpsc::unbounded_channel();

        Self {
            config,
            local_peer_id,
            nat_traversal,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_sender,
            message_receiver: Arc::new(Mutex::new(Some(message_receiver))),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Génère un ID unique pour une connexion
    fn generate_connection_id(&self, peer_id: &PeerId) -> String {
        format!(
            "webrtc_{}_{}_{}",
            self.local_peer_id.short(),
            peer_id.short(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        )
    }

    /// Négocie ICE candidates avec un pair
    async fn negotiate_ice_candidates(
        &self,
        peer_id: &PeerId,
        remote_addr: SocketAddr,
    ) -> Result<(IceCandidate, IceCandidate), NetworkError> {
        info!("🧊 Négociation ICE avec pair {}", peer_id.short());

        // Démarrer la découverte NAT pour notre adresse locale
        let local_addr = SocketAddr::new("0.0.0.0".parse().unwrap(), 0); // Bind n'importe quel port
        let discovery_result = self.nat_traversal.start_discovery(local_addr).await?;

        if discovery_result.candidates.is_empty() {
            return Err(NetworkError::General(
                "Aucun candidat ICE local trouvé".to_string(),
            ));
        }

        // Sélectionner notre meilleur candidat (priorité la plus haute)
        let local_candidate = discovery_result.candidates[0].clone();

        // TDD: Pour MVP, simuler un candidat distant basé sur l'adresse fournie
        // En production, récupérer via signaling server
        let remote_candidate = IceCandidate {
            address: remote_addr,
            candidate_type: crate::CandidateType::Host,
            priority: 100,
            foundation: "remote_host".to_string(),
            component_id: 1,
            protocol: crate::TransportProtocol::Udp,
            related_address: None,
        };

        // Tester la connectivité
        let connectivity_ok = self
            .nat_traversal
            .test_connectivity(&local_candidate, &remote_candidate)
            .await?;

        if !connectivity_ok {
            warn!("⚠️  Connectivity check échoué entre candidats ICE");
            return Err(NetworkError::General(
                "Connectivity check échoué".to_string(),
            ));
        }

        info!("✅ ICE candidates négociés avec succès");
        Ok((local_candidate, remote_candidate))
    }

    /// Établit un Data Channel WebRTC (simulation pour MVP)
    async fn establish_datachannel(
        &self,
        connection_id: &str,
        local: &IceCandidate,
        remote: &IceCandidate,
    ) -> Result<(), NetworkError> {
        info!(
            "📡 Établissement Data Channel pour connexion {}",
            connection_id
        );

        // TDD: Pour MVP, simuler l'établissement réussi
        // En production, utiliser la crate webrtc-rs pour créer une vraie connexion

        // Simuler temps d'établissement
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Vérifier que les candidats sont valides
        if local.address.port() == 0 || remote.address.port() == 0 {
            return Err(NetworkError::General("Candidats ICE invalides".to_string()));
        }

        info!(
            "✅ Data Channel établi : {} <-> {}",
            local.address, remote.address
        );
        Ok(())
    }

    /// Simule l'envoi d'un message via WebRTC (MVP)
    async fn send_via_datachannel(
        &self,
        connection: &mut WebRtcConnection,
        message: &DataChannelMessage,
    ) -> Result<(), NetworkError> {
        debug!(
            "📤 Envoi message via Data Channel: {} -> {}",
            message.from.short(),
            message.to.short()
        );

        // Sérialiser le message
        let serialized = message.serialize()?;

        // TDD: Pour MVP, simuler envoi réussi
        // En production, utiliser webrtc Data Channel send()

        // Simuler latence réseau
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Mettre à jour les stats
        connection.update_send_stats(serialized.len() as u64);

        debug!("✅ Message envoyé ({} bytes)", serialized.len());
        Ok(())
    }

    /// Simule la réception de messages (MVP)
    async fn simulate_message_reception(
        &self,
        connection_id: &str,
        peer_id: &PeerId,
    ) -> Result<(), NetworkError> {
        // TDD: Pour MVP, simuler périodiquement des messages entrants pour les tests
        // En production, écouter les vraies Data Channel events

        let sender = self.message_sender.clone();
        let peer_id = peer_id.clone();
        let local_peer_id = self.local_peer_id.clone();
        let _connection_id = connection_id.to_string();

        tokio::spawn(async move {
            // Simuler un message de test après une seconde
            tokio::time::sleep(Duration::from_secs(1)).await;

            let test_message =
                DataChannelMessage::text(peer_id.clone(), local_peer_id, "Hello from WebRTC!");

            if let Err(e) = sender.send(test_message) {
                debug!("Erreur envoi message simulé: {}", e);
            }
        });

        Ok(())
    }

    /// Retourne la configuration du manager
    pub fn config(&self) -> &WebRtcConnectionConfig {
        &self.config
    }
}

#[async_trait]
impl WebRtcDataChannels for WebRtcDataChannelManager {
    async fn start(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(NetworkError::General(
                "WebRTC gestionnaire déjà actif".to_string(),
            ));
        }
        *running = true;

        // Démarrer NAT traversal
        self.nat_traversal.start().await?;

        info!("🚀 WebRTC Data Channels gestionnaire démarré");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.write().await;
        if !*running {
            return Err(NetworkError::General(
                "WebRTC gestionnaire non actif".to_string(),
            ));
        }
        *running = false;

        // Fermer toutes les connexions
        let connection_ids: Vec<String> = {
            let connections = self.connections.read().await;
            connections.keys().cloned().collect()
        };

        for connection_id in connection_ids {
            if let Err(e) = self.close_connection(&connection_id).await {
                warn!("Erreur fermeture connexion {}: {}", connection_id, e);
            }
        }

        // Arrêter NAT traversal
        let nat = Arc::get_mut(&mut self.nat_traversal)
            .ok_or_else(|| NetworkError::General("NAT traversal lock error".to_string()))?;
        nat.stop().await?;

        info!("🛑 WebRTC Data Channels gestionnaire arrêté");
        Ok(())
    }

    async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        remote_address: SocketAddr,
    ) -> Result<String, NetworkError> {
        let running = self.is_running.read().await;
        if !*running {
            return Err(NetworkError::General(
                "WebRTC gestionnaire non actif".to_string(),
            ));
        }
        drop(running);

        info!(
            "🔗 Connexion WebRTC vers pair {} ({})",
            peer_id.short(),
            remote_address
        );

        // Générer ID de connexion
        let connection_id = self.generate_connection_id(&peer_id);

        // Créer l'objet connexion
        let mut connection = WebRtcConnection::new(connection_id.clone(), peer_id.clone());
        connection.state = ConnectionState::Connecting;

        // Ajouter aux connexions actives
        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id.clone(), connection.clone());
        }

        // Négocier ICE candidates
        let (local_candidate, remote_candidate) = match self
            .negotiate_ice_candidates(&peer_id, remote_address)
            .await
        {
            Ok(candidates) => candidates,
            Err(e) => {
                // Marquer connexion comme échouée
                let mut connections = self.connections.write().await;
                if let Some(conn) = connections.get_mut(&connection_id) {
                    conn.state = ConnectionState::Failed;
                }
                return Err(e);
            }
        };

        // Établir Data Channel
        if let Err(e) = self
            .establish_datachannel(&connection_id, &local_candidate, &remote_candidate)
            .await
        {
            // Marquer connexion comme échouée
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(&connection_id) {
                conn.state = ConnectionState::Failed;
            }
            return Err(e);
        }

        // Marquer connexion comme réussie
        {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(&connection_id) {
                conn.mark_connected(local_candidate, remote_candidate);
            }
        }

        // Démarrer simulation de réception de messages
        self.simulate_message_reception(&connection_id, &peer_id)
            .await?;

        info!("✅ Connexion WebRTC établie: {}", connection_id);
        Ok(connection_id)
    }

    async fn accept_connection(&self, connection_id: &str) -> Result<(), NetworkError> {
        info!(
            "📨 Acceptation connexion WebRTC entrante: {}",
            connection_id
        );

        let mut connections = self.connections.write().await;

        if let Some(connection) = connections.get_mut(connection_id) {
            if connection.state == ConnectionState::New {
                connection.state = ConnectionState::Connected;
                info!("✅ Connexion acceptée: {}", connection_id);
                Ok(())
            } else {
                Err(NetworkError::General(
                    "Connexion pas dans l'état correct pour acceptation".to_string(),
                ))
            }
        } else {
            Err(NetworkError::General("Connexion non trouvée".to_string()))
        }
    }

    async fn send_message(
        &self,
        connection_id: &str,
        message: DataChannelMessage,
    ) -> Result<(), NetworkError> {
        let mut connections = self.connections.write().await;

        if let Some(connection) = connections.get_mut(connection_id) {
            if !connection.is_active() {
                return Err(NetworkError::General("Connexion non active".to_string()));
            }

            self.send_via_datachannel(connection, &message).await?;
            Ok(())
        } else {
            Err(NetworkError::General("Connexion non trouvée".to_string()))
        }
    }

    async fn close_connection(&self, connection_id: &str) -> Result<(), NetworkError> {
        info!("🔒 Fermeture connexion WebRTC: {}", connection_id);

        let mut connections = self.connections.write().await;

        if let Some(connection) = connections.get_mut(connection_id) {
            connection.state = ConnectionState::Closed;
            info!("✅ Connexion fermée: {}", connection_id);
            Ok(())
        } else {
            Err(NetworkError::General("Connexion non trouvée".to_string()))
        }
    }

    async fn list_connections(&self) -> Vec<WebRtcConnection> {
        let connections = self.connections.read().await;
        connections.values().cloned().collect()
    }

    async fn get_connection(&self, connection_id: &str) -> Option<WebRtcConnection> {
        let connections = self.connections.read().await;
        connections.get(connection_id).cloned()
    }

    fn message_receiver(&self) -> mpsc::UnboundedReceiver<DataChannelMessage> {
        let mut receiver_guard = self.message_receiver.lock().unwrap();
        receiver_guard.take().expect("Message receiver déjà pris")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        assert_eq!(ConnectionState::default(), ConnectionState::New);
    }

    #[test]
    fn test_datachannel_message_creation() {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());

        let msg = DataChannelMessage::text(from.clone(), to.clone(), "Hello WebRTC!");

        assert_eq!(msg.from, from);
        assert_eq!(msg.to, to);
        assert_eq!(msg.message_type, DataChannelMessageType::Text);
        assert!(!msg.id.is_empty());
        assert!(msg.timestamp > 0);

        let text = msg.as_text().unwrap();
        assert_eq!(text, "Hello WebRTC!");
    }

    #[test]
    fn test_datachannel_message_binary() {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());
        let data = vec![1, 2, 3, 4, 5];

        let msg = DataChannelMessage::binary(from.clone(), to.clone(), data.clone());

        assert_eq!(msg.message_type, DataChannelMessageType::Binary);
        assert_eq!(msg.payload, data);
    }

    #[test]
    fn test_datachannel_message_control() {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());

        let msg = DataChannelMessage::control(from.clone(), to.clone(), "PING");

        assert_eq!(msg.message_type, DataChannelMessageType::Control);
        assert_eq!(msg.as_text().unwrap(), "PING");
    }

    #[test]
    fn test_datachannel_message_serialization() {
        let from = PeerId::from_bytes(b"alice".to_vec());
        let to = PeerId::from_bytes(b"bob".to_vec());

        let original = DataChannelMessage::text(from, to, "Serialize test");
        let serialized = original.serialize().unwrap();
        let deserialized = DataChannelMessage::deserialize(&serialized).unwrap();

        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.from, deserialized.from);
        assert_eq!(original.to, deserialized.to);
        assert_eq!(original.message_type, deserialized.message_type);
        assert_eq!(original.payload, deserialized.payload);
    }

    #[test]
    fn test_datachannel_config_default() {
        let config = DataChannelConfig::default();

        assert_eq!(config.label, "miaou-datachannel");
        assert!(config.ordered);
        assert_eq!(config.max_retransmits, Some(5));
        assert_eq!(config.protocol, "miaou/0.2.0");
        assert_eq!(config.buffer_size, 65536);
    }

    #[test]
    fn test_webrtc_connection_config_default() {
        let config = WebRtcConnectionConfig::default();

        assert_eq!(config.connection_timeout_seconds, 30);
        assert_eq!(config.ice_gathering_timeout_seconds, 10);
        assert!(config.enable_keepalive);
        assert_eq!(config.keepalive_interval_seconds, 30);
    }

    #[test]
    fn test_webrtc_connection_creation() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let connection_id = "test_conn_123".to_string();

        let conn = WebRtcConnection::new(connection_id.clone(), peer_id.clone());

        assert_eq!(conn.connection_id, connection_id);
        assert_eq!(conn.peer_id, peer_id);
        assert_eq!(conn.state, ConnectionState::New);
        assert!(conn.negotiated_address.is_none());
        assert!(conn.connected_at.is_none());
        assert!(!conn.is_active());
    }

    #[test]
    fn test_webrtc_connection_mark_connected() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let mut conn = WebRtcConnection::new("test_conn".to_string(), peer_id);

        let local = IceCandidate {
            address: "192.168.1.100:5000".parse().unwrap(),
            candidate_type: crate::CandidateType::Host,
            priority: 100,
            foundation: "local".to_string(),
            component_id: 1,
            protocol: crate::TransportProtocol::Udp,
            related_address: None,
        };

        let remote = IceCandidate {
            address: "203.0.113.1:6000".parse().unwrap(),
            candidate_type: crate::CandidateType::ServerReflexive,
            priority: 80,
            foundation: "remote".to_string(),
            component_id: 1,
            protocol: crate::TransportProtocol::Udp,
            related_address: None,
        };

        conn.mark_connected(local.clone(), remote.clone());

        assert_eq!(conn.state, ConnectionState::Connected);
        assert_eq!(conn.local_candidate, Some(local));
        assert_eq!(conn.remote_candidate, Some(remote));
        assert!(conn.connected_at.is_some());
        assert!(conn.is_active());
    }

    #[test]
    fn test_webrtc_connection_stats_update() {
        let peer_id = PeerId::from_bytes(b"test_peer".to_vec());
        let mut conn = WebRtcConnection::new("test_conn".to_string(), peer_id);

        conn.update_send_stats(1024);
        assert_eq!(conn.bytes_sent, 1024);
        assert_eq!(conn.messages_sent, 1);

        conn.update_receive_stats(2048);
        assert_eq!(conn.bytes_received, 2048);
        assert_eq!(conn.messages_received, 1);

        conn.update_send_stats(512);
        assert_eq!(conn.bytes_sent, 1536); // 1024 + 512
        assert_eq!(conn.messages_sent, 2);
    }

    #[tokio::test]
    async fn test_webrtc_manager_creation() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer.clone());

        assert_eq!(manager.local_peer_id, local_peer);

        let running = manager.is_running.read().await;
        assert!(!*running);

        let connections = manager.connections.read().await;
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn test_webrtc_manager_start_stop() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let mut manager = WebRtcDataChannelManager::new(config, local_peer);

        // Démarrer
        assert!(manager.start().await.is_ok());
        let running = manager.is_running.read().await;
        assert!(*running);
        drop(running);

        // Double start devrait échouer
        assert!(manager.start().await.is_err());

        // Arrêter
        assert!(manager.stop().await.is_ok());
        let running = manager.is_running.read().await;
        assert!(!*running);
        drop(running);

        // Double stop devrait échouer
        assert!(manager.stop().await.is_err());
    }

    #[test]
    fn test_generate_connection_id() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer.clone());

        let conn_id = manager.generate_connection_id(&remote_peer);

        assert!(conn_id.starts_with("webrtc_"));
        assert!(conn_id.contains(&local_peer.short()));
        assert!(conn_id.contains(&remote_peer.short()));
    }

    #[tokio::test]
    async fn test_webrtc_manager_list_connections_empty() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        let connections = manager.list_connections().await;
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn test_webrtc_manager_get_connection_not_found() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        let connection = manager.get_connection("non_existent").await;
        assert!(connection.is_none());
    }

    #[tokio::test]
    async fn test_close_connection_not_found() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        let result = manager.close_connection("non_existent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_message_connection_not_found() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer.clone());

        let message = DataChannelMessage::text(local_peer, remote_peer, "test");
        let result = manager.send_message("non_existent", message).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_accept_connection_not_found() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        let result = manager.accept_connection("non_existent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_operations_when_not_running() {
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_peer".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote_peer".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        // Manager pas démarré - connect_to_peer devrait échouer
        let remote_addr = "203.0.113.1:8080".parse().unwrap();
        let result = manager.connect_to_peer(remote_peer, remote_addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_webrtc_message_receiver() {
        // TDD: Test récupération du receiver de messages
        let config = WebRtcConnectionConfig::default();
        let local_peer = PeerId::from_bytes(b"local_receiver".to_vec());

        let manager = WebRtcDataChannelManager::new(config, local_peer);

        // Récupérer le receiver - devrait réussir une fois
        let _receiver = manager.message_receiver();

        // La deuxième tentative devrait paniquer car déjà pris
        // On ne peut pas tester le panic facilement, mais le receiver est pris
    }

    #[tokio::test]
    async fn test_webrtc_connection_establishment_with_valid_ice_candidates() {
        // TDD: Test établissement connexion avec candidats ICE manuels
        let mut config = WebRtcConnectionConfig::default();
        config.ice_gathering_timeout_seconds = 1; // Réduit pour test rapide

        let local_peer = PeerId::from_bytes(b"local_valid_ice".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote_valid_ice".to_vec());

        let mut manager = WebRtcDataChannelManager::new(config, local_peer.clone());

        // Démarrer le manager
        assert!(manager.start().await.is_ok());

        // Tenter une connexion (peut échouer avec ICE invalides en mode simulation)
        let remote_addr = "198.51.100.10:9000".parse().unwrap();
        let result = manager
            .connect_to_peer(remote_peer.clone(), remote_addr)
            .await;

        // Vérifier qu'au moins une tentative de connexion a été faite
        let connections = manager.list_connections().await;

        match result {
            Ok(connection_id) => {
                // Connexion réussie
                assert!(!connection_id.is_empty());
                assert_eq!(connections.len(), 1);
                assert_eq!(connections[0].peer_id, remote_peer);
            }
            Err(e) => {
                // Échec attendu avec simulation ICE
                assert!(
                    e.to_string().contains("Candidats ICE invalides")
                        || e.to_string().contains("Connectivity check échoué")
                );

                // Une connexion échouée peut être listée mais pas active
                if !connections.is_empty() {
                    assert!(!connections[0].is_active());
                }
            }
        }

        assert!(manager.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_webrtc_message_metadata() {
        // TDD: Test métadonnées des messages
        let alice = PeerId::from_bytes(b"alice_meta".to_vec());
        let bob = PeerId::from_bytes(b"bob_meta".to_vec());

        let mut message =
            DataChannelMessage::text(alice.clone(), bob.clone(), "Hello with metadata");

        // Ajouter des métadonnées
        message
            .metadata
            .insert("priority".to_string(), "high".to_string());
        message
            .metadata
            .insert("app_version".to_string(), "1.0.0".to_string());

        assert_eq!(message.metadata.get("priority"), Some(&"high".to_string()));
        assert_eq!(
            message.metadata.get("app_version"),
            Some(&"1.0.0".to_string())
        );

        // Test sérialisation avec métadonnées
        let serialized = message.serialize().unwrap();
        let deserialized = DataChannelMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.metadata.len(), 2);
        assert_eq!(
            deserialized.metadata.get("priority"),
            Some(&"high".to_string())
        );
        assert_eq!(
            deserialized.metadata.get("app_version"),
            Some(&"1.0.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_webrtc_message_types_comprehensive() {
        // TDD: Test complet de tous les types de messages
        let alice = PeerId::from_bytes(b"alice_types".to_vec());
        let bob = PeerId::from_bytes(b"bob_types".to_vec());

        // Message texte
        let text_msg = DataChannelMessage::text(alice.clone(), bob.clone(), "Plain text");
        assert_eq!(text_msg.message_type, DataChannelMessageType::Text);
        assert_eq!(text_msg.as_text().unwrap(), "Plain text");

        // Message binaire
        let binary_data = vec![0x01, 0x02, 0x03, 0x04];
        let binary_msg =
            DataChannelMessage::binary(alice.clone(), bob.clone(), binary_data.clone());
        assert_eq!(binary_msg.message_type, DataChannelMessageType::Binary);
        assert_eq!(binary_msg.payload, binary_data);

        // Message de contrôle
        let control_msg = DataChannelMessage::control(alice.clone(), bob.clone(), "PING");
        assert_eq!(control_msg.message_type, DataChannelMessageType::Control);
        assert_eq!(control_msg.as_text().unwrap(), "PING");

        // Message chiffré (structure)
        let mut encrypted_msg = DataChannelMessage::new(
            alice,
            bob,
            DataChannelMessageType::Encrypted,
            vec![0xFF, 0xFE, 0xFD],
        );
        encrypted_msg.message_type = DataChannelMessageType::Encrypted;
        assert_eq!(
            encrypted_msg.message_type,
            DataChannelMessageType::Encrypted
        );
    }

    #[tokio::test]
    async fn test_webrtc_connection_statistics_detailed() {
        // TDD: Test détaillé des statistiques de connexion
        let peer_id = PeerId::from_bytes(b"stats_peer".to_vec());
        let mut connection = WebRtcConnection::new("stats_conn_123".to_string(), peer_id.clone());

        // État initial
        assert_eq!(connection.bytes_sent, 0);
        assert_eq!(connection.bytes_received, 0);
        assert_eq!(connection.messages_sent, 0);
        assert_eq!(connection.messages_received, 0);
        assert!(connection.connected_at.is_none());

        // Simuler plusieurs envois
        connection.update_send_stats(100);
        connection.update_send_stats(250);
        connection.update_send_stats(50);

        assert_eq!(connection.bytes_sent, 400); // 100 + 250 + 50
        assert_eq!(connection.messages_sent, 3);

        // Simuler plusieurs réceptions
        connection.update_receive_stats(300);
        connection.update_receive_stats(200);

        assert_eq!(connection.bytes_received, 500); // 300 + 200
        assert_eq!(connection.messages_received, 2);

        // Test mark_connected
        let local_candidate = IceCandidate {
            address: "192.168.1.100:5000".parse().unwrap(),
            candidate_type: crate::CandidateType::Host,
            priority: 100,
            foundation: "local_foundation".to_string(),
            component_id: 1,
            protocol: crate::TransportProtocol::Udp,
            related_address: None,
        };

        let remote_candidate = IceCandidate {
            address: "203.0.113.50:6000".parse().unwrap(),
            candidate_type: crate::CandidateType::ServerReflexive,
            priority: 80,
            foundation: "remote_foundation".to_string(),
            component_id: 1,
            protocol: crate::TransportProtocol::Udp,
            related_address: None,
        };

        connection.mark_connected(local_candidate.clone(), remote_candidate.clone());

        assert!(connection.is_active());
        assert_eq!(connection.state, ConnectionState::Connected);
        assert_eq!(connection.local_candidate, Some(local_candidate));
        assert_eq!(connection.remote_candidate, Some(remote_candidate));
        assert!(connection.connected_at.is_some());
    }

    #[tokio::test]
    async fn test_webrtc_connection_states() {
        // TDD: Test transitions d'états de connexion
        let peer_id = PeerId::from_bytes(b"state_peer".to_vec());
        let mut connection = WebRtcConnection::new("state_conn".to_string(), peer_id);

        // État initial
        assert_eq!(connection.state, ConnectionState::New);
        assert!(!connection.is_active());

        // Simuler différents états
        connection.state = ConnectionState::Connecting;
        assert!(!connection.is_active());

        connection.state = ConnectionState::Gathering;
        assert!(!connection.is_active());

        connection.state = ConnectionState::Connected;
        assert!(connection.is_active());

        connection.state = ConnectionState::Disconnected;
        assert!(!connection.is_active());

        connection.state = ConnectionState::Failed;
        assert!(!connection.is_active());

        connection.state = ConnectionState::Closed;
        assert!(!connection.is_active());
    }

    #[tokio::test]
    async fn test_webrtc_data_channel_config_customization() {
        // TDD: Test personnalisation config data channel
        let mut config = DataChannelConfig::default();

        // Modifier la configuration
        config.label = "custom-channel".to_string();
        config.ordered = false;
        config.max_retransmits = Some(10);
        config.max_packet_life_time = Some(5000);
        config.protocol = "custom/1.0".to_string();
        config.buffer_size = 32768;

        assert_eq!(config.label, "custom-channel");
        assert!(!config.ordered);
        assert_eq!(config.max_retransmits, Some(10));
        assert_eq!(config.max_packet_life_time, Some(5000));
        assert_eq!(config.protocol, "custom/1.0");
        assert_eq!(config.buffer_size, 32768);
    }

    #[tokio::test]
    async fn test_webrtc_connection_config_timeouts() {
        // TDD: Test configuration des timeouts
        let mut config = WebRtcConnectionConfig::default();

        // Modifier les timeouts
        config.connection_timeout_seconds = 60;
        config.ice_gathering_timeout_seconds = 15;
        config.enable_keepalive = false;
        config.keepalive_interval_seconds = 60;

        assert_eq!(config.connection_timeout_seconds, 60);
        assert_eq!(config.ice_gathering_timeout_seconds, 15);
        assert!(!config.enable_keepalive);
        assert_eq!(config.keepalive_interval_seconds, 60);

        // Créer un manager avec cette config
        let local_peer = PeerId::from_bytes(b"timeout_peer".to_vec());
        let manager = WebRtcDataChannelManager::new(config, local_peer);

        // Le manager devrait utiliser la config personnalisée
        assert_eq!(manager.config.connection_timeout_seconds, 60);
        assert_eq!(manager.config.ice_gathering_timeout_seconds, 15);
    }

    #[tokio::test]
    async fn test_webrtc_message_id_uniqueness() {
        // TDD: Test unicité des IDs de messages
        let alice = PeerId::from_bytes(b"alice_unique".to_vec());
        let bob = PeerId::from_bytes(b"bob_unique".to_vec());

        let mut message_ids = std::collections::HashSet::new();

        // Créer plusieurs messages et vérifier l'unicité des IDs
        for i in 0..100 {
            let msg =
                DataChannelMessage::text(alice.clone(), bob.clone(), &format!("Message {}", i));
            assert!(
                message_ids.insert(msg.id.clone()),
                "Message ID should be unique: {}",
                msg.id
            );
        }

        assert_eq!(message_ids.len(), 100);
    }

    #[tokio::test]
    async fn test_webrtc_message_serialization_error_handling() {
        // TDD: Test gestion erreurs de sérialisation
        // Pour ce test, nous utilisons des données valides car bincode est très robuste

        let alice = PeerId::from_bytes(b"alice_ser_err".to_vec());
        let bob = PeerId::from_bytes(b"bob_ser_err".to_vec());

        let message = DataChannelMessage::text(alice, bob, "Valid message");
        let serialized = message.serialize().unwrap();

        // Test désérialisation de données corrompues
        let corrupted_data = vec![0xFF, 0xFE, 0xFD]; // Données invalides
        let result = DataChannelMessage::deserialize(&corrupted_data);
        assert!(result.is_err());

        // Test désérialisation de données valides
        let result = DataChannelMessage::deserialize(&serialized);
        assert!(result.is_ok());
    }
}
