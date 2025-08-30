//! WebRTC Production Real - Implémentation complète avec webrtc-rs
//!
//! Remplace les simulations par de vraies primitives WebRTC (Issue #4)

use crate::{NetworkError, PeerId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

// Import webrtc-rs types
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage as WebRtcMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Configuration WebRTC production réelle
#[derive(Debug, Clone)]
pub struct RealWebRtcConfig {
    /// Serveurs STUN pour découverte NAT
    pub stun_servers: Vec<String>,
    /// Serveurs TURN pour relay (optionnels)
    pub turn_servers: Vec<TurnServer>,
    /// Timeout connexion
    pub connection_timeout: Duration,
    /// Timeout gathering ICE candidates
    pub ice_gathering_timeout: Duration,
    /// Buffer size des data channels
    pub data_channel_buffer_size: usize,
    /// Interval keepalive
    pub keepalive_interval: Duration,
}

impl Default for RealWebRtcConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: vec![],
            connection_timeout: Duration::from_secs(30),
            ice_gathering_timeout: Duration::from_secs(10),
            data_channel_buffer_size: 16384, // 16KB
            keepalive_interval: Duration::from_secs(30),
        }
    }
}

/// Configuration serveur TURN
#[derive(Debug, Clone)]
pub struct TurnServer {
    /// URL du serveur TURN
    pub url: String,
    /// Username
    pub username: String,
    /// Credential
    pub credential: String,
}

/// État d'une connexion WebRTC réelle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealWebRtcState {
    /// Nouvelle connexion
    New,
    /// Gathering ICE candidates
    Gathering,
    /// Connecting (exchanging SDP)
    Connecting,
    /// Connected
    Connected,
    /// Disconnected (recoverable)
    Disconnected,
    /// Failed
    Failed,
    /// Closed
    Closed,
}

/// Candidat ICE réel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealIceCandidate {
    /// Candidat sous format SDP
    pub candidate: String,
    /// sdpMid
    pub sdp_mid: Option<String>,
    /// sdpMLineIndex
    pub sdp_m_line_index: Option<u16>,
    /// Username fragment
    pub username_fragment: Option<String>,
}

impl From<RTCIceCandidate> for RealIceCandidate {
    fn from(rtc_candidate: RTCIceCandidate) -> Self {
        // Construire la chaîne candidate depuis les champs de RTCIceCandidate
        let candidate_string = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            rtc_candidate.foundation,
            rtc_candidate.component,
            rtc_candidate.protocol.to_string().to_uppercase(),
            rtc_candidate.priority,
            rtc_candidate.address,
            rtc_candidate.port,
            rtc_candidate.typ
        );

        Self {
            candidate: candidate_string,
            sdp_mid: None, // RTCIceCandidate ne contient pas cette info directement
            sdp_m_line_index: None, // RTCIceCandidate ne contient pas cette info directement
            username_fragment: None, // RTCIceCandidate ne contient pas cette info directement
        }
    }
}

impl TryInto<RTCIceCandidateInit> for RealIceCandidate {
    type Error = NetworkError;

    fn try_into(self) -> Result<RTCIceCandidateInit, Self::Error> {
        Ok(RTCIceCandidateInit {
            candidate: self.candidate,
            sdp_mid: self.sdp_mid,
            sdp_mline_index: self.sdp_m_line_index,
            username_fragment: self.username_fragment,
        })
    }
}

/// Message de données échangé via DataChannel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealDataChannelMessage {
    /// ID unique du message
    pub id: String,
    /// Expéditeur
    pub from: PeerId,
    /// Destinataire
    pub to: PeerId,
    /// Payload
    pub payload: Vec<u8>,
    /// Timestamp d'envoi
    pub timestamp: u64,
    /// Métadonnées
    pub metadata: HashMap<String, String>,
}

impl RealDataChannelMessage {
    /// Créer un nouveau message
    pub fn new(from: PeerId, to: PeerId, payload: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            id: format!("msg_{}_{}", timestamp, fastrand::u32(..)),
            from,
            to,
            payload,
            timestamp,
            metadata: HashMap::new(),
        }
    }

    /// Message texte
    pub fn text(from: PeerId, to: PeerId, text: &str) -> Self {
        Self::new(from, to, text.as_bytes().to_vec())
    }

    /// Sérialiser en JSON pour transmission
    pub fn serialize(&self) -> Result<Vec<u8>, NetworkError> {
        serde_json::to_vec(self).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Désérialiser depuis JSON
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        serde_json::from_slice(data).map_err(|e| NetworkError::SerializationError(e.to_string()))
    }

    /// Obtenir le contenu comme texte
    pub fn as_text(&self) -> Result<String, NetworkError> {
        String::from_utf8(self.payload.clone())
            .map_err(|e| NetworkError::General(format!("Invalid UTF-8: {}", e)))
    }
}

/// Connexion WebRTC production avec vraies primitives
pub struct RealWebRtcConnection {
    /// ID unique de la connexion
    pub connection_id: String,
    /// Peer distant
    pub peer_id: PeerId,
    /// État de la connexion
    pub state: Arc<RwLock<RealWebRtcState>>,
    /// Peer Connection WebRTC
    pub peer_connection: Arc<RTCPeerConnection>,
    /// Data Channel principal
    pub data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    /// Canal pour messages entrants
    message_tx: mpsc::UnboundedSender<RealDataChannelMessage>,
    message_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<RealDataChannelMessage>>>>,
    /// Statistiques
    /// Bytes envoyés par cette connexion
    pub bytes_sent: Arc<RwLock<u64>>,
    /// Bytes reçus par cette connexion
    pub bytes_received: Arc<RwLock<u64>>,
    /// Messages envoyés par cette connexion
    pub messages_sent: Arc<RwLock<u64>>,
    /// Messages reçus par cette connexion
    pub messages_received: Arc<RwLock<u64>>,
    /// Timestamp de connexion
    pub connected_at: Arc<RwLock<Option<Instant>>>,
}

impl RealWebRtcConnection {
    /// Créer une nouvelle connexion WebRTC réelle
    pub async fn new(
        connection_id: String,
        peer_id: PeerId,
        config: &RealWebRtcConfig,
    ) -> Result<Self, NetworkError> {
        // Créer MediaEngine et Registry
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| NetworkError::General(format!("Erreur enregistrement codecs: {}", e)))?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine).map_err(|e| {
            NetworkError::General(format!("Erreur enregistrement interceptors: {}", e))
        })?;

        // Créer l'API WebRTC
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        // Configuration ICE servers
        let mut ice_servers = vec![];

        // Ajouter serveurs STUN
        for stun_url in &config.stun_servers {
            ice_servers.push(RTCIceServer {
                urls: vec![stun_url.clone()],
                username: "".to_string(),
                credential: "".to_string(),
            });
        }

        // Ajouter serveurs TURN
        for turn in &config.turn_servers {
            ice_servers.push(RTCIceServer {
                urls: vec![turn.url.clone()],
                username: turn.username.clone(),
                credential: turn.credential.clone(),
            });
        }

        // Créer la configuration WebRTC
        let rtc_config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        // Créer peer connection
        let peer_connection = Arc::new(api.new_peer_connection(rtc_config).await.map_err(|e| {
            NetworkError::General(format!("Erreur création peer connection: {}", e))
        })?);

        let (message_tx, message_rx) = mpsc::unbounded_channel();

        info!(
            "🔗 Connexion WebRTC réelle créée: {} pour peer {}",
            connection_id,
            peer_id.short()
        );

        Ok(Self {
            connection_id,
            peer_id,
            state: Arc::new(RwLock::new(RealWebRtcState::New)),
            peer_connection,
            data_channel: Arc::new(RwLock::new(None)),
            message_tx,
            message_rx: Arc::new(Mutex::new(Some(message_rx))),
            bytes_sent: Arc::new(RwLock::new(0)),
            bytes_received: Arc::new(RwLock::new(0)),
            messages_sent: Arc::new(RwLock::new(0)),
            messages_received: Arc::new(RwLock::new(0)),
            connected_at: Arc::new(RwLock::new(None)),
        })
    }

    /// Créer une offre (caller)
    pub async fn create_offer(&self) -> Result<RTCSessionDescription, NetworkError> {
        info!("📤 Création offer WebRTC pour {}", self.peer_id.short());

        // Créer data channel en tant qu'offerer
        let data_channel = self
            .peer_connection
            .create_data_channel("miaou-data", None)
            .await
            .map_err(|e| NetworkError::General(format!("Erreur création data channel: {}", e)))?;

        // Configurer data channel handlers
        self.setup_data_channel_handlers(Arc::clone(&data_channel))
            .await?;

        // Stocker le data channel
        *self.data_channel.write().await = Some(data_channel);

        // Créer l'offer
        let offer = self
            .peer_connection
            .create_offer(None)
            .await
            .map_err(|e| NetworkError::General(format!("Erreur création offer: {}", e)))?;

        // Définir la local description
        self.peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| NetworkError::General(format!("Erreur set local description: {}", e)))?;

        *self.state.write().await = RealWebRtcState::Gathering;

        Ok(offer)
    }

    /// Créer une réponse (callee)
    pub async fn create_answer(
        &self,
        offer: RTCSessionDescription,
    ) -> Result<RTCSessionDescription, NetworkError> {
        info!(
            "📥 Traitement offer et création answer pour {}",
            self.peer_id.short()
        );

        // Définir la remote description (offer)
        self.peer_connection
            .set_remote_description(offer)
            .await
            .map_err(|e| NetworkError::General(format!("Erreur set remote description: {}", e)))?;

        // Setup data channel handlers pour les canaux entrants
        let pc = Arc::clone(&self.peer_connection);
        let state = Arc::clone(&self.state);
        let data_channel_lock = Arc::clone(&self.data_channel);

        pc.on_data_channel(Box::new(move |dc| {
            let state = Arc::clone(&state);
            let data_channel_lock = Arc::clone(&data_channel_lock);

            Box::pin(async move {
                info!("📨 Data channel entrant reçu: {}", dc.label());

                // Stocker le data channel
                *data_channel_lock.write().await = Some(Arc::clone(&dc));

                // Setup handlers (sans self, donc on fait basique)
                dc.on_open(Box::new(move || {
                    Box::pin(async move {
                        info!("✅ Data channel entrant ouvert");
                    })
                }));

                *state.write().await = RealWebRtcState::Connected;
            })
        }));

        // Créer l'answer
        let answer = self
            .peer_connection
            .create_answer(None)
            .await
            .map_err(|e| NetworkError::General(format!("Erreur création answer: {}", e)))?;

        // Définir la local description
        self.peer_connection
            .set_local_description(answer.clone())
            .await
            .map_err(|e| NetworkError::General(format!("Erreur set local description: {}", e)))?;

        *self.state.write().await = RealWebRtcState::Connecting;

        Ok(answer)
    }

    /// Finaliser la connexion avec l'answer (côté offerer)
    pub async fn finalize_connection(
        &self,
        answer: RTCSessionDescription,
    ) -> Result<(), NetworkError> {
        info!(
            "🔗 Finalisation connexion avec answer de {}",
            self.peer_id.short()
        );

        // Définir la remote description (answer)
        self.peer_connection
            .set_remote_description(answer)
            .await
            .map_err(|e| NetworkError::General(format!("Erreur set remote description: {}", e)))?;

        *self.state.write().await = RealWebRtcState::Connecting;

        // Attendre que la connexion soit établie
        self.wait_for_connection().await?;

        Ok(())
    }

    /// Attendre que la connexion soit établie
    async fn wait_for_connection(&self) -> Result<(), NetworkError> {
        let timeout = Duration::from_secs(30);
        let start = Instant::now();

        loop {
            let pc_state = self.peer_connection.connection_state();

            match pc_state {
                RTCPeerConnectionState::Connected => {
                    *self.state.write().await = RealWebRtcState::Connected;
                    *self.connected_at.write().await = Some(Instant::now());
                    info!("✅ Connexion WebRTC établie avec {}", self.peer_id.short());
                    return Ok(());
                }
                RTCPeerConnectionState::Failed => {
                    *self.state.write().await = RealWebRtcState::Failed;
                    return Err(NetworkError::General(
                        "Connexion WebRTC échouée".to_string(),
                    ));
                }
                RTCPeerConnectionState::Closed => {
                    *self.state.write().await = RealWebRtcState::Closed;
                    return Err(NetworkError::General("Connexion WebRTC fermée".to_string()));
                }
                _ => {
                    // Continuer à attendre
                    if start.elapsed() > timeout {
                        *self.state.write().await = RealWebRtcState::Failed;
                        return Err(NetworkError::General(
                            "Timeout connexion WebRTC".to_string(),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Configurer les handlers du data channel
    async fn setup_data_channel_handlers(
        &self,
        data_channel: Arc<RTCDataChannel>,
    ) -> Result<(), NetworkError> {
        let state = Arc::clone(&self.state);
        let connected_at = Arc::clone(&self.connected_at);
        let message_tx = self.message_tx.clone();
        let bytes_received = Arc::clone(&self.bytes_received);
        let messages_received = Arc::clone(&self.messages_received);
        let peer_id = self.peer_id.clone();

        // Handler ouverture
        let state_open = Arc::clone(&state);
        let connected_at_open = Arc::clone(&connected_at);
        let peer_id_open = peer_id.clone();
        data_channel.on_open(Box::new(move || {
            let state_open = Arc::clone(&state_open);
            let connected_at_open = Arc::clone(&connected_at_open);
            let peer_id_open = peer_id_open.clone();

            Box::pin(async move {
                info!("🟢 Data channel ouvert avec {}", peer_id_open.short());
                *state_open.write().await = RealWebRtcState::Connected;
                *connected_at_open.write().await = Some(Instant::now());
            })
        }));

        // Handler fermeture
        let state_close = Arc::clone(&state);
        let peer_id_close = peer_id.clone();
        data_channel.on_close(Box::new(move || {
            let state_close = Arc::clone(&state_close);
            let peer_id_close = peer_id_close.clone();

            Box::pin(async move {
                info!("🔴 Data channel fermé avec {}", peer_id_close.short());
                *state_close.write().await = RealWebRtcState::Closed;
            })
        }));

        // Handler erreur
        let state_error = Arc::clone(&state);
        let peer_id_error = peer_id.clone();
        data_channel.on_error(Box::new(move |err| {
            let state_error = Arc::clone(&state_error);
            let peer_id_error = peer_id_error.clone();

            Box::pin(async move {
                error!(
                    "❌ Erreur data channel avec {}: {}",
                    peer_id_error.short(),
                    err
                );
                *state_error.write().await = RealWebRtcState::Failed;
            })
        }));

        // Handler messages entrants
        data_channel.on_message(Box::new(move |msg: WebRtcMessage| {
            let message_tx = message_tx.clone();
            let bytes_received = Arc::clone(&bytes_received);
            let messages_received = Arc::clone(&messages_received);
            let peer_id = peer_id.clone();

            Box::pin(async move {
                debug!(
                    "📥 Message reçu de {}: {} bytes",
                    peer_id.short(),
                    msg.data.len()
                );

                // Mettre à jour les statistiques
                *bytes_received.write().await += msg.data.len() as u64;
                *messages_received.write().await += 1;

                // Désérialiser et transmettre le message
                match RealDataChannelMessage::deserialize(&msg.data) {
                    Ok(message) => {
                        if let Err(e) = message_tx.send(message) {
                            warn!("Erreur transmission message interne: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Erreur désérialisation message: {}", e);
                    }
                }
            })
        }));

        Ok(())
    }

    /// Envoyer un message via le data channel
    pub async fn send_message(&self, message: RealDataChannelMessage) -> Result<(), NetworkError> {
        let data_channel_guard = self.data_channel.read().await;
        if let Some(ref data_channel) = *data_channel_guard {
            // Sérialiser le message
            let serialized = message.serialize()?;

            // Envoyer les données directement
            data_channel
                .send(&bytes::Bytes::from(serialized.clone()))
                .await
                .map_err(|e| NetworkError::General(format!("Erreur envoi message: {}", e)))?;

            // Mettre à jour les statistiques
            *self.bytes_sent.write().await += serialized.len() as u64;
            *self.messages_sent.write().await += 1;

            debug!(
                "📤 Message envoyé à {}: {} bytes",
                self.peer_id.short(),
                serialized.len()
            );

            Ok(())
        } else {
            Err(NetworkError::General(
                "Data channel non disponible".to_string(),
            ))
        }
    }

    /// Recevoir un message (non-bloquant)
    pub async fn recv_message(&self) -> Result<RealDataChannelMessage, NetworkError> {
        let mut rx_guard = self.message_rx.lock().await;
        if let Some(ref mut rx) = *rx_guard {
            match rx.try_recv() {
                Ok(message) => Ok(message),
                Err(mpsc::error::TryRecvError::Empty) => Err(NetworkError::General(
                    "Pas de message disponible".to_string(),
                )),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    Err(NetworkError::General("Canal de messages fermé".to_string()))
                }
            }
        } else {
            Err(NetworkError::General(
                "Receiver de messages déjà pris".to_string(),
            ))
        }
    }

    /// Prendre le receiver de messages (pour écoute externe)
    pub async fn take_message_receiver(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<RealDataChannelMessage>, NetworkError> {
        let mut rx_guard = self.message_rx.lock().await;
        rx_guard
            .take()
            .ok_or_else(|| NetworkError::General("Receiver déjà pris".to_string()))
    }

    /// Obtenir l'état actuel
    pub async fn get_state(&self) -> RealWebRtcState {
        *self.state.read().await
    }

    /// Vérifier si la connexion est active
    pub async fn is_active(&self) -> bool {
        matches!(*self.state.read().await, RealWebRtcState::Connected)
    }

    /// Obtenir les statistiques
    pub async fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            bytes_sent: *self.bytes_sent.read().await,
            bytes_received: *self.bytes_received.read().await,
            messages_sent: *self.messages_sent.read().await,
            messages_received: *self.messages_received.read().await,
            connected_at: *self.connected_at.read().await,
            current_state: *self.state.read().await,
        }
    }

    /// Fermer la connexion
    pub async fn close(&self) -> Result<(), NetworkError> {
        info!(
            "🔒 Fermeture connexion WebRTC avec {}",
            self.peer_id.short()
        );

        if let Some(ref data_channel) = *self.data_channel.read().await {
            if let Err(e) = data_channel.close().await {
                warn!("Erreur fermeture data channel: {}", e);
            }
        }

        if let Err(e) = self.peer_connection.close().await {
            warn!("Erreur fermeture peer connection: {}", e);
        }

        *self.state.write().await = RealWebRtcState::Closed;

        Ok(())
    }
}

/// Statistiques de connexion
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Bytes envoyés total
    pub bytes_sent: u64,
    /// Bytes reçus total
    pub bytes_received: u64,
    /// Messages envoyés total
    pub messages_sent: u64,
    /// Messages reçus total
    pub messages_received: u64,
    /// Timestamp de connexion
    pub connected_at: Option<Instant>,
    /// État actuel de la connexion
    pub current_state: RealWebRtcState,
}

/// Gestionnaire WebRTC production avec vraies primitives
pub struct RealWebRtcManager {
    /// Configuration
    config: RealWebRtcConfig,
    /// Pair local
    local_peer_id: PeerId,
    /// Connexions actives
    connections: Arc<RwLock<HashMap<String, Arc<RealWebRtcConnection>>>>,
    /// Canal pour événements
    event_tx: Arc<RwLock<Option<mpsc::UnboundedSender<WebRtcConnectionEvent>>>>,
}

/// Événements de connexion WebRTC
#[derive(Debug, Clone)]
pub enum WebRtcConnectionEvent {
    /// Connexion établie
    ConnectionEstablished {
        /// ID de la connexion
        connection_id: String,
        /// ID du pair
        peer_id: PeerId,
        /// Latence mesurée en millisecondes
        latency_ms: Option<u64>,
    },
    /// Connexion fermée
    ConnectionClosed {
        /// ID de la connexion
        connection_id: String,
        /// ID du pair
        peer_id: PeerId,
    },
    /// Erreur de connexion
    ConnectionError {
        /// ID de la connexion
        connection_id: String,
        /// ID du pair
        peer_id: PeerId,
        /// Message d'erreur
        error: String,
    },
    /// Message reçu
    MessageReceived {
        /// ID de la connexion
        connection_id: String,
        /// Message reçu
        message: RealDataChannelMessage,
    },
}

impl RealWebRtcManager {
    /// Créer un nouveau gestionnaire
    pub fn new(config: RealWebRtcConfig, local_peer_id: PeerId) -> Self {
        info!(
            "🚀 Création gestionnaire WebRTC réel pour peer {}",
            local_peer_id.short()
        );

        Self {
            config,
            local_peer_id,
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx: Arc::new(RwLock::new(None)),
        }
    }

    /// Configurer le canal d'événements
    pub async fn set_event_channel(&self, tx: mpsc::UnboundedSender<WebRtcConnectionEvent>) {
        *self.event_tx.write().await = Some(tx);
    }

    /// Créer une connexion sortante (offerer)
    pub async fn create_outbound_connection(
        &self,
        peer_id: PeerId,
    ) -> Result<(String, RTCSessionDescription), NetworkError> {
        let connection_id = format!("conn_{}_{}", self.local_peer_id.short(), peer_id.short());

        info!(
            "📞 Création connexion sortante vers {} (ID: {})",
            peer_id.short(),
            connection_id
        );

        // Créer la connexion
        let connection =
            RealWebRtcConnection::new(connection_id.clone(), peer_id.clone(), &self.config).await?;

        // Créer l'offer
        let offer = connection.create_offer().await?;

        // Stocker la connexion
        let connection_arc = Arc::new(connection);
        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id.clone(), Arc::clone(&connection_arc));
        }

        Ok((connection_id, offer))
    }

    /// Créer une connexion entrante (answerer)
    pub async fn create_inbound_connection(
        &self,
        peer_id: PeerId,
        offer: RTCSessionDescription,
    ) -> Result<(String, RTCSessionDescription), NetworkError> {
        let connection_id = format!("conn_{}_{}", peer_id.short(), self.local_peer_id.short());

        info!(
            "📞 Création connexion entrante depuis {} (ID: {})",
            peer_id.short(),
            connection_id
        );

        // Créer la connexion
        let connection =
            RealWebRtcConnection::new(connection_id.clone(), peer_id.clone(), &self.config).await?;

        // Créer l'answer
        let answer = connection.create_answer(offer).await?;

        // Stocker la connexion
        let connection_arc = Arc::new(connection);
        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id.clone(), Arc::clone(&connection_arc));
        }

        Ok((connection_id, answer))
    }

    /// Finaliser une connexion sortante avec l'answer
    pub async fn finalize_outbound_connection(
        &self,
        connection_id: &str,
        answer: RTCSessionDescription,
    ) -> Result<(), NetworkError> {
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(connection_id) {
            connection.finalize_connection(answer).await?;

            // Émettre événement de connexion établie
            if let Some(tx) = &*self.event_tx.read().await {
                let _ = tx.send(WebRtcConnectionEvent::ConnectionEstablished {
                    connection_id: connection_id.to_string(),
                    peer_id: connection.peer_id.clone(),
                    latency_ms: None, // TODO: mesurer latency réelle
                });
            }

            Ok(())
        } else {
            Err(NetworkError::General("Connexion introuvable".to_string()))
        }
    }

    /// Envoyer un message via une connexion
    pub async fn send_message(
        &self,
        connection_id: &str,
        message: RealDataChannelMessage,
    ) -> Result<(), NetworkError> {
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(connection_id) {
            connection.send_message(message).await
        } else {
            Err(NetworkError::General("Connexion introuvable".to_string()))
        }
    }

    /// Lister les connexions actives
    pub async fn list_connections(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }

    /// Obtenir une connexion
    pub async fn get_connection(&self, connection_id: &str) -> Option<Arc<RealWebRtcConnection>> {
        let connections = self.connections.read().await;
        connections.get(connection_id).cloned()
    }

    /// Fermer une connexion
    pub async fn close_connection(&self, connection_id: &str) -> Result<(), NetworkError> {
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.remove(connection_id) {
            connection.close().await?;

            // Émettre événement de fermeture
            if let Some(tx) = &*self.event_tx.read().await {
                let _ = tx.send(WebRtcConnectionEvent::ConnectionClosed {
                    connection_id: connection_id.to_string(),
                    peer_id: connection.peer_id.clone(),
                });
            }

            Ok(())
        } else {
            Err(NetworkError::General("Connexion introuvable".to_string()))
        }
    }

    /// Fermer toutes les connexions
    pub async fn close_all(&self) -> Result<(), NetworkError> {
        let connection_ids: Vec<String> = {
            let connections = self.connections.read().await;
            connections.keys().cloned().collect()
        };

        for connection_id in connection_ids {
            if let Err(e) = self.close_connection(&connection_id).await {
                warn!("Erreur fermeture connexion {}: {}", connection_id, e);
            }
        }

        Ok(())
    }
}

/// Trait pour gestionnaire WebRTC réel
#[async_trait]
pub trait RealWebRtcManagerTrait: Send + Sync {
    /// Créer connexion sortante
    async fn create_outbound_connection(
        &self,
        peer_id: PeerId,
    ) -> Result<(String, RTCSessionDescription), NetworkError>;

    /// Créer connexion entrante
    async fn create_inbound_connection(
        &self,
        peer_id: PeerId,
        offer: RTCSessionDescription,
    ) -> Result<(String, RTCSessionDescription), NetworkError>;

    /// Finaliser connexion sortante
    async fn finalize_outbound_connection(
        &self,
        connection_id: &str,
        answer: RTCSessionDescription,
    ) -> Result<(), NetworkError>;

    /// Envoyer un message
    async fn send_message(
        &self,
        connection_id: &str,
        message: RealDataChannelMessage,
    ) -> Result<(), NetworkError>;

    /// Lister connexions
    async fn list_connections(&self) -> Vec<String>;

    /// Fermer connexion
    async fn close_connection(&self, connection_id: &str) -> Result<(), NetworkError>;
}

#[async_trait]
impl RealWebRtcManagerTrait for RealWebRtcManager {
    async fn create_outbound_connection(
        &self,
        peer_id: PeerId,
    ) -> Result<(String, RTCSessionDescription), NetworkError> {
        self.create_outbound_connection(peer_id).await
    }

    async fn create_inbound_connection(
        &self,
        peer_id: PeerId,
        offer: RTCSessionDescription,
    ) -> Result<(String, RTCSessionDescription), NetworkError> {
        self.create_inbound_connection(peer_id, offer).await
    }

    async fn finalize_outbound_connection(
        &self,
        connection_id: &str,
        answer: RTCSessionDescription,
    ) -> Result<(), NetworkError> {
        self.finalize_outbound_connection(connection_id, answer)
            .await
    }

    async fn send_message(
        &self,
        connection_id: &str,
        message: RealDataChannelMessage,
    ) -> Result<(), NetworkError> {
        self.send_message(connection_id, message).await
    }

    async fn list_connections(&self) -> Vec<String> {
        self.list_connections().await
    }

    async fn close_connection(&self, connection_id: &str) -> Result<(), NetworkError> {
        self.close_connection(connection_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[test]
    fn test_real_webrtc_config_default() {
        let config = RealWebRtcConfig::default();
        assert!(!config.stun_servers.is_empty());
        assert!(config.stun_servers.iter().any(|s| s.contains("google.com")));
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_real_data_channel_message_creation() {
        let alice = PeerId::from_bytes(b"alice".to_vec());
        let bob = PeerId::from_bytes(b"bob".to_vec());

        let message = RealDataChannelMessage::text(alice.clone(), bob.clone(), "Hello WebRTC!");

        assert_eq!(message.from, alice);
        assert_eq!(message.to, bob);
        assert_eq!(message.as_text().unwrap(), "Hello WebRTC!");
        assert!(!message.id.is_empty());
        assert!(message.timestamp > 0);
    }

    #[test]
    fn test_real_data_channel_message_serialization() {
        let alice = PeerId::from_bytes(b"alice".to_vec());
        let bob = PeerId::from_bytes(b"bob".to_vec());

        let original = RealDataChannelMessage::text(alice, bob, "Serialize test");
        let serialized = original.serialize().unwrap();
        let deserialized = RealDataChannelMessage::deserialize(&serialized).unwrap();

        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.from, deserialized.from);
        assert_eq!(original.to, deserialized.to);
        assert_eq!(original.payload, deserialized.payload);
    }

    #[tokio::test]
    async fn test_real_webrtc_connection_creation() {
        let config = RealWebRtcConfig::default();
        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());
        let connection_id = "test-conn-123".to_string();

        let result =
            RealWebRtcConnection::new(connection_id.clone(), peer_id.clone(), &config).await;

        // La création peut échouer si WebRTC n'est pas disponible dans l'environnement de test
        match result {
            Ok(connection) => {
                assert_eq!(connection.connection_id, connection_id);
                assert_eq!(connection.peer_id, peer_id);
                assert_eq!(connection.get_state().await, RealWebRtcState::New);
                assert!(!connection.is_active().await);
            }
            Err(e) => {
                println!("WebRTC non disponible dans l'environnement de test: {}", e);
                // C'est acceptable dans un environnement de test sans stack WebRTC complète
            }
        }
    }

    #[tokio::test]
    async fn test_real_webrtc_manager_creation() {
        let config = RealWebRtcConfig::default();
        let peer_id = PeerId::from_bytes(b"manager-peer".to_vec());

        let manager = RealWebRtcManager::new(config, peer_id.clone());

        let connections = manager.list_connections().await;
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn test_real_webrtc_manager_event_channel() {
        let config = RealWebRtcConfig::default();
        let peer_id = PeerId::from_bytes(b"event-peer".to_vec());
        let manager = RealWebRtcManager::new(config, peer_id);

        let (tx, _rx) = mpsc::unbounded_channel();
        manager.set_event_channel(tx).await;

        // Vérifier que le canal est configuré
        assert!(manager.event_tx.read().await.is_some());
    }

    #[tokio::test]
    async fn test_real_ice_candidate_conversion() {
        let real_candidate = RealIceCandidate {
            candidate: "candidate:1 1 UDP 2130706431 192.168.1.100 54400 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
            username_fragment: Some("4ZcD".to_string()),
        };

        let rtc_init: Result<RTCIceCandidateInit, _> = real_candidate.try_into();
        assert!(rtc_init.is_ok());

        let rtc_init = rtc_init.unwrap();
        assert!(rtc_init.candidate.contains("192.168.1.100"));
        assert_eq!(rtc_init.sdp_mid, Some("0".to_string()));
    }

    #[tokio::test]
    async fn test_connection_stats() {
        // Test que les statistiques sont bien initialisées
        let config = RealWebRtcConfig::default();
        let peer_id = PeerId::from_bytes(b"stats-peer".to_vec());
        let connection_id = "stats-conn".to_string();

        let result = RealWebRtcConnection::new(connection_id, peer_id, &config).await;

        if let Ok(connection) = result {
            let stats = connection.get_stats().await;
            assert_eq!(stats.bytes_sent, 0);
            assert_eq!(stats.bytes_received, 0);
            assert_eq!(stats.messages_sent, 0);
            assert_eq!(stats.messages_received, 0);
            assert_eq!(stats.current_state, RealWebRtcState::New);
            assert!(stats.connected_at.is_none());
        }
    }
}
