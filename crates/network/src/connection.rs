//! Gestion des connexions réseau
//!
//! Principe SOLID : Single Responsibility & Interface Segregation
//! Chaque connexion gère uniquement son propre état et communication

use crate::{NetworkError, PeerId};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// État d'une connexion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Connexion en cours d'établissement
    Connecting,
    /// Connexion établie et active
    Connected,
    /// Connexion fermée proprement
    Closed,
    /// Connexion échouée ou interrompue
    Failed,
}

/// Frame de données sur le réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Type de frame
    pub frame_type: FrameType,
    /// Numéro de séquence
    pub sequence: u64,
    /// Données du frame
    pub payload: Vec<u8>,
}

/// Types de frames supportés
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    /// Données applicatives
    Data,
    /// Keep-alive
    KeepAlive,
    /// Handshake
    Handshake,
    /// Fermeture
    Close,
}

/// Connexion active avec un pair
pub struct Connection {
    /// Identifiant du pair distant
    peer_id: Option<PeerId>,
    /// État de la connexion
    state: Arc<Mutex<ConnectionState>>,
    /// Statistiques de connexion
    stats: Arc<Mutex<ConnectionStats>>,
    /// Canal pour envoyer des frames
    tx: mpsc::Sender<Frame>,
    /// Canal pour recevoir des frames
    rx: Arc<AsyncMutex<mpsc::Receiver<Frame>>>,
}

/// Statistiques d'une connexion
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Temps d'établissement de la connexion
    pub established_at: Option<Instant>,
    /// Nombre de bytes envoyés
    pub bytes_sent: u64,
    /// Nombre de bytes reçus
    pub bytes_received: u64,
    /// RTT moyen en millisecondes
    pub rtt_ms: Option<u32>,
    /// Nombre de frames envoyés
    pub frames_sent: u64,
    /// Nombre de frames reçus
    pub frames_received: u64,
}

impl Connection {
    /// Crée une nouvelle connexion
    pub fn new(peer_id: Option<PeerId>) -> Self {
        let (tx, rx) = mpsc::channel(100);

        Self {
            peer_id,
            state: Arc::new(Mutex::new(ConnectionState::Connecting)),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            tx,
            rx: Arc::new(AsyncMutex::new(rx)),
        }
    }

    /// Envoie un frame sur la connexion
    ///
    /// # Errors
    /// Retourne une erreur si la connexion est fermée
    pub async fn send_frame(&self, frame: Frame) -> Result<(), NetworkError> {
        if self.state() != ConnectionState::Connected {
            return Err(NetworkError::ConnectionFailed(
                "Connexion non active".to_string(),
            ));
        }

        let payload_len = frame.payload.len() as u64;

        self.tx
            .send(frame)
            .await
            .map_err(|e| NetworkError::TransportError(e.to_string()))?;

        let mut stats = self.stats.lock().unwrap();
        stats.frames_sent += 1;
        stats.bytes_sent += payload_len;

        Ok(())
    }

    /// Reçoit un frame de la connexion
    ///
    /// # Errors
    /// Retourne une erreur si aucun frame n'est disponible
    pub async fn receive_frame(&self) -> Result<Frame, NetworkError> {
        if self.state() != ConnectionState::Connected {
            return Err(NetworkError::ConnectionFailed(
                "Connexion non active".to_string(),
            ));
        }

        let frame = {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| NetworkError::ConnectionFailed("Canal fermé".to_string()))?
        };

        let mut stats = self.stats.lock().unwrap();
        stats.frames_received += 1;
        stats.bytes_received += frame.payload.len() as u64;

        Ok(frame)
    }

    /// Ferme la connexion
    pub async fn close(&self) -> Result<(), NetworkError> {
        {
            let mut state = self.state.lock().unwrap();
            *state = ConnectionState::Closed;
        }

        // Envoyer frame de fermeture
        let close_frame = Frame {
            frame_type: FrameType::Close,
            sequence: 0,
            payload: Vec::new(),
        };

        let _ = self.tx.send(close_frame).await;
        Ok(())
    }

    /// Retourne l'état actuel de la connexion
    pub fn state(&self) -> ConnectionState {
        *self.state.lock().unwrap()
    }

    /// Met à jour l'état de la connexion
    pub fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.lock().unwrap();
        *state = new_state;

        if new_state == ConnectionState::Connected {
            let mut stats = self.stats.lock().unwrap();
            stats.established_at = Some(Instant::now());
        }
    }

    /// Retourne l'ID du pair distant
    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer_id.clone()
    }

    /// Retourne les statistiques de connexion
    pub fn stats(&self) -> ConnectionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Met à jour le RTT
    pub fn update_rtt(&self, rtt_ms: u32) {
        let mut stats = self.stats.lock().unwrap();
        stats.rtt_ms = Some(rtt_ms);
    }

    #[cfg(test)]
    pub(crate) fn new_mock() -> Self {
        let conn = Self::new(Some(PeerId::new_mock()));
        conn.set_state(ConnectionState::Connected);
        conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[test]
    fn test_connection_state_transitions() {
        let conn = Connection::new(None);
        assert_eq!(conn.state(), ConnectionState::Connecting);

        conn.set_state(ConnectionState::Connected);
        assert_eq!(conn.state(), ConnectionState::Connected);

        conn.set_state(ConnectionState::Closed);
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[tokio::test]
    async fn test_send_frame_when_connected() {
        let conn = Connection::new(Some(PeerId::new_mock()));
        conn.set_state(ConnectionState::Connected);

        let frame = Frame {
            frame_type: FrameType::Data,
            sequence: 1,
            payload: vec![1, 2, 3],
        };

        let result = conn.send_frame(frame).await;
        assert!(result.is_ok());

        let stats = conn.stats();
        assert_eq!(stats.frames_sent, 1);
        assert_eq!(stats.bytes_sent, 3);
    }

    #[tokio::test]
    async fn test_send_frame_when_disconnected() {
        let conn = Connection::new(None);
        // État par défaut : Connecting, pas Connected

        let frame = Frame {
            frame_type: FrameType::Data,
            sequence: 1,
            payload: vec![1, 2, 3],
        };

        let result = conn.send_frame(frame).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_close() {
        let conn = Connection::new(Some(PeerId::new_mock()));
        conn.set_state(ConnectionState::Connected);

        let result = conn.close().await;
        assert!(result.is_ok());
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_connection_stats() {
        let conn = Connection::new(None);
        conn.set_state(ConnectionState::Connected);

        let stats = conn.stats();
        assert!(stats.established_at.is_some());
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);

        conn.update_rtt(42);
        let stats = conn.stats();
        assert_eq!(stats.rtt_ms, Some(42));
    }
}
