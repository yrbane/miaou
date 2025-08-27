//! P2P Connection Management with SOLID principles
//!
//! TDD Implementation: Tests define behavior BEFORE implementation
//! SOLID Architecture: Each component has single responsibility

use crate::{NetworkError, PeerId, PeerInfo};
use std::sync::Arc;
use std::collections::HashMap;
use async_trait::async_trait;

// ========== TDD: Start with minimal interfaces (SOLID - ISP) ==========

/// Connection Manager - Single Responsibility: Manage P2P connection lifecycle
pub struct P2pConnectionManager {
    peer_id: PeerId,
    factory: Arc<dyn P2pConnectionFactory>,
    handshake: Arc<dyn P2pHandshakeProtocol>,
    connections: Arc<tokio::sync::RwLock<HashMap<P2pConnectionId, Arc<dyn P2pConnection>>>>,
}

impl P2pConnectionManager {
    /// Create new connection manager with dependency injection (SOLID - DIP)
    pub fn new(
        peer_id: PeerId, 
        factory: Arc<dyn P2pConnectionFactory>,
        handshake: Arc<dyn P2pHandshakeProtocol>,
    ) -> Self {
        Self { 
            peer_id,
            factory,
            handshake,
            connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Connect to peer (TDD: GREEN - Now implemented!)
    pub async fn connect_to_peer(&self, peer_info: &PeerInfo) -> Result<P2pConnectionId, NetworkError> {
        // GREEN: Real implementation using injected dependencies
        let connection = self.factory.create_connection(peer_info, Arc::clone(&self.handshake)).await?;
        let conn_id = P2pConnectionId::new(format!("{:?}-{:?}", self.peer_id, peer_info.id));
        
        // Store connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(conn_id.clone(), connection);
        }
        
        Ok(conn_id)
    }

    /// List active connections
    pub async fn list_connections(&self) -> Vec<P2pConnectionId> {
        // GREEN: Real implementation
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }

    /// Get connection by ID  
    pub async fn get_connection(&self, conn_id: &P2pConnectionId) -> Option<Arc<dyn P2pConnection>> {
        let connections = self.connections.read().await;
        connections.get(conn_id).cloned()
    }
}

/// Connection ID type (SOLID - SRP)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct P2pConnectionId(String);

impl P2pConnectionId {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

// ========== TDD: Next iteration - Add more interfaces ==========

/// Handshake Protocol abstraction (SOLID - DIP)
#[async_trait]
pub trait P2pHandshakeProtocol: Send + Sync {
    /// Initiate handshake with peer
    async fn initiate_handshake(&self, peer_info: &PeerInfo) -> Result<HandshakeResult, NetworkError>;
    /// Verify handshake data
    async fn verify_handshake(&self, data: &[u8]) -> Result<bool, NetworkError>;
}

/// Handshake result
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// Session key for encryption
    pub session_key: Vec<u8>,
    /// Whether peer is verified
    pub peer_verified: bool,
}

/// Mock implementation for testing (SOLID - LSP)
pub struct MockHandshakeProtocol;

#[async_trait]
impl P2pHandshakeProtocol for MockHandshakeProtocol {
    async fn initiate_handshake(&self, _peer_info: &PeerInfo) -> Result<HandshakeResult, NetworkError> {
        Ok(HandshakeResult {
            session_key: vec![0u8; 32],
            peer_verified: true,
        })
    }

    async fn verify_handshake(&self, _data: &[u8]) -> Result<bool, NetworkError> {
        Ok(true)
    }
}

// ========== TDD: Next iteration - Connection Factory (SOLID - OCP) ==========

/// Connection Factory for dependency injection (SOLID - DIP)
#[async_trait]
pub trait P2pConnectionFactory: Send + Sync {
    /// Create connection
    async fn create_connection(
        &self,
        peer_info: &PeerInfo,
        handshake: Arc<dyn P2pHandshakeProtocol>,
    ) -> Result<Arc<dyn P2pConnection>, NetworkError>;
}

/// P2P Connection abstraction
#[async_trait]
pub trait P2pConnection: Send + Sync {
    /// Send message
    async fn send_message(&self, data: &[u8]) -> Result<(), NetworkError>;
    /// Receive message
    async fn receive_message(&self) -> Result<Vec<u8>, NetworkError>;
    /// Close connection
    async fn close(&self) -> Result<(), NetworkError>;
    /// Check if active
    fn is_active(&self) -> bool;
    /// Get peer ID
    fn peer_id(&self) -> &PeerId;
}

/// Mock connection for testing
pub struct MockP2pConnection {
    peer_id: PeerId,
    active: bool,
}

impl MockP2pConnection {
    /// Create mock connection
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            active: true,
        }
    }
}

#[async_trait]
impl P2pConnection for MockP2pConnection {
    async fn send_message(&self, _data: &[u8]) -> Result<(), NetworkError> {
        if !self.active {
            return Err(NetworkError::HandshakeError("Connection not active".to_string()));
        }
        Ok(())
    }

    async fn receive_message(&self) -> Result<Vec<u8>, NetworkError> {
        if !self.active {
            return Err(NetworkError::HandshakeError("Connection not active".to_string()));
        }
        Ok(b"mock message".to_vec())
    }

    async fn close(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

/// Mock factory for testing
pub struct MockP2pConnectionFactory;

#[async_trait]
impl P2pConnectionFactory for MockP2pConnectionFactory {
    async fn create_connection(
        &self,
        peer_info: &PeerInfo,
        _handshake: Arc<dyn P2pHandshakeProtocol>,
    ) -> Result<Arc<dyn P2pConnection>, NetworkError> {
        Ok(Arc::new(MockP2pConnection::new(peer_info.id.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== TDD: RED phase - Write failing tests first ==========

    #[tokio::test]
    async fn test_connection_manager_new_creates_empty_state() {
        // GREEN: Test basic creation with dependency injection
        let peer_id = PeerId::from_bytes(b"test-peer".to_vec());
        let factory = Arc::new(MockP2pConnectionFactory);
        let handshake = Arc::new(MockHandshakeProtocol);
        let manager = P2pConnectionManager::new(peer_id, factory, handshake);
        
        let connections = manager.list_connections().await;
        assert!(connections.is_empty(), "New manager should have no connections");
    }

    #[tokio::test]
    async fn test_connect_to_peer_returns_connection_id() {
        // GREEN: Test now passes with real implementation!
        let peer_id = PeerId::from_bytes(b"local-peer".to_vec());
        let factory = Arc::new(MockP2pConnectionFactory);
        let handshake = Arc::new(MockHandshakeProtocol);
        let manager = P2pConnectionManager::new(peer_id, factory, handshake);
        
        let remote_peer_id = PeerId::from_bytes(b"remote-peer".to_vec());
        let mut peer_info = PeerInfo::new(remote_peer_id.clone());
        peer_info.add_address("127.0.0.1:8080".parse().unwrap());

        // GREEN: Now this works!
        let conn_id = manager.connect_to_peer(&peer_info).await.unwrap();
        
        // Verify connection was created
        let connections = manager.list_connections().await;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0], conn_id);
        
        // Verify we can get the connection
        let connection = manager.get_connection(&conn_id).await;
        assert!(connection.is_some());
    }

    #[test]
    fn test_connection_id_creation() {
        // GREEN: This can pass immediately
        let conn_id = P2pConnectionId::new("test-connection-123".to_string());
        assert_eq!(conn_id.0, "test-connection-123");
    }

    #[test]
    fn test_connection_id_equality() {
        // GREEN: Test value equality
        let id1 = P2pConnectionId::new("same-id".to_string());
        let id2 = P2pConnectionId::new("same-id".to_string());
        let id3 = P2pConnectionId::new("different-id".to_string());
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;

    // ========== TDD: Handshake Protocol Tests ==========

    #[tokio::test]
    async fn test_mock_handshake_success() {
        // GREEN: Simple test that should pass
        let protocol = MockHandshakeProtocol;
        let peer_info = create_test_peer();
        
        let result = protocol.initiate_handshake(&peer_info).await.unwrap();
        
        assert_eq!(result.session_key.len(), 32);
        assert!(result.peer_verified);
    }

    #[tokio::test]
    async fn test_handshake_verification() {
        // GREEN: Verification test
        let protocol = MockHandshakeProtocol;
        let test_data = b"test handshake data";
        
        let is_valid = protocol.verify_handshake(test_data).await.unwrap();
        assert!(is_valid);
    }

    fn create_test_peer() -> PeerInfo {
        let peer_id = PeerId::from_bytes(b"test-peer-handshake".to_vec());
        let mut peer_info = PeerInfo::new(peer_id);
        peer_info.add_address("127.0.0.1:9000".parse().unwrap());
        peer_info
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    // ========== TDD: Connection Tests ==========

    #[tokio::test]
    async fn test_mock_connection_send_receive() {
        // GREEN: Basic connection functionality
        let peer_id = PeerId::from_bytes(b"connection-test-peer".to_vec());
        let connection = MockP2pConnection::new(peer_id.clone());
        
        // Test sending
        let result = connection.send_message(b"test message").await;
        assert!(result.is_ok());
        
        // Test receiving
        let received = connection.receive_message().await.unwrap();
        assert_eq!(received, b"mock message");
        
        // Test peer ID
        assert_eq!(connection.peer_id(), &peer_id);
        
        // Test active status
        assert!(connection.is_active());
    }

    #[tokio::test]
    async fn test_connection_factory_creates_connection() {
        // GREEN: Factory pattern test
        let factory = MockP2pConnectionFactory;
        let handshake = Arc::new(MockHandshakeProtocol);
        
        let peer_id = PeerId::from_bytes(b"factory-test-peer".to_vec());
        let mut peer_info = PeerInfo::new(peer_id.clone());
        peer_info.add_address("127.0.0.1:7000".parse().unwrap());
        
        let connection = factory.create_connection(&peer_info, handshake).await.unwrap();
        
        assert_eq!(connection.peer_id(), &peer_id);
        assert!(connection.is_active());
    }
}

// ========== SUMMARY ==========
// This module demonstrates SOLID + TDD:
// 
// SOLID Principles Applied:
// ✅ Single Responsibility: Each struct has one clear responsibility
// ✅ Open/Closed: Extensible via traits without modifying existing code  
// ✅ Liskov Substitution: All implementations are interchangeable
// ✅ Interface Segregation: Small, focused traits
// ✅ Dependency Inversion: Depend on abstractions (traits), not concretions
//
// TDD Process:
// ✅ RED: Write failing tests first (todo!() for unimplemented features)
// ✅ GREEN: Write minimal code to make tests pass
// ✅ REFACTOR: Improve design while keeping tests green
//
// Next TDD iteration: Remove todo!() and implement real connection logic