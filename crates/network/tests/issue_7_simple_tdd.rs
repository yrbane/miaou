//! Tests TDD simples pour Issue #7 - Tests RED puis GREEN
//!
//! Phase TDD: Tests unitaires simples pour valider les fonctionnalités

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;
use tracing_subscriber::fmt;

use miaou_network::{
    Message, PeerId, RobustMessagingManager, RobustMessagingConfig
};

#[tokio::test]
async fn test_robust_messaging_manager_creation() {
    // TDD GREEN: Test basique - création du manager
    let _ = fmt::try_init();
    info!("🧪 Test création RobustMessagingManager");
    
    let config = RobustMessagingConfig::default();
    let manager = RobustMessagingManager::new(config);
    
    // Test: Manager créé avec stats initiales
    let stats = manager.get_stats().await;
    assert_eq!(stats.messages_sent, 0);
    assert_eq!(stats.messages_received, 0);
    assert_eq!(stats.duplicates_detected, 0);
    
    info!("✅ Manager créé avec succès");
}

#[tokio::test]
async fn test_send_message_basic() {
    // TDD GREEN: Test envoi basique d'un message
    let _ = fmt::try_init();
    info!("🧪 Test envoi message basique");
    
    let config = RobustMessagingConfig::default();
    let manager = RobustMessagingManager::new(config);
    
    let sender = PeerId::from_bytes(b"sender".to_vec());
    let receiver = PeerId::from_bytes(b"receiver".to_vec());
    let message = Message::new(
        sender, 
        receiver, 
        "Test message".to_string(),
        "test_session".to_string()
    );
    
    // Envoyer message sans ACK requis
    let result = manager.send_with_guarantees(message.clone(), false).await;
    assert!(result.is_ok());
    
    let message_id = result.unwrap();
    assert_eq!(message_id, message.id);
    
    info!("✅ Message envoyé: {}", message_id);
}

#[tokio::test] 
async fn test_load_test_minimal() {
    // TDD GREEN: Test de charge minimal (10 messages)
    let _ = fmt::try_init();
    info!("🧪 Test charge minimal");
    
    let config = RobustMessagingConfig::default();
    let manager = RobustMessagingManager::new(config);
    
    // Test très simple: 10 messages
    let result = manager.load_test(10, false).await;
    assert!(result.is_ok());
    
    let load_results = result.unwrap();
    assert_eq!(load_results.total_sent, 10);
    assert!(load_results.elapsed_ms < 60000); // Moins de 60s
    
    info!(
        "✅ Test charge: {} messages en {}ms", 
        load_results.total_sent, load_results.elapsed_ms
    );
}