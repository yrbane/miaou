//! Exemple d'utilisation de miaou-network v0.2.0
//! 
//! Ce programme démontre :
//! - Création d'un pair P2P
//! - Découverte de pairs via mDNS et DHT
//! - Envoi de messages chiffrés

use miaou_network::{
    Discovery, DiscoveryConfig, DiscoveryMethod, UnifiedDiscovery,
    MessageQueue, InMemoryMessageQueue, MessageQueueConfig,
    PeerInfo, PeerId, NetworkError
};
use std::time::Duration;
use tokio;

#[tokio::main]
async fn main() -> Result<(), NetworkError> {
    println!("🐱 Miaou P2P v0.2.0 - Exemple");
    
    // 1. Créer un ID de pair unique
    let local_peer_id = PeerId::from_bytes(b"example_peer_123".to_vec());
    let local_peer_info = PeerInfo::new(local_peer_id.clone());
    
    // 2. Configuration discovery (mDNS + DHT)
    let discovery_config = DiscoveryConfig {
        methods: vec![DiscoveryMethod::Mdns, DiscoveryMethod::Dht],
        max_peers: 10,
        announcement_interval_seconds: 30,
        ..Default::default()
    };
    
    // 3. Créer le système de découverte unifié
    let mut discovery = UnifiedDiscovery::new(discovery_config, local_peer_info).await?;
    
    // 4. Créer la queue de messages
    let queue_config = MessageQueueConfig::default();
    let message_queue = InMemoryMessageQueue::new(queue_config);
    
    println!("✅ Pair créé avec ID: {}", local_peer_id);
    
    // 5. Démarrer la découverte
    discovery.start().await?;
    println!("🔍 Découverte démarrée (mDNS + DHT)...");
    
    // 6. Attendre et chercher des pairs
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    let discovered_peers = discovery.discovered_peers().await;
    println!("📡 Pairs découverts: {}", discovered_peers.len());
    
    for peer in discovered_peers {
        println!("  - Pair: {} à {}", peer.id, peer.address);
    }
    
    // 7. Statistiques
    let stats = discovery.get_stats().await;
    println!("📊 Stats discovery: {} méthodes actives", stats.len());
    
    // 8. Arrêt propre
    discovery.stop().await?;
    println!("🛑 Discovery arrêtée");
    
    Ok(())
}