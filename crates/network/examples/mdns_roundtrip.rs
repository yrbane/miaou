//! # Exemple mDNS Roundtrip - Démo découverte LAN v0.2.0
//!
//! **Démonstrateur pratique** pour la release v0.2.0 "Radar à Moustaches".
//!
//! Ce programme :
//! 1. **Démarre** un service mDNS local
//! 2. **Annonce** le peer sur `_miaou._tcp.local`  
//! 3. **Écoute** pendant 10 secondes pour découvrir d'autres pairs
//! 4. **Affiche** le résultat JSON des pairs découverts
//! 5. **Arrête** proprement le service
//!
//! ## Usage
//!
//! **Terminal 1:**
//! ```bash
//! cargo run --example mdns_roundtrip
//! ```
//!
//! **Terminal 2 (dans les 10 secondes):**
//! ```bash
//! cargo run --example mdns_roundtrip
//! ```
//!
//! → Les deux instances devraient se découvrir mutuellement !
//!
//! ## Sortie attendue
//!
//! ```json
//! {
//!   "local_peer": {
//!     "id": "miaou-demo-1234",
//!     "address": "192.168.1.100:4242",
//!     "service": "_miaou._tcp.local"
//!   },
//!   "discovered_peers": [
//!     {
//!       "id": "miaou-demo-5678", 
//!       "addresses": ["192.168.1.101:4242"]
//!     }
//!   ],
//!   "discovery_duration_seconds": 10,
//!   "timestamp": 1756400000
//! }
//! ```

#![forbid(unsafe_code)]

use miaou_network::{Discovery, MdnsDiscovery, PeerId, PeerInfo};
use std::net::{IpAddr, UdpSocket};
use tokio::time::{sleep, Duration};

/// Détecte l'adresse IP locale non-loopback
fn get_local_ip() -> Option<String> {
    // Méthode UDP socket fictif pour détecter IP sortante
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?; // Google DNS comme destination fictive
    let local_addr = socket.local_addr().ok()?;
    
    match local_addr.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip.to_string()),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration de base  
    let discovery_duration = 10; // secondes
    let service_port = 4242;
    
    println!("🚀 Démarrage démonstrateur mDNS Roundtrip v0.2.0");
    println!("==================================================");
    
    // Générer un peer ID unique pour cette démo
    let local_peer_id = PeerId::from_bytes(
        format!("miaou-demo-{}", rand::random::<u16>()).into_bytes()
    );
    
    // Détecter l'IP locale (éviter 127.0.0.1)
    let local_ip = get_local_ip().unwrap_or_else(|| {
        println!("⚠️  Impossible de détecter l'IP locale, utilisation de 127.0.0.1");
        "127.0.0.1".to_string()
    });
    
    // Créer le PeerInfo local
    let mut local_peer_info = PeerInfo::new(local_peer_id.clone());
    let local_address = format!("{}:{}", local_ip, service_port);
    local_peer_info.add_address(local_address.parse()?);
    
    println!("📋 Configuration locale:");
    println!("   • Peer ID: {}", local_peer_info.id.short());
    println!("   • Adresse: {}", local_address);
    println!("   • Service: _miaou._tcp.local");
    println!();
    
    // Créer et démarrer le service mDNS
    println!("📡 Phase 1: Démarrage du service mDNS...");
    let mdns_discovery = MdnsDiscovery::new(Default::default());
    
    mdns_discovery.start().await?;
    println!("   ✅ Service mDNS démarré");
    
    // Annoncer ce peer sur le réseau
    println!("\n📢 Phase 2: Annonce du peer sur le réseau LAN...");
    mdns_discovery.announce(&local_peer_info).await?;
    println!("   ✅ Peer annoncé via mDNS");
    
    // Écouter et découvrir les autres pairs
    println!("\n🔍 Phase 3: Écoute et découverte ({}s)...", discovery_duration);
    println!("   Recherche d'autres instances de miaou sur le réseau...");
    
    // Affichage progressif
    for i in 1..=discovery_duration {
        print!("   [{:2}/{}] Écoute en cours", i, discovery_duration);
        if i % 3 == 0 {
            print!(" 🔄");
        }
        println!();
        sleep(Duration::from_secs(1)).await;
    }
    
    // Collecter les résultats
    println!("\n📊 Phase 4: Collecte des résultats...");
    let discovered_peers = mdns_discovery.discovered_peers().await;
    
    // Arrêter le service proprement  
    println!("\n🛑 Phase 5: Arrêt du service...");
    mdns_discovery.stop().await?;
    println!("   ✅ Service mDNS arrêté proprement");
    
    // Générer la sortie JSON finale
    println!("\n🎯 Résultats de la découverte:");
    println!("==============================");
    
    let result = serde_json::json!({
        "demo": "mDNS Roundtrip v0.2.0",
        "local_peer": {
            "id": local_peer_info.id.to_string(),
            "short_id": local_peer_info.id.short(),
            "address": local_address,
            "service": "_miaou._tcp.local"
        },
        "discovered_peers": discovered_peers.iter().map(|peer| {
            serde_json::json!({
                "id": peer.id.to_string(),
                "short_id": peer.id.short(),
                "addresses": peer.addresses
            })
        }).collect::<Vec<_>>(),
        "stats": {
            "local_peers": discovered_peers.len(),
            "discovery_duration_seconds": discovery_duration,
            "success": !discovered_peers.is_empty()
        },
        "timestamp": chrono::Utc::now().timestamp(),
        "version": "0.2.0"
    });
    
    println!("{}", serde_json::to_string_pretty(&result)?);
    
    // Message final de succès/information
    if discovered_peers.is_empty() {
        println!("\n💡 Aucun autre pair découvert.");
        println!("   Pour tester la découverte mutuelle:");
        println!("   1. Lancez cette démo dans un autre terminal");
        println!("   2. Ou sur une autre machine du même réseau LAN");
        println!("   3. Dans les {} secondes suivant le démarrage", discovery_duration);
    } else {
        println!("\n🎉 Succès ! {} pair(s) découvert(s) sur le LAN.", discovered_peers.len());
        println!("   La découverte mDNS fonctionne parfaitement !");
    }
    
    println!("\n✨ Démonstrateur terminé. mDNS v0.2.0 opérationnel !");
    
    Ok(())
}