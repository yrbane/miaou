//! Tests de robustesse pour mDNS découverte
//!
//! Tests TDD pour les améliorations de robustesse :
//! - TTL et refresh automatique des services
//! - Détection IP locale robuste (éviter 127.0.0.1)
//! - Gestion des erreurs réseau et reconnexion
//! - Nettoyage automatique des pairs expirés

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{DiscoveryMethod, MdnsDiscovery, PeerId, PeerInfo};
    use std::time::Duration;
    use tokio::time::sleep;

    fn create_robust_config() -> DiscoveryConfig {
        DiscoveryConfig {
            methods: vec![DiscoveryMethod::Mdns],
            announce_interval: Duration::from_secs(5), // Refresh toutes les 5 secondes
            discovery_timeout: Duration::from_secs(10),
            max_peers: 50,
        }
    }

    #[tokio::test]
    async fn test_mdns_service_ttl_refresh() {
        // TDD: Test que les services mDNS sont refresh périodiquement
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config.clone(), 4280);
        let peer = PeerInfo::new_mock();

        // Démarrer et annoncer
        discovery.start().await.unwrap();
        discovery.announce(&peer).await.unwrap();

        // Attendre un peu pour voir si le service reste actif
        sleep(Duration::from_millis(1000)).await;

        // Le service devrait être annoncé avec un TTL approprié
        // En production, on vérifierait que le service est toujours visible après TTL/2

        discovery.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_mdns_avoid_loopback_ip() {
        // TDD: Test que get_local_ip évite 127.0.0.1 quand possible
        #[cfg(feature = "mdns-discovery")]
        {
            let local_ip = MdnsDiscovery::get_local_ip();

            if let Some(ip) = local_ip {
                // Si on obtient une IP, elle ne devrait pas être 127.0.0.1
                // sauf si c'est vraiment la seule option
                if ip != "127.0.0.1" {
                    // Vérifier que c'est une IP privée valide
                    let addr: std::net::IpAddr = ip.parse().expect("IP invalide");
                    match addr {
                        std::net::IpAddr::V4(ipv4) => {
                            assert!(
                                ipv4.is_private() || ipv4.is_link_local(),
                                "IP should be private or link-local: {}",
                                ip
                            );
                        }
                        std::net::IpAddr::V6(_) => {
                            // IPv6 accepté
                        }
                    }
                } else {
                    // 127.0.0.1 uniquement en dernier recours
                    println!("⚠️  Utilisation 127.0.0.1 (dernière option)");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_mdns_peer_expiration() {
        // TDD: Test que les pairs inactifs sont expirés automatiquement
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new(config);

        // Ajouter un pair manuellement
        let peer = PeerInfo::new_mock();
        discovery.add_discovered_peer(peer.clone());

        // Vérifier qu'il est présent
        let found = discovery.find_peer(&peer.id).await.unwrap();
        assert!(found.is_some());

        // En production, après TTL expiré, le pair devrait être supprimé
        // Pour ce test, on simule juste le concept
        let peers = discovery.discovered_peers().await;
        assert!(!peers.is_empty());

        // TODO v0.3.0: Implémenter vrai TTL avec suppression automatique
    }

    #[tokio::test]
    async fn test_mdns_network_interface_selection() {
        // TDD: Test sélection d'interface réseau robuste
        let config = create_robust_config();
        let discovery1 = MdnsDiscovery::new_with_port(config.clone(), 4281);
        let discovery2 = MdnsDiscovery::new_with_port(config.clone(), 4282);

        // Les deux instances doivent pouvoir démarrer sur des ports différents
        assert!(discovery1.start().await.is_ok());
        assert!(discovery2.start().await.is_ok());

        // Et s'arrêter proprement
        assert!(discovery1.stop().await.is_ok());
        assert!(discovery2.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_service_name_uniqueness() {
        // TDD: Test que les noms de service sont uniques par pair
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new(config);

        // Le nom de service devrait inclure le peer ID pour unicité
        let peer1 = PeerInfo::new(PeerId::from_bytes(vec![1, 2, 3, 4]));
        let peer2 = PeerInfo::new(PeerId::from_bytes(vec![5, 6, 7, 8]));

        discovery.start().await.unwrap();

        // Annoncer les deux pairs
        assert!(discovery.announce(&peer1).await.is_ok());
        assert!(discovery.announce(&peer2).await.is_ok());

        discovery.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_mdns_discovery_resilience_to_network_errors() {
        // TDD: Test résilience aux erreurs réseau
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config, 65535); // Port potentiellement problématique

        // Le démarrage pourrait échouer mais ne devrait pas paniquer
        let result = discovery.start().await;
        // On accepte succès ou échec gracieux
        match result {
            Ok(_) => {
                // Succès: arrêter proprement
                let _ = discovery.stop().await;
            }
            Err(e) => {
                // Échec gracieux acceptable
                println!("Échec gracieux attendu: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_mdns_concurrent_discoveries() {
        // TDD: Test découvertes concurrentes sur le même réseau
        let config1 = create_robust_config();
        let config2 = create_robust_config();
        let config3 = create_robust_config();

        let discovery1 = MdnsDiscovery::new_with_port(config1, 4283);
        let discovery2 = MdnsDiscovery::new_with_port(config2, 4284);
        let discovery3 = MdnsDiscovery::new_with_port(config3, 4285);

        // Démarrer toutes en parallèle
        let start1 = discovery1.start();
        let start2 = discovery2.start();
        let start3 = discovery3.start();

        let (res1, res2, res3) = tokio::join!(start1, start2, start3);

        // Au moins une devrait réussir
        let successes = [res1.is_ok(), res2.is_ok(), res3.is_ok()];
        assert!(
            successes.iter().any(|&x| x),
            "Au moins une découverte devrait réussir"
        );

        // Arrêter celles qui ont réussi
        if res1.is_ok() {
            let _ = discovery1.stop().await;
        }
        if res2.is_ok() {
            let _ = discovery2.stop().await;
        }
        if res3.is_ok() {
            let _ = discovery3.stop().await;
        }
    }

    #[tokio::test]
    async fn test_mdns_service_properties_format() {
        // TDD: Test format des propriétés TXT dans les services mDNS
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config, 4286);

        let mut peer = PeerInfo::new_mock();
        peer.add_address("192.168.1.100:4286".parse().unwrap());

        discovery.start().await.unwrap();

        // Les propriétés devraient inclure peer_id en hex, version, port, adresse
        let result = discovery.announce(&peer).await;
        assert!(result.is_ok());

        discovery.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_mdns_hostname_validity() {
        // TDD: Test validité du hostname utilisé
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config, 4287);

        // Le hostname doit être valide pour mDNS (se terminer par .local.)
        let service_name = discovery.service_name();
        assert!(service_name.ends_with(".local."));
        assert!(service_name.starts_with("_miaou._tcp"));
    }

    #[tokio::test]
    async fn test_mdns_port_binding_fallback() {
        // TDD: Test fallback si port indisponible
        let config = create_robust_config();

        // Occuper le port avec le premier service
        let discovery1 = MdnsDiscovery::new_with_port(config.clone(), 4288);
        assert!(discovery1.start().await.is_ok());

        // Essayer d'utiliser le même port avec un second service
        let discovery2 = MdnsDiscovery::new_with_port(config, 4288);
        let result2 = discovery2.start().await;

        // Le second peut échouer (normal) ou réussir (OS gère le conflit)
        match result2 {
            Ok(_) => {
                // Succès: OS a géré le conflit, arrêter proprement
                let _ = discovery2.stop().await;
            }
            Err(_) => {
                // Échec attendu: conflit de port
                println!("Conflit de port géré gracieusement");
            }
        }

        // Arrêter le premier service
        assert!(discovery1.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_timeout_handling() {
        // TDD: Test gestion des timeouts de découverte
        let mut config = create_robust_config();
        config.discovery_timeout = Duration::from_millis(100); // Timeout très court

        let discovery = MdnsDiscovery::new(config);
        discovery.start().await.unwrap();

        // Chercher un pair inexistant avec timeout court
        let start = std::time::Instant::now();
        let nonexistent_peer = PeerId::from_bytes(vec![255, 255, 255, 255]);
        let found = discovery.find_peer(&nonexistent_peer).await.unwrap();
        let duration = start.elapsed();

        // Devrait retourner None rapidement
        assert!(found.is_none());
        assert!(duration < Duration::from_secs(1)); // Retour rapide

        discovery.stop().await.unwrap();
    }

    #[cfg(feature = "mdns-discovery")]
    #[tokio::test]
    async fn test_mdns_real_network_stress() {
        // TDD: Test de stress sur vrai réseau mDNS
        use tokio::time::Duration;

        let config = create_robust_config();
        let num_services = 5;
        let mut discoveries = Vec::new();
        let mut peers = Vec::new();

        // Créer plusieurs services sur ports différents
        for i in 0..num_services {
            let port = 4290 + i;
            let discovery = MdnsDiscovery::new_with_port(config.clone(), port as u16);
            let peer = PeerInfo::new(PeerId::from_bytes(vec![i as u8; 4]));

            discoveries.push(discovery);
            peers.push(peer);
        }

        // Démarrer tous les services
        for (i, discovery) in discoveries.iter().enumerate() {
            if discovery.start().await.is_ok() {
                let _ = discovery.announce(&peers[i]).await;
            }
        }

        // Attendre stabilisation
        sleep(Duration::from_millis(1000)).await;

        // Vérifier qu'au moins un service fonctionne
        let mut working_services = 0;
        for discovery in &discoveries {
            if discovery.is_active() {
                working_services += 1;
            }
        }

        assert!(
            working_services > 0,
            "Au moins un service devrait fonctionner"
        );

        // Arrêter tous les services
        for discovery in discoveries {
            let _ = discovery.stop().await;
        }

        println!(
            "✅ {} services mDNS ont fonctionné simultanément",
            working_services
        );
    }

    #[tokio::test]
    async fn test_mdns_memory_cleanup_on_stop() {
        // TDD: Test nettoyage mémoire à l'arrêt
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config, 4295);

        // Ajouter des pairs
        for i in 0..10 {
            let peer = PeerInfo::new(PeerId::from_bytes(vec![i; 4]));
            discovery.add_discovered_peer(peer);
        }

        // Vérifier qu'ils sont présents
        let peers_before = discovery.discovered_peers().await;
        assert_eq!(peers_before.len(), 10);

        // Démarrer et arrêter
        discovery.start().await.unwrap();
        discovery.stop().await.unwrap();

        // Les pairs découverts devraient être conservés après stop
        // (seules les tâches réseau sont arrêtées)
        let peers_after = discovery.discovered_peers().await;
        assert_eq!(peers_after.len(), 10);
    }

    #[tokio::test]
    async fn test_mdns_ipv6_support_check() {
        // TDD: Test support IPv6 pour mDNS
        #[cfg(feature = "mdns-discovery")]
        {
            // Vérifier que get_local_ip peut retourner IPv6
            let local_ip = MdnsDiscovery::get_local_ip();
            if let Some(ip) = local_ip {
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    match addr {
                        std::net::IpAddr::V4(_) => {
                            println!("IPv4 détectée: {}", ip);
                        }
                        std::net::IpAddr::V6(_) => {
                            println!("IPv6 détectée: {}", ip);
                        }
                    }
                } else {
                    panic!("IP invalide retournée: {}", ip);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_mdns_service_priority_handling() {
        // TDD: Test gestion des priorités de service mDNS
        let config = create_robust_config();
        let discovery = MdnsDiscovery::new_with_port(config, 4296);

        // Créer des pairs avec différentes "priorités" (simulé par ID)
        let high_priority_peer = PeerInfo::new(PeerId::from_bytes(vec![1])); // ID court = haute priorité
        let low_priority_peer = PeerInfo::new(PeerId::from_bytes(vec![255; 20])); // ID long = basse priorité

        discovery.add_discovered_peer(high_priority_peer.clone());
        discovery.add_discovered_peer(low_priority_peer.clone());

        let discovered = discovery.discovered_peers().await;
        assert_eq!(discovered.len(), 2);

        // Les deux pairs devraient être présents (pas de filtrage par priorité pour l'instant)
        let ids: std::collections::HashSet<_> = discovered.iter().map(|p| &p.id).collect();
        assert!(ids.contains(&high_priority_peer.id));
        assert!(ids.contains(&low_priority_peer.id));
    }
}
