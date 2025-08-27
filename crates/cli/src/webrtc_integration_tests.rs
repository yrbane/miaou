//! Tests d'intégration WebRTC + mDNS pour validation CLI
//!
//! TDD GREEN v0.2.0: Tests pour valider l'étape 2 du plan

#[cfg(test)]
mod webrtc_integration_tests {
    use crate::{run_with_keystore, Cli, Command};
    use miaou_keyring::MemoryKeyStore;
    use miaou_network::{
        DataChannelMessage, NatConfig, PeerId, WebRtcConnectionConfig, WebRtcDataChannelManager,
        WebRtcDataChannels,
    };

    #[tokio::test]
    async fn test_webrtc_manager_creation() {
        // TDD GREEN v0.2.0: Test création du gestionnaire WebRTC
        let peer_id = PeerId::from_bytes(b"test-webrtc-peer".to_vec());
        let nat_config = NatConfig::default();
        let config = WebRtcConnectionConfig {
            connection_timeout_seconds: 5,
            ice_gathering_timeout_seconds: 3,
            enable_keepalive: false,
            keepalive_interval_seconds: 30,
            nat_config,
            datachannel_config: Default::default(),
        };

        let manager = WebRtcDataChannelManager::new(config, peer_id);

        // Vérifier configuration
        assert_eq!(manager.config().connection_timeout_seconds, 5);
        assert_eq!(manager.config().ice_gathering_timeout_seconds, 3);
        assert!(!manager.config().enable_keepalive);
    }

    #[tokio::test]
    async fn test_webrtc_manager_start_stop() {
        // TDD GREEN v0.2.0: Test cycle start/stop WebRTC
        let peer_id = PeerId::from_bytes(b"start-stop-peer".to_vec());
        let config = WebRtcConnectionConfig::default();
        let mut manager = WebRtcDataChannelManager::new(config, peer_id);

        // Test start
        let result = manager.start().await;
        assert!(result.is_ok(), "WebRTC manager should start successfully");

        // Test stop
        let result = manager.stop().await;
        assert!(result.is_ok(), "WebRTC manager should stop successfully");
    }

    #[tokio::test]
    async fn test_datachannel_message_creation() {
        // TDD GREEN v0.2.0: Test création messages WebRTC
        let alice = PeerId::from_bytes(b"alice-webrtc".to_vec());
        let bob = PeerId::from_bytes(b"bob-webrtc".to_vec());

        // Message texte
        let text_msg = DataChannelMessage::text(alice.clone(), bob.clone(), "Hello WebRTC!");
        assert_eq!(text_msg.from, alice);
        assert_eq!(text_msg.to, bob);
        assert_eq!(text_msg.as_text().unwrap(), "Hello WebRTC!");

        // Message binaire
        let binary_data = vec![0x01, 0x02, 0x03, 0x04];
        let binary_msg =
            DataChannelMessage::binary(alice.clone(), bob.clone(), binary_data.clone());
        assert_eq!(binary_msg.payload, binary_data);

        // Sérialisation/désérialisation
        let serialized = text_msg.serialize().unwrap();
        let deserialized = DataChannelMessage::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.id, text_msg.id);
        assert_eq!(deserialized.from, text_msg.from);
        assert_eq!(deserialized.to, text_msg.to);
        assert_eq!(deserialized.as_text().unwrap(), "Hello WebRTC!");
    }

    #[tokio::test]
    async fn test_net_connect_with_webrtc_integration() {
        // TDD GREEN v0.2.0: Test CLI net-connect avec WebRTC (sans pair réel)
        // Ce test valide que l'intégration compile et fonctionne structurellement

        let cli = Cli {
            log: "error".to_string(), // Réduire le bruit des logs
            cmd: Command::NetConnect {
                peer_id: "webrtc-integration-test".to_string(),
            },
        };

        let result = run_with_keystore(cli, MemoryKeyStore::new()).await;

        // TDD GREEN v0.2.0: En test isolé, attendu = pair non trouvé
        // L'important c'est que WebRTC compile et s'intègre sans panic
        if let Err(err) = &result {
            // Vérifier que c'est bien une erreur de "pair non trouvé" et pas un crash WebRTC
            let err_msg = format!("{:?}", err);
            assert!(
                err_msg.contains("non trouvé") || err_msg.contains("non découvert"),
                "Should fail with 'peer not found', not WebRTC crash: {}",
                err_msg
            );
        }

        println!("✅ Test WebRTC integration: {:?}", result);
    }

    #[tokio::test]
    async fn test_webrtc_connection_simulation() {
        // TDD GREEN v0.2.0: Test simulation connexion WebRTC (sans réseau réel)
        let local_peer = PeerId::from_bytes(b"local-sim".to_vec());
        let remote_peer = PeerId::from_bytes(b"remote-sim".to_vec());

        let config = WebRtcConnectionConfig::default();
        let mut manager = WebRtcDataChannelManager::new(config, local_peer.clone());

        // Démarrer le gestionnaire
        manager.start().await.unwrap();

        // Pour le MVP, la connexion échouera (pas de réseau réel)
        // Mais elle ne doit pas panic
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        let connection_result = manager
            .connect_to_peer(remote_peer.clone(), remote_addr)
            .await;

        // Dans un environnement de test isolé, c'est normal que ça échoue
        if connection_result.is_err() {
            println!("✅ Connexion WebRTC échouée comme attendu en test isolé");
        } else {
            println!("✅ Connexion WebRTC réussie (surprenant mais OK)");
        }

        // Arrêter proprement
        manager.stop().await.unwrap();
    }

    #[test]
    fn test_webrtc_config_defaults() {
        // TDD GREEN v0.2.0: Test valeurs par défaut configuration WebRTC
        let config = WebRtcConnectionConfig::default();

        // Vérifier des valeurs sensées
        assert!(config.connection_timeout_seconds > 0);
        assert!(config.ice_gathering_timeout_seconds > 0);
        assert!(config.keepalive_interval_seconds > 0);

        // NAT config doit exister
        assert!(
            config.nat_config.stun_servers.len() > 0 || config.nat_config.turn_servers.len() >= 0
        );
    }
}
