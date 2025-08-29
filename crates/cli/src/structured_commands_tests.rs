//! Tests dédiés aux nouvelles commandes structurées LAN et NET
//!
//! Ces tests vérifient que les nouvelles commandes CLI v0.2.0
//! compilent correctement et exécutent les chemins de code prévus.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn test_mdns_command_variants() {
        // Test creation of all MdnsCommand variants
        let announce = MdnsCommand::Announce {
            duration: 10,
            port: 1234,
        };

        let list_peers = MdnsCommand::ListPeers { timeout: 5 };

        // Verify they implement Debug
        println!("{:?}", announce);
        println!("{:?}", list_peers);
    }

    #[test]
    fn test_unified_command_variants() {
        // Test creation of all UnifiedCommand variants
        let start = UnifiedCommand::Start {
            duration: 1, // 1 second for testing
            methods: vec!["mdns".to_string(), "dht".to_string()],
        };

        let announce = UnifiedCommand::Announce;

        let list_peers = UnifiedCommand::ListPeers { timeout: 5 };

        let find = UnifiedCommand::Find {
            peer_id: "test-peer".to_string(),
            timeout: 3,
        };

        // Verify they implement Debug
        println!("{:?}", start);
        println!("{:?}", announce);
        println!("{:?}", list_peers);
        println!("{:?}", find);
    }

    #[test]
    fn test_structured_command_hierarchy() {
        // Test the full command hierarchy
        let lan_cmd = Command::Lan(LanCommand::Mdns(MdnsCommand::Announce {
            duration: 1, // 1 second for testing
            port: 8080,
        }));

        let net_cmd = Command::Net(NetCommand::Unified(UnifiedCommand::Start {
            duration: 1, // 1 second for testing
            methods: vec!["mdns".to_string()],
        }));

        // Verify they implement Debug
        println!("{:?}", lan_cmd);
        println!("{:?}", net_cmd);
    }

    #[tokio::test]
    async fn test_lan_mdns_announce_error_handling() {
        // Test LAN MDNS Announce with invalid parameters
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Lan(LanCommand::Mdns(MdnsCommand::Announce {
                duration: 0, // Test edge case
                port: 1,     // Low port number
            })),
        };

        // Should not panic, may return error due to port binding
        let _result = run_internal(cli, &mut ks).await;
    }

    #[tokio::test]
    async fn test_lan_mdns_list_peers_timeout_zero() {
        // Test LAN MDNS ListPeers with zero timeout
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Lan(LanCommand::Mdns(MdnsCommand::ListPeers {
                timeout: 0, // Edge case: immediate timeout
            })),
        };

        // Should complete quickly without hanging
        let start = std::time::Instant::now();
        let _result = run_internal(cli, &mut ks).await;
        let duration = start.elapsed();

        // Should complete in less than 2 seconds even with network operations
        assert!(
            duration.as_secs() < 2,
            "Command took too long: {:?}",
            duration
        );
    }

    #[tokio::test]
    async fn test_net_unified_start_empty_methods() {
        // Test NET Unified Start with empty methods
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Net(NetCommand::Unified(UnifiedCommand::Start {
                duration: 1,
                methods: vec![], // Empty methods list
            })),
        };

        // Should handle empty methods gracefully
        let _result = run_internal(cli, &mut ks).await;
    }

    #[tokio::test]
    async fn test_net_unified_start_invalid_methods() {
        // Test NET Unified Start with invalid methods
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Net(NetCommand::Unified(UnifiedCommand::Start {
                duration: 1,
                methods: vec!["invalid".to_string(), "unknown".to_string()],
            })),
        };

        // Should handle invalid methods gracefully (with warnings)
        let _result = run_internal(cli, &mut ks).await;
    }

    #[tokio::test]
    async fn test_net_unified_find_empty_peer_id() {
        // Test NET Unified Find with empty peer ID
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Net(NetCommand::Unified(UnifiedCommand::Find {
                peer_id: "".to_string(), // Empty peer ID
                timeout: 0, // Zero timeout for instant return
            })),
        };

        // Should handle empty peer ID gracefully
        let _result = run_internal(cli, &mut ks).await;
    }

    #[test]
    fn test_cli_debug_formatting_structured_commands() {
        // Test Debug formatting for structured commands
        let cli = Cli {
            log: "debug".to_string(),
            json: true,
            cmd: Command::Lan(LanCommand::Mdns(MdnsCommand::ListPeers { timeout: 10 })),
        };

        let debug_str = format!("{:?}", cli);
        assert!(debug_str.contains("Lan"));
        assert!(debug_str.contains("Mdns"));
        assert!(debug_str.contains("ListPeers"));
        assert!(debug_str.contains("timeout: 10"));
    }

    #[test]
    fn test_method_parsing_cases() {
        // Test various method string cases that might be encountered
        let methods = vec![
            "mdns".to_string(),
            "MDNS".to_string(),
            "dht".to_string(),
            "DHT".to_string(),
            "manual".to_string(),
            "MANUAL".to_string(),
            "invalid_method".to_string(),
            "".to_string(),
        ];

        let cmd = UnifiedCommand::Start {
            duration: 5,
            methods,
        };

        // Should create successfully regardless of case/validity
        // (validation happens at runtime)
        println!("{:?}", cmd);
    }
}
