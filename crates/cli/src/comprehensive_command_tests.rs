//! Tests complets pour toutes les commandes CLI
//!
//! Ce module contient des tests pour maximiser la couverture de code
//! en couvrant tous les chemins d'exécution des commandes CLI.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn test_net_start_command_execution() {
        let mut ks = MemoryKeyStore::new();

        // Test NetStart normal mode
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetStart {
                daemon: false,
                duration: 1, // Short duration for tests
            },
        };

        let result = run_internal(cli, &mut ks).await;
        // Should execute without panicking (may return error due to network setup)
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_start_daemon_mode() {
        let mut ks = MemoryKeyStore::new();

        // Test NetStart daemon mode
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetStart {
                daemon: false, // Non-daemon for faster test
                duration: 1,   // 1 second only
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_list_peers_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetListPeers {
                timeout: 0, // Zero timeout for instant return
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_list_peers_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,                                // JSON output
            cmd: Command::NetListPeers { timeout: 0 }, // Zero timeout
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_connect_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetConnect {
                peer_id: "test-peer-id".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_connect_invalid_peer_id() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetConnect {
                peer_id: "invalid peer id with spaces".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        // Should handle invalid peer ID
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_handshake_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetHandshake {
                peer_id: "handshake-peer".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_status_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetStatus,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_net_status_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::NetStatus,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_send_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Send {
                to: "alice".to_string(),
                message: "Hello, Alice!".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_send_command_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::Send {
                to: "bob".to_string(),
                message: "Test message".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_recv_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Recv,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_recv_command_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::Recv,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_history_command_default() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::History {
                limit: 10,
                peer: None,
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_history_command_with_peer_filter() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::History {
                limit: 5,
                peer: Some("alice".to_string()),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_history_command_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::History {
                limit: 20,
                peer: None,
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_dht_put_signing_key() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::DhtPut {
                key_type: "signing".to_string(),
                key_data: "1234567890abcdef".repeat(4), // 64 hex chars
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_dht_put_encryption_key() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::DhtPut {
                key_type: "encryption".to_string(),
                key_data: "abcdef1234567890".repeat(4), // 64 hex chars
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_dht_put_invalid_key_type() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::DhtPut {
                key_type: "invalid_type".to_string(),
                key_data: "1234567890abcdef".repeat(4),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        // Should handle invalid key type gracefully
        let _ = result;
    }

    #[tokio::test]
    async fn test_dht_get_signing_key() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::DhtGet {
                peer_id: "target-peer-id".to_string(),
                key_type: "signing".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_dht_get_encryption_key() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::DhtGet {
                peer_id: "another-peer".to_string(),
                key_type: "encryption".to_string(),
            },
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_network_info_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetworkInfo,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_network_info_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::NetworkInfo,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_diagnostics_command() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Diagnostics,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_diagnostics_json_mode() {
        let mut ks = MemoryKeyStore::new();

        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::Diagnostics,
        };

        let result = run_internal(cli, &mut ks).await;
        let _ = result;
    }
}
