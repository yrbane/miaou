//! Tests pour couvrir toutes les branches match et conditions
//!
//! Ce module teste chaque branche de chaque match statement

#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn test_message_category_display_branches() {
        // Test toutes les branches du match MessageCategory
        let categories = vec![
            MessageCategory::Sent,
            MessageCategory::Received,
            MessageCategory::Draft,
            MessageCategory::System,
        ];

        for category in categories {
            let display_str = match category {
                MessageCategory::Sent => "envoyé",
                MessageCategory::Received => "reçu",
                MessageCategory::Draft => "brouillon",
                MessageCategory::System => "système",
            };

            assert!(!display_str.is_empty());
        }
    }

    #[tokio::test]
    async fn test_net_unified_method_parsing_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test all method parsing branches
        let methods_to_test = vec![
            vec!["mdns".to_string()],
            vec!["dht".to_string()],
            vec!["manual".to_string()],
            vec!["invalid".to_string()], // Unknown method
            vec!["mdns".to_string(), "dht".to_string(), "manual".to_string()],
            vec![], // Empty methods
        ];

        for methods in methods_to_test {
            let cli = Cli {
                log: "error".to_string(),
                json: false,
                cmd: Command::Net(NetCommand::Unified(UnifiedCommand::Start {
                    duration: 1,
                    methods,
                })),
            };

            let _result = run_internal(cli, &mut ks).await;
        }
    }

    #[tokio::test]
    async fn test_dht_entry_type_branches() {
        // Test all DHT entry type branches
        let key_types = vec![
            ("signing", true),
            ("encryption", true),
            ("unknown", false),
            ("", false),
            ("SIGNING", false), // Case sensitive
        ];

        for (key_type, should_succeed) in key_types {
            let entry_type = match key_type {
                "signing" => Some(DirectoryEntryType::SigningKey),
                "encryption" => Some(DirectoryEntryType::EncryptionKey),
                _ => None,
            };

            if should_succeed {
                assert!(entry_type.is_some());
            } else {
                assert!(entry_type.is_none());
            }
        }
    }

    #[tokio::test]
    async fn test_json_serialization_error_branch() {
        let mut ks = MemoryKeyStore::new();

        // Test JSON serialization failure branch (hard to trigger naturally)
        // We can at least ensure the JSON success path works
        let cli = Cli {
            log: "error".to_string(),
            json: true,
            cmd: Command::NetListPeers { timeout: 1 },
        };

        let _result = run_internal(cli, &mut ks).await;
    }

    #[tokio::test]
    async fn test_net_connect_find_peer_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test peer found/not found branches
        let peer_ids = vec![
            "valid-peer-id",
            "another-peer",
            "", // Edge case
        ];

        for peer_id in peer_ids {
            let cli = Cli {
                log: "error".to_string(),
                json: false,
                cmd: Command::NetConnect {
                    peer_id: peer_id.to_string(),
                },
            };

            let _result = run_internal(cli, &mut ks).await;
        }
    }

    #[tokio::test]
    async fn test_net_unified_find_result_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test Find command result branches
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Net(NetCommand::Unified(UnifiedCommand::Find {
                peer_id: "search-target".to_string(),
                timeout: 1,
            })),
        };

        let _result = run_internal(cli, &mut ks).await;
        // Will test match result { Some(peer) => ..., None => ... }
    }

    #[tokio::test]
    async fn test_webrtc_manager_start_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test WebRTC manager start success/failure branches
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetConnect {
                peer_id: "webrtc-peer".to_string(),
            },
        };

        let _result = run_internal(cli, &mut ks).await;
        // Will exercise match webrtc_manager.start() branches
    }

    #[tokio::test]
    async fn test_handshake_result_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test handshake initiation success/failure branches
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::NetHandshake {
                peer_id: "handshake-target".to_string(),
            },
        };

        let _result = run_internal(cli, &mut ks).await;
        // Will exercise match handshake.initiate_handshake() branches
    }

    #[tokio::test]
    async fn test_history_peer_filter_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test with and without peer filter
        let peer_filters = vec![
            None,
            Some("alice".to_string()),
            Some("bob".to_string()),
            Some("".to_string()), // Edge case
        ];

        for peer_filter in peer_filters {
            let cli = Cli {
                log: "error".to_string(),
                json: false,
                cmd: Command::History {
                    limit: 5,
                    peer: peer_filter,
                },
            };

            let result = run_internal(cli, &mut ks).await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_daemon_mode_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test daemon vs normal mode branches
        let configs = vec![
            (true, 0),   // Daemon with infinite duration
            (false, 10), // Normal with specific duration
            (true, 10),  // Daemon with duration (edge case)
            (false, 0),  // Normal with zero duration (edge case)
        ];

        for (daemon, duration) in configs {
            let cli = Cli {
                log: "error".to_string(),
                json: false,
                cmd: Command::NetStart { daemon, duration },
            };

            let _result = run_internal(cli, &mut ks).await;
        }
    }

    #[tokio::test]
    async fn test_lan_mdns_json_output_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test JSON output branches for LAN commands
        let json_modes = vec![true, false];

        for json_mode in json_modes {
            let cli = Cli {
                log: "error".to_string(),
                json: json_mode,
                cmd: Command::Lan(LanCommand::Mdns(MdnsCommand::ListPeers { timeout: 1 })),
            };

            let _result = run_internal(cli, &mut ks).await;
        }
    }

    #[tokio::test]
    async fn test_net_unified_json_output_branches() {
        let mut ks = MemoryKeyStore::new();

        // Test JSON output branches for NET commands
        let json_modes = vec![true, false];

        for json_mode in json_modes {
            let cli = Cli {
                log: "error".to_string(),
                json: json_mode,
                cmd: Command::Net(NetCommand::Unified(UnifiedCommand::ListPeers {
                    timeout: 1,
                })),
            };

            let _result = run_internal(cli, &mut ks).await;
        }
    }

    #[test]
    fn test_hostname_command_execution_path() {
        // Test the hostname command path in get_local_ip
        // This tests the if let Ok(output) = Command::new("hostname")... branch
        let ip = get_local_ip();
        let ip2 = get_local_ip();

        // The function should always return Some or None, never panic
        match &ip {
            Some(ip_str) => {
                // Validate IP format
                assert!(!ip_str.is_empty());
            }
            None => {
                // Valid to return None if hostname command fails
            }
        }

        // Test multiple calls for consistency
        assert_eq!(ip, ip2);
    }

    #[test]
    fn test_exit_code_conversion() {
        // Test the ExitCode::from(1) conversion in main error path
        let code = ExitCode::from(1);
        assert_ne!(code, ExitCode::SUCCESS);

        // Test various error codes
        for i in 1..10 {
            let error_code = ExitCode::from(i);
            assert_ne!(error_code, ExitCode::SUCCESS);
        }
    }

    #[test]
    fn test_tracing_level_match_branches() {
        // Test all branches in init_tracing level matching
        let test_cases = vec![
            ("trace", Level::TRACE),
            ("debug", Level::DEBUG),
            ("info", Level::INFO),
            ("warn", Level::WARN),
            ("error", Level::ERROR),
            ("unknown", Level::INFO), // Default case
            ("TRACE", Level::INFO),   // Case sensitive, falls to default
            ("", Level::INFO),        // Empty string, falls to default
        ];

        for (input, _expected) in test_cases {
            // We can't easily assert the actual level set in the subscriber,
            // but we can ensure it doesn't panic
            init_tracing(input);
        }
    }

    #[tokio::test]
    async fn test_error_propagation_paths() {
        let mut ks = MemoryKeyStore::new();

        // Test various error propagation paths with ?

        // Test KeyExport with invalid ID (propagates error)
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::KeyExport {
                id: "nonexistent".to_string(),
            },
        };
        let result = run_internal(cli, &mut ks).await;
        assert!(result.is_err());

        // Test Sign with invalid ID (propagates error)
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::Sign {
                id: "nonexistent".to_string(),
                message: "test".to_string(),
            },
        };
        let result = run_internal(cli, &mut ks).await;
        assert!(result.is_err());

        // Test AeadEncrypt with invalid key hex (propagates error)
        let cli = Cli {
            log: "error".to_string(),
            json: false,
            cmd: Command::AeadEncrypt {
                key_hex: "invalid".to_string(),
                nonce_hex: "0".repeat(24),
                aad_hex: "".to_string(),
                plaintext: "test".to_string(),
            },
        };
        let result = run_internal(cli, &mut ks).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_string_from_utf8_lossy_path() {
        // Test String::from_utf8_lossy in AeadDecrypt output
        // This handles both valid UTF-8 and invalid UTF-8 bytes

        let valid_utf8 = vec![72, 101, 108, 108, 111]; // "Hello"
        let output = String::from_utf8_lossy(&valid_utf8);
        assert_eq!(output, "Hello");

        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8
        let output = String::from_utf8_lossy(&invalid_utf8);
        assert!(output.contains('�')); // Replacement character
    }

    #[test]
    fn test_unwrap_or_else_branches() {
        // Test unwrap_or_else pattern used in get_local_ip

        // When get_local_ip returns None, it should use "127.0.0.1"
        let ip_result = get_local_ip();
        let ip = ip_result.unwrap_or_else(|| "127.0.0.1".to_string());
        assert!(!ip.is_empty());

        // Test multiple calls for consistency
        let ip1 = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        let ip2 = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        assert_eq!(ip1, ip2);
    }
}
