//! Tests d'intégration "fumée" CLI pour v0.2.0
//!
//! Ces tests vérifient que les nouvelles commandes CLI compilent et s'exécutent.
//!
//! ## Usage
//!
//! ```bash  
//! # Tests de base (pas de réseau)
//! cargo test --package miaou-cli integration_smoke_tests
//!
//! # Tests réseau (marqués #[ignore])
//! cargo test --package miaou-cli integration_smoke_tests -- --ignored
//! ```

use std::process::Command;

/// Helper pour exécuter le CLI via cargo run
fn run_cli_command(args: &[&str]) -> std::process::Output {
    let mut cmd_args = vec!["run", "--package", "miaou-cli", "--"];
    cmd_args.extend_from_slice(args);

    Command::new("cargo")
        .args(&cmd_args)
        .output()
        .expect("Failed to execute CLI via cargo run")
}

/// Test que la nouvelle CLI structurée compile et montre l'aide
#[test]
fn test_structured_cli_help() {
    let output = run_cli_command(&["--help"]);

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);

    // Vérifier que les nouvelles commandes structurées existent
    assert!(help.contains("lan"), "CLI should have 'lan' commands");
    assert!(help.contains("net"), "CLI should have 'net' commands");
}

#[test]
fn test_lan_mdns_help() {
    let output = run_cli_command(&["lan", "mdns", "--help"]);

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(
        help.contains("announce"),
        "Should have 'announce' subcommand"
    );
    assert!(
        help.contains("list-peers"),
        "Should have 'list-peers' subcommand"
    );
}

#[test]
fn test_net_unified_help() {
    let output = run_cli_command(&["net", "unified", "--help"]);

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(help.contains("start"), "Should have 'start' subcommand");
    assert!(
        help.contains("list-peers"),
        "Should have 'list-peers' subcommand"
    );
    assert!(help.contains("find"), "Should have 'find' subcommand");
}

/// Test fumée réseau : `lan mdns list-peers` avec timeout court
#[test]
#[ignore = "Network test - run with `cargo test -- --ignored`"]
fn test_lan_mdns_list_peers_smoke() {
    let output = run_cli_command(&["--json", "lan", "mdns", "list-peers", "--timeout", "1"]);

    // Ne doit pas crash, même si aucun pair trouvé
    assert!(
        output.status.success(),
        "Command should complete successfully"
    );

    let json_output = String::from_utf8_lossy(&output.stdout);

    // Vérifier structure JSON basique
    assert!(
        json_output.contains("method"),
        "Should contain 'method' field"
    );
    assert!(json_output.contains("mdns"), "Method should be 'mdns'");
    assert!(
        json_output.contains("peers"),
        "Should contain 'peers' array"
    );
    assert!(
        json_output.contains("count"),
        "Should contain 'count' field"
    );
}

/// Test fumée réseau : `net unified list-peers` avec timeout court  
#[test]
#[ignore = "Network test - run with `cargo test -- --ignored`"]
fn test_net_unified_list_peers_smoke() {
    let output = run_cli_command(&["--json", "net", "unified", "list-peers", "--timeout", "1"]);

    assert!(
        output.status.success(),
        "Command should complete successfully"
    );

    let json_output = String::from_utf8_lossy(&output.stdout);

    // Vérifier structure JSON basique
    assert!(
        json_output.contains("method"),
        "Should contain 'method' field"
    );
    assert!(
        json_output.contains("unified"),
        "Method should be 'unified'"
    );
    assert!(
        json_output.contains("peers"),
        "Should contain 'peers' array"
    );
}
