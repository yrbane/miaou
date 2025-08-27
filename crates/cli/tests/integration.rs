//! Tests d'intégration pour CLI main()
//!
//! TDD: Test de la fonction main() qui ne peut être testée en unit test

use std::process::{Command, Stdio};

#[test]
fn test_main_integration_success() {
    // TDD: Test main() success path (lines 58-67)
    // Test via cargo run pour exercer la vraie fonction main()

    let output = Command::new("cargo")
        .args(["run", "-p", "miaou-cli", "--", "key-generate"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute command");

    // Vérifier que le processus s'est terminé avec succès (ExitCode::SUCCESS)
    assert!(output.status.success());

    // Vérifier qu'on a bien une clé générée (format hex)
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
    assert!(stdout
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c.is_whitespace()));
}

#[test]
fn test_main_integration_error() {
    // TDD: Test main() error path (lines 63-66)
    // Utiliser une commande qui va échouer pour tester le chemin d'erreur

    let output = Command::new("cargo")
        .args(["run", "-p", "miaou-cli", "--", "key-export", "nonexistent"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute command");

    // Vérifier que le processus s'est terminé avec erreur (ExitCode::from(1))
    assert!(!output.status.success());

    // Vérifier qu'il y a un message d'erreur sur stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"));
}
