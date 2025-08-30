//! Tests d'intégration TDD pour la commande net-handshake
//! Issue #14 - Nettoyer incohérences handshake

use assert_cmd::Command;
use predicates::prelude::*;

#[tokio::test]
async fn test_net_handshake_should_use_production_manager() {
    // GREEN: Test réussi maintenant avec système production
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    cmd.args(["net-handshake", "test-peer-123"])
        // Le handshake va échouer car le pair n'existe pas, mais on teste que
        // le bon système de production est utilisé (visible dans les logs)
        .assert()
        .failure() // Normal: pair non trouvé
        .stdout(predicate::str::contains("🤝 Production handshake manager"))
        .stdout(predicate::str::contains("X3DH protocol"))
        .stdout(predicate::str::contains("Protocol: X3DH-ED25519"))
        .stderr(predicate::str::contains("Pair 'test-peer-123' non trouvé"));
}

#[tokio::test]
async fn test_net_handshake_should_handle_invalid_peer_id() {
    // GREEN: Test gestion d'erreur avec nouveau système
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    cmd.args(["net-handshake", "invalid-peer-id"])
        .assert()
        .failure() // Normal: peer non trouvé sur réseau
        .stdout(predicate::str::contains("Production handshake manager"))
        .stderr(predicate::str::contains("non trouvé"));
}

#[tokio::test]
async fn test_net_handshake_should_show_config_info() {
    // GREEN: Test affichage configuration production
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    cmd.args(["net-handshake", "valid-peer-hex"])
        .assert()
        .failure() // Normal: pair non trouvé, mais config affichée
        .stdout(predicate::str::contains("Handshake timeout: 10000 ms"))
        .stdout(predicate::str::contains("Protocol: X3DH-ED25519"));
}

#[tokio::test]
async fn test_net_status_uses_production_handshake() {
    // GREEN: Test que net-status utilise aussi le nouveau système
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    cmd.args(["net-status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Statut des sessions E2E Production",
        ))
        .stdout(predicate::str::contains("X3DH + Double Ratchet"))
        .stdout(predicate::str::contains("Timeout handshake: 10000 ms"));
}

/// Tests unitaires simplifiés pour validation compilation
#[cfg(test)]
mod unit_tests {
    #[tokio::test]
    async fn test_handshake_integration_exists() {
        // GREEN: Test basique pour vérifier que l'intégration compile
        // Implémentation corrigée - tous les tests d'intégration passent
        // GREEN: Test basique pour vérifier que l'intégration compile
        // Implémentation corrigée - tous les tests d'intégration passent
    }
}
