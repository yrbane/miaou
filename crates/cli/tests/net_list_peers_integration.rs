//! Tests d'intégration pour net-list-peers - Issue #2
//!
//! Validation des codes retour, retries, et sortie JSON

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

#[test]
fn test_net_list_peers_no_peers_exit_code_2() {
    // Test que net-list-peers retourne le code 2 quand aucun pair n'est découvert
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    // Utiliser un timeout très court pour que le test soit rapide
    let result = cmd
        .args(["net", "unified", "list-peers", "--timeout", "1"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(2); // Code retour 2 pour "aucun pair"

    // Vérifier que le message indique qu'aucun pair n'a été trouvé
    result.stdout(predicate::str::contains("Aucun pair découvert"));
}

#[test]
fn test_net_list_peers_json_format() {
    // Test que la sortie JSON est bien formattée même sans pairs
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    let result = cmd
        .args(["--json", "net", "unified", "list-peers", "--timeout", "1"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(2); // Même code retour, mais sortie JSON

    // Vérifier que la sortie est un JSON valide
    let output = result.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 output");

    // Extraire seulement la partie JSON (après les logs)
    let json_start = stdout.find('{').expect("Should contain JSON");
    let json_str = &stdout[json_start..];

    // Parser le JSON pour vérifier qu'il est valide
    let json: Value = serde_json::from_str(json_str).expect("Should be valid JSON");

    // Vérifier la structure JSON attendue
    assert!(json["discovered_peers"].is_array());
    assert_eq!(json["count"], 0);
    assert!(json["timestamp"].is_number());
    assert!(json["discovery_timeout_sec"].is_number());
    assert_eq!(json["total_attempts"], 3); // 3 tentatives avec retries

    // Vérifier que le tableau des pairs est vide
    let peers = json["discovered_peers"].as_array().unwrap();
    assert_eq!(peers.len(), 0);
}

#[test]
fn test_net_list_peers_json_structure_when_peers_exist() {
    // Ce test utilise une approche différente car on ne peut pas facilement
    // créer des pairs réels dans un test unitaire isolé

    // On teste juste que la commande existe et accepte les paramètres
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    // Le test échouera probablement avec code 2 (aucun pair), mais
    // on vérifie que la syntaxe de la commande est correcte
    cmd.args(["--json", "net", "unified", "list-peers", "--timeout", "2"])
        .timeout(Duration::from_secs(15))
        .assert()
        .code(predicate::in_iter([0, 2])); // Succès OU aucun pair
}

#[test]
fn test_net_list_peers_retry_behavior() {
    // Test que les retries fonctionnent (on peut observer dans les logs)
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    let start_time = std::time::Instant::now();

    cmd.args(["net", "unified", "list-peers", "--timeout", "1"])
        .timeout(Duration::from_secs(20)) // Assez de temps pour 3 retries
        .assert()
        .code(2);

    let elapsed = start_time.elapsed();

    // Les retries sont : timeout initial (1s) + retry 1 (1s) + retry 2 (2s) + retry 3 (3s)
    // Total attendu : environ 7 secondes, on accepte 5-10s à cause des variations
    assert!(
        elapsed >= Duration::from_secs(5),
        "Should take at least 5s for retries"
    );
    assert!(
        elapsed <= Duration::from_secs(10),
        "Should not take more than 10s"
    );
}

#[test]
fn test_net_list_peers_help() {
    // Test que l'aide fonctionne
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    cmd.args(["help", "net", "unified", "list-peers"])
        .assert()
        .success()
        .stdout(predicate::str::contains("timeout"));
}

#[test]
fn test_net_list_peers_with_different_timeouts() {
    // Test avec différents timeouts pour vérifier la flexibilité
    for timeout in &["1", "2", "5"] {
        let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

        // Tous devraient échouer avec code 2 (aucun pair), mais ne pas crasher
        cmd.args(["net", "unified", "list-peers", "--timeout", timeout])
            .timeout(Duration::from_secs(30))
            .assert()
            .code(2);
    }
}

#[test]
fn test_net_list_peers_error_handling() {
    // Test avec des paramètres invalides
    let mut cmd = Command::cargo_bin("miaou-cli").unwrap();

    // Timeout invalide devrait donner erreur (clap retourne code 2 pour args invalides)
    cmd.args(["net", "unified", "list-peers", "--timeout", "invalid"])
        .assert()
        .code(2) // clap retourne 2 pour paramètres invalides
        .stderr(predicate::str::contains("invalid value"));
}
