//! # Miaou v{VERSION} "{VERSION_NAME}"
//! 
//! **Phase {PHASE_NUMBER} :** {PHASE_DESCRIPTION}
//! 
//! ## Vue d'ensemble
//! 
//! {VERSION_OVERVIEW_DESCRIPTION}
//! 
//! Cette version de Miaou implémente {KEY_FEATURES_SUMMARY} selon les principes
//! de sécurité, performance et décentralisation du projet.
//! 
//! ## Architecture
//! 
//! ```text
//! {ASCII_ARCHITECTURE_DIAGRAM}
//! ```
//! 
//! ## Modules principaux
//! 
//! - [`crypto`] - Primitives cryptographiques auditées (Phase 1+)
//! - [`network`] - Communication P2P décentralisée (Phase 2+)
//! - [`blockchain`] - Système économique et croquettes (Phase 3+)
//! - [`interfaces`] - Applications multi-plateformes (Phase 4+)
//! - [`bridges`] - Interopérabilité protocoles existants (Phase 5+)
//! - [`advanced`] - Fonctionnalités avancées et IA (Phase 6+)
//! - [`governance`] - Gouvernance décentralisée et DAO (Phase 7+)
//! 
//! ## Exemples d'usage rapide
//! 
//! ### Cryptographie (Phase 1+)
//! ```rust
//! use miaou::crypto::{ChaCha20Poly1305, Ed25519};
//! 
//! // Chiffrement authentifié
//! let key = ChaCha20Poly1305::generate_key()?;
//! let encrypted = key.encrypt(b"Hello, Miaou!", b"unique_nonce_12")?;
//! let decrypted = key.decrypt(&encrypted, b"unique_nonce_12")?;
//! 
//! // Signatures numériques
//! let keypair = Ed25519::generate_keypair()?;
//! let signature = keypair.sign(b"Message to sign")?;
//! assert!(keypair.verify(b"Message to sign", &signature)?);
//! ```
//! 
//! ### Réseau P2P (Phase 2+)
//! ```rust
//! use miaou::network::{P2PNode, PeerDiscovery};
//! 
//! let mut node = P2PNode::new().await?;
//! node.start_discovery().await?;
//! 
//! // Envoi de message chiffré
//! let peer_id = node.discover_peers().await?.first().unwrap();
//! node.send_encrypted_message(peer_id, b"Hello from Miaou!").await?;
//! ```
//! 
//! ### Interface utilisateur (Phase 4+)
//! ```rust
//! use miaou::interfaces::{DesktopApp, MobileApp};
//! 
//! // Application desktop
//! let app = DesktopApp::new().await?;
//! app.show_main_window().await?;
//! 
//! // Support mobile
//! #[cfg(target_os = "android")]
//! let mobile_app = MobileApp::initialize_android()?;
//! 
//! #[cfg(target_os = "ios")]
//! let mobile_app = MobileApp::initialize_ios()?;
//! ```
//! 
//! ## Sécurité et audit
//! 
//! ### Propriétés cryptographiques garanties
//! 
//! - **Confidentialité :** Chiffrement ChaCha20-Poly1305 authenticated
//! - **Intégrité :** AEAD (Authenticated Encryption with Associated Data)
//! - **Authenticité :** Signatures Ed25519 avec vérification obligatoire
//! - **Forward Secrecy :** Double Ratchet pour messagerie (Phase 2+)
//! - **Post-Quantum Ready :** Architecture préparée aux algorithmes quantiques
//! 
//! ### Standards et conformité
//! 
//! - **RFC 8439 :** ChaCha20-Poly1305 AEAD
//! - **RFC 8032 :** EdDSA signatures avec Ed25519
//! - **RFC 3526 :** Diffie-Hellman groups pour échanges de clés
//! - **NIST SP 800-185 :** SHAKE et fonctions dérivées
//! - **Signal Protocol :** Double Ratchet pour messagerie sécurisée
//! 
//! ### Audit et tests
//! 
//! ```rust
//! // Tests avec vecteurs NIST officiels
//! #[cfg(test)]
//! mod crypto_known_answer_tests {
//!     use super::*;
//!     
//!     #[test]
//!     fn test_chacha20_poly1305_nist_vectors() {
//!         // Vecteurs de test officiels IETF RFC 8439
//!         let test_vectors = load_nist_test_vectors();
//!         for vector in test_vectors {
//!             let result = ChaCha20Poly1305::encrypt(&vector.key, &vector.plaintext, &vector.nonce);
//!             assert_eq!(result.unwrap(), vector.expected_ciphertext);
//!         }
//!     }
//! }
//! ```
//! 
//! ## Performance et benchmarks
//! 
//! ### Objectifs de performance par phase
//! 
//! | Phase | Métrique | Objectif | Actuel |
//! |-------|----------|----------|---------|
//! | 1 | Chiffrement | >1GB/s | {CRYPTO_PERF} |
//! | 2 | Latence P2P | <100ms | {NETWORK_LATENCY} |
//! | 3 | Tx/seconde | >1000 | {BLOCKCHAIN_TPS} |
//! | 4 | Startup time | <2s | {STARTUP_TIME} |
//! | 5 | Bridge latency | <200ms | {BRIDGE_LATENCY} |
//! | 6 | AI response | <500ms | {AI_RESPONSE_TIME} |
//! | 7 | Governance | >10k votes/min | {GOVERNANCE_THROUGHPUT} |
//! 
//! ### Benchmarks automatisés
//! 
//! ```bash
//! # Exécution des benchmarks
//! cargo bench
//! 
//! # Génération des rapports
//! cargo bench -- --output-format html
//! ```
//! 
//! ## Compatibilité et plateformes
//! 
//! ### Plateformes supportées
//! 
//! - **Desktop :** Linux, macOS, Windows (via Tauri)
//! - **Mobile :** Android (API 21+), iOS (13.0+) 
//! - **Web :** Tous navigateurs modernes avec WebAssembly
//! - **Serveur :** Linux x86_64, ARM64
//! 
//! ### Versions Rust
//! 
//! - **Minimum supporté :** Rust 1.70.0
//! - **Recommandé :** Rust stable (dernière version)
//! - **Features requises :** `std`, editions 2021
//! 
//! ## Changelog et migration
//! 
//! ### Changements depuis v{PREVIOUS_VERSION}
//! 
//! #### 🎉 Nouvelles fonctionnalités
//! - {NEW_FEATURE_1}
//! - {NEW_FEATURE_2}
//! - {NEW_FEATURE_3}
//! 
//! #### 🔄 Améliorations
//! - {IMPROVEMENT_1}
//! - {IMPROVEMENT_2}
//! 
//! #### ⚠️ Breaking changes
//! - {BREAKING_CHANGE_1}
//! - {BREAKING_CHANGE_2}
//! 
//! #### 🐛 Corrections
//! - {BUG_FIX_1}
//! - {BUG_FIX_2}
//! 
//! ### Guide de migration
//! 
//! ```rust
//! // Ancien code (v{PREVIOUS_VERSION})
//! let old_api = OldMiaouClient::new();
//! old_api.deprecated_method();
//! 
//! // Nouveau code (v{VERSION})
//! let new_api = MiaouClient::new().await?;
//! new_api.improved_method().await?;
//! ```
//! 
//! ## Contribution et développement
//! 
//! ### Structure du projet
//! 
//! ```text
//! miaou/
//! ├── src/
//! │   ├── crypto/          # Primitives cryptographiques
//! │   ├── network/         # Communication P2P
//! │   ├── blockchain/      # Système économique
//! │   ├── interfaces/      # Applications utilisateur
//! │   └── lib.rs          # Point d'entrée principal
//! ├── tests/
//! │   ├── integration/     # Tests d'intégration
//! │   ├── crypto_vectors/  # Vecteurs de test crypto
//! │   └── benchmarks/      # Benchmarks performance
//! ├── docs/               # Documentation complète
//! └── examples/           # Exemples d'usage
//! ```
//! 
//! ### Standards de développement
//! 
//! - **TDD obligatoire :** Tests avant code
//! - **Couverture ≥90% :** Validation automatique
//! - **Documentation :** 100% APIs publiques documentées
//! - **Sécurité :** Audit continu des dépendances
//! - **Performance :** Benchmarks sur chaque PR
//! 
//! ## Ressources et liens
//! 
//! - **Repository :** <https://github.com/yrbane/miaou>
//! - **Documentation :** <https://docs.rs/miaou>
//! - **Changelog :** <https://github.com/yrbane/miaou/blob/main/CHANGELOG.md>
//! - **Issues :** <https://github.com/yrbane/miaou/issues>
//! - **Discussions :** <https://github.com/yrbane/miaou/discussions>
//! 
//! ---
//! 
//! *Miaou - Communication décentralisée, sécurisée et libre* 🐱

#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/yrbane/miaou/main/assets/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/yrbane/miaou/main/assets/favicon.ico",
    html_root_url = "https://docs.rs/miaou/"
)]

// Configuration de documentation avancée
#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]
#![warn(rustdoc::broken_intra_doc_links)]

// Re-exports publics pour API simplifiée
pub use crypto::*;
pub use network::*;
pub use interfaces::*;

// Modules principaux
pub mod crypto;
pub mod network;
pub mod blockchain;
pub mod interfaces;
pub mod bridges;
pub mod advanced;
pub mod governance;

// Modules utilitaires
pub mod error;
pub mod config;
pub mod logging;