//! Double Ratchet Algorithm pour E2E encryption avec forward secrecy
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : Forward Secrecy + Perfect Forward Secrecy

use crate::NetworkError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Clé de chaîne pour Double Ratchet (32 bytes)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainKey {
    /// Données de la clé de chaîne
    pub key_data: Vec<u8>,
    /// Numéro de chaîne pour l'ordre des messages
    pub chain_number: u32,
}

impl ChainKey {
    /// Crée une nouvelle clé de chaîne
    pub fn new(key_data: Vec<u8>, chain_number: u32) -> Self {
        Self {
            key_data,
            chain_number,
        }
    }

    /// Dérive la prochaine clé de chaîne
    pub fn derive_next(&self) -> ChainKey {
        // TDD: Implémentation HMAC-SHA256 après tests
        ChainKey {
            key_data: self.key_data.clone(), // Mock pour TDD
            chain_number: self.chain_number + 1,
        }
    }

    /// Dérive une clé de message à partir de cette clé de chaîne
    pub fn derive_message_key(&self) -> MessageKey {
        // TDD: Implémentation HKDF après tests
        MessageKey::new(vec![42; 32], self.chain_number) // Mock pour TDD
    }
}

/// Clé de message pour chiffrer/déchiffrer un message spécifique
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageKey {
    /// Données de la clé de message (32 bytes)
    pub key_data: Vec<u8>,
    /// Numéro de message pour l'ordre
    pub message_number: u32,
}

impl MessageKey {
    /// Crée une nouvelle clé de message
    pub fn new(key_data: Vec<u8>, message_number: u32) -> Self {
        Self {
            key_data,
            message_number,
        }
    }
}

/// État du Double Ratchet pour une session
#[derive(Clone, Debug)]
pub struct RatchetState {
    /// Clé racine actuelle (32 bytes)
    pub root_key: Vec<u8>,
    /// Clé de chaîne d'envoi
    pub sending_chain_key: Option<ChainKey>,
    /// Clé de chaîne de réception
    pub receiving_chain_key: Option<ChainKey>,
    /// Clé publique Diffie-Hellman du pair
    pub remote_dh_public_key: Vec<u8>,
    /// Clé privée Diffie-Hellman locale
    pub local_dh_private_key: Vec<u8>,
    /// Compteur de messages envoyés
    pub send_count: u32,
    /// Compteur de messages reçus
    pub receive_count: u32,
}

/// Configuration pour le Double Ratchet
#[derive(Clone, Debug)]
pub struct RatchetConfig {
    /// Taille des clés en bytes (par défaut 32)
    pub key_size: usize,
    /// Nombre maximum de clés de messages à stocker
    pub max_skip_keys: usize,
    /// Intervalle de rotation des clés DH (en nombre de messages)
    pub dh_ratchet_interval: u32,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            key_size: 32,
            max_skip_keys: 1000,
            dh_ratchet_interval: 100,
        }
    }
}

/// Message chiffré avec métadonnées Double Ratchet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Numéro de chaîne
    pub chain_number: u32,
    /// Numéro de message dans la chaîne
    pub message_number: u32,
    /// Clé publique DH (si rotation)
    pub dh_public_key: Option<Vec<u8>>,
    /// Données chiffrées
    pub ciphertext: Vec<u8>,
    /// Authentication tag (MAC)
    pub auth_tag: Vec<u8>,
}

/// Trait abstrait pour le Double Ratchet
/// Architecture SOLID : Interface Segregation Principle
#[async_trait]
pub trait DoubleRatchet: Send + Sync {
    /// Initialise le ratchet avec une clé partagée (depuis handshake)
    async fn initialize(
        &mut self,
        shared_secret: &[u8],
        is_initiator: bool,
    ) -> Result<(), NetworkError>;

    /// Chiffre un message
    async fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, NetworkError>;

    /// Déchiffre un message
    async fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, NetworkError>;

    /// Effectue la rotation Diffie-Hellman si nécessaire
    async fn try_dh_ratchet(&mut self) -> Result<bool, NetworkError>;

    /// Nettoie les anciennes clés (pour limiter la mémoire)
    async fn cleanup_old_keys(&mut self) -> Result<usize, NetworkError>;

    /// Configuration du ratchet
    fn config(&self) -> &RatchetConfig;

    /// Obtient l'état actuel (pour debug/monitoring)
    fn state(&self) -> &RatchetState;
}

/// Implémentation concrète du Double Ratchet
pub struct X3dhDoubleRatchet {
    config: RatchetConfig,
    state: RatchetState,
    /// Clés de messages anciennes pour déchiffrer les messages en retard
    skipped_message_keys: Arc<Mutex<HashMap<u32, Vec<MessageKey>>>>,
}

impl X3dhDoubleRatchet {
    /// Crée une nouvelle instance de Double Ratchet
    pub fn new(config: RatchetConfig) -> Self {
        let state = RatchetState {
            root_key: vec![0; config.key_size],
            sending_chain_key: None,
            receiving_chain_key: None,
            remote_dh_public_key: Vec::new(),
            local_dh_private_key: Vec::new(),
            send_count: 0,
            receive_count: 0,
        };

        Self {
            config,
            state,
            skipped_message_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Dérive la clé racine et les clés de chaîne initiales
    fn derive_initial_keys(&mut self, shared_secret: &[u8]) -> Result<(), NetworkError> {
        // TDD: Implémentation HKDF après tests
        self.state.root_key = shared_secret.to_vec(); // Mock pour TDD
        Ok(())
    }

    /// Génère une nouvelle paire de clés DH
    fn generate_dh_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), NetworkError> {
        // TDD: Implémentation X25519 après tests
        Ok((vec![1; 32], vec![2; 32])) // Mock (private, public) pour TDD
    }

    /// Effectue un échange DH avec la clé publique du pair
    fn dh_exchange(
        &self,
        _our_private: &[u8],
        _their_public: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        // TDD: Implémentation X25519 après tests
        Ok(vec![42; 32]) // Mock shared secret pour TDD
    }

    /// Vérifie si une rotation DH est nécessaire
    fn should_rotate_dh(&self) -> bool {
        self.state.send_count >= self.config.dh_ratchet_interval
    }
}

#[async_trait]
impl DoubleRatchet for X3dhDoubleRatchet {
    async fn initialize(
        &mut self,
        shared_secret: &[u8],
        is_initiator: bool,
    ) -> Result<(), NetworkError> {
        if shared_secret.len() != 32 {
            return Err(NetworkError::HandshakeError(
                "Shared secret doit faire 32 bytes".to_string(),
            ));
        }

        self.derive_initial_keys(shared_secret)?;

        // Générer paire DH initiale
        let (private_key, _public_key) = self.generate_dh_keypair()?;
        self.state.local_dh_private_key = private_key;

        if is_initiator {
            // L'initiateur commence avec une clé d'envoi
            self.state.sending_chain_key = Some(ChainKey::new(vec![1; 32], 0));
        } else {
            // Le récepteur attend la première clé DH pour initialiser la réception
            self.state.receiving_chain_key = Some(ChainKey::new(vec![2; 32], 0));
        }

        Ok(())
    }

    async fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, NetworkError> {
        // Obtenir clé de chaîne d'envoi
        let chain_key = self
            .state
            .sending_chain_key
            .as_ref()
            .ok_or_else(|| {
                NetworkError::HandshakeError("Clé de chaîne d'envoi non initialisée".to_string())
            })?
            .clone();

        // Dériver clé de message
        let message_key = chain_key.derive_message_key();

        // TDD: Chiffrement AES-GCM après tests
        let ciphertext = plaintext.to_vec(); // Mock pour TDD
        let auth_tag = vec![99; 16]; // Mock MAC pour TDD

        // Avancer la chaîne et incrémenter compteur
        let next_chain_key = chain_key.derive_next();
        self.state.sending_chain_key = Some(next_chain_key);
        self.state.send_count += 1;

        // Vérifier rotation DH après avoir incrémenté le compteur
        let dh_public_key = if self.should_rotate_dh() {
            let (new_private, _new_public) = self.generate_dh_keypair()?;
            self.state.local_dh_private_key = new_private;
            self.state.send_count = 1; // Reset à 1 car on vient d'envoyer un message
            Some(vec![88; 32]) // Mock nouvelle clé publique pour TDD
        } else {
            None
        };

        Ok(RatchetMessage {
            chain_number: chain_key.chain_number,
            message_number: message_key.message_number,
            dh_public_key,
            ciphertext,
            auth_tag,
        })
    }

    async fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, NetworkError> {
        // Vérifier rotation DH si nouvelle clé publique
        if let Some(ref new_dh_public) = message.dh_public_key {
            self.state.remote_dh_public_key = new_dh_public.clone();

            // Effectuer DH exchange et dériver nouvelles clés
            let shared_secret =
                self.dh_exchange(&self.state.local_dh_private_key, new_dh_public)?;
            self.derive_initial_keys(&shared_secret)?;

            // Nouvelle clé de réception
            self.state.receiving_chain_key = Some(ChainKey::new(vec![3; 32], message.chain_number));
        }

        // Obtenir clé de chaîne de réception
        let chain_key = self
            .state
            .receiving_chain_key
            .as_ref()
            .ok_or_else(|| {
                NetworkError::HandshakeError(
                    "Clé de chaîne de réception non initialisée".to_string(),
                )
            })?
            .clone();

        // Dériver clé de message pour déchiffrement
        let _message_key = chain_key.derive_message_key();

        // TDD: Déchiffrement AES-GCM après tests
        let plaintext = message.ciphertext.clone(); // Mock pour TDD

        // Avancer la chaîne de réception
        let next_chain_key = chain_key.derive_next();
        self.state.receiving_chain_key = Some(next_chain_key);
        self.state.receive_count += 1;

        Ok(plaintext)
    }

    async fn try_dh_ratchet(&mut self) -> Result<bool, NetworkError> {
        if self.should_rotate_dh() {
            let (new_private, _new_public) = self.generate_dh_keypair()?;
            self.state.local_dh_private_key = new_private;
            self.state.send_count = 0;

            Ok(true) // Rotation effectuée
        } else {
            Ok(false) // Pas de rotation nécessaire
        }
    }

    async fn cleanup_old_keys(&mut self) -> Result<usize, NetworkError> {
        let mut skipped = self.skipped_message_keys.lock().unwrap();
        let initial_count = skipped.values().map(|v| v.len()).sum::<usize>();

        // TDD: Logique de nettoyage après tests
        skipped.clear(); // Mock nettoyage pour TDD

        Ok(initial_count)
    }

    fn config(&self) -> &RatchetConfig {
        &self.config
    }

    fn state(&self) -> &RatchetState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    fn create_test_config() -> RatchetConfig {
        RatchetConfig {
            key_size: 32,
            max_skip_keys: 100,
            dh_ratchet_interval: 10,
        }
    }

    #[test]
    fn test_chain_key_creation() {
        // TDD: Test création de ChainKey
        let chain_key = ChainKey::new(vec![1, 2, 3, 4], 42);

        assert_eq!(chain_key.key_data, vec![1, 2, 3, 4]);
        assert_eq!(chain_key.chain_number, 42);
    }

    #[test]
    fn test_chain_key_derive_next() {
        // TDD: Test dérivation de la prochaine clé de chaîne
        let chain_key = ChainKey::new(vec![1, 2, 3, 4], 5);
        let next_key = chain_key.derive_next();

        assert_eq!(next_key.chain_number, 6);
        // TDD: Vérifier dérivation cryptographique réelle après implémentation
    }

    #[test]
    fn test_chain_key_derive_message_key() {
        // TDD: Test dérivation de clé de message
        let chain_key = ChainKey::new(vec![5, 6, 7, 8], 10);
        let message_key = chain_key.derive_message_key();

        assert_eq!(message_key.message_number, 10);
        assert_eq!(message_key.key_data.len(), 32);
    }

    #[test]
    fn test_message_key_creation() {
        // TDD: Test création de MessageKey
        let message_key = MessageKey::new(vec![9; 32], 123);

        assert_eq!(message_key.key_data, vec![9; 32]);
        assert_eq!(message_key.message_number, 123);
    }

    #[test]
    fn test_ratchet_config_default() {
        // TDD: Test configuration par défaut
        let config = RatchetConfig::default();

        assert_eq!(config.key_size, 32);
        assert_eq!(config.max_skip_keys, 1000);
        assert_eq!(config.dh_ratchet_interval, 100);
    }

    #[test]
    fn test_ratchet_message_creation() {
        // TDD: Test création de RatchetMessage
        let message = RatchetMessage {
            chain_number: 1,
            message_number: 2,
            dh_public_key: Some(vec![3; 32]),
            ciphertext: vec![4, 5, 6],
            auth_tag: vec![7; 16],
        };

        assert_eq!(message.chain_number, 1);
        assert_eq!(message.message_number, 2);
        assert!(message.dh_public_key.is_some());
        assert_eq!(message.ciphertext, vec![4, 5, 6]);
        assert_eq!(message.auth_tag.len(), 16);
    }

    #[test]
    fn test_x3dh_double_ratchet_creation() {
        // TDD: Test création X3dhDoubleRatchet
        let config = create_test_config();
        let ratchet = X3dhDoubleRatchet::new(config.clone());

        assert_eq!(ratchet.config().key_size, config.key_size);
        assert_eq!(ratchet.config().max_skip_keys, config.max_skip_keys);
        assert_eq!(
            ratchet.config().dh_ratchet_interval,
            config.dh_ratchet_interval
        );

        assert_eq!(ratchet.state().send_count, 0);
        assert_eq!(ratchet.state().receive_count, 0);
    }

    #[tokio::test]
    async fn test_ratchet_initialize_valid_secret() {
        // TDD: Test initialisation avec secret valide
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        let result = ratchet.initialize(&shared_secret, true).await;
        assert!(result.is_ok());

        // Vérifier état après initialisation
        assert_eq!(ratchet.state().root_key, shared_secret);
        assert!(ratchet.state().sending_chain_key.is_some()); // Initiateur
        assert!(ratchet.state().receiving_chain_key.is_none()); // Pas encore
    }

    #[tokio::test]
    async fn test_ratchet_initialize_invalid_secret_size() {
        // TDD: Test initialisation avec secret invalide
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 16]; // Taille incorrecte

        let result = ratchet.initialize(&shared_secret, true).await;
        assert!(result.is_err());

        if let Err(NetworkError::HandshakeError(msg)) = result {
            assert!(msg.contains("32 bytes"));
        }
    }

    #[tokio::test]
    async fn test_ratchet_initialize_initiator_vs_responder() {
        // TDD: Test différence initiateur vs récepteur
        let config = create_test_config();
        let shared_secret = vec![42; 32];

        // Initiateur
        let mut initiator = X3dhDoubleRatchet::new(config.clone());
        initiator.initialize(&shared_secret, true).await.unwrap();
        assert!(initiator.state().sending_chain_key.is_some());
        assert!(initiator.state().receiving_chain_key.is_none());

        // Récepteur
        let mut responder = X3dhDoubleRatchet::new(config);
        responder.initialize(&shared_secret, false).await.unwrap();
        assert!(responder.state().sending_chain_key.is_none());
        assert!(responder.state().receiving_chain_key.is_some());
    }

    #[tokio::test]
    async fn test_ratchet_encrypt_basic() {
        // TDD: Test chiffrement basique
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        ratchet.initialize(&shared_secret, true).await.unwrap();

        let plaintext = b"Hello, World!";
        let result = ratchet.encrypt(plaintext).await;
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.chain_number, 0);
        assert_eq!(message.message_number, 0);
        assert!(message.dh_public_key.is_none()); // Pas de rotation pour premier message
        assert_eq!(message.ciphertext, plaintext); // Mock pour TDD

        // Vérifier compteur incrémenté
        assert_eq!(ratchet.state().send_count, 1);
    }

    #[tokio::test]
    async fn test_ratchet_encrypt_without_initialization() {
        // TDD: Test chiffrement sans initialisation
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);

        let plaintext = b"Should fail";
        let result = ratchet.encrypt(plaintext).await;
        assert!(result.is_err());

        if let Err(NetworkError::HandshakeError(msg)) = result {
            assert!(msg.contains("non initialisée"));
        }
    }

    #[tokio::test]
    async fn test_ratchet_decrypt_basic() {
        // TDD: Test déchiffrement basique
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        ratchet.initialize(&shared_secret, false).await.unwrap(); // Récepteur

        let message = RatchetMessage {
            chain_number: 0,
            message_number: 0,
            dh_public_key: None,
            ciphertext: b"Encrypted data".to_vec(),
            auth_tag: vec![99; 16],
        };

        let result = ratchet.decrypt(&message).await;
        assert!(result.is_ok());

        let plaintext = result.unwrap();
        assert_eq!(plaintext, b"Encrypted data"); // Mock pour TDD

        // Vérifier compteur incrémenté
        assert_eq!(ratchet.state().receive_count, 1);
    }

    #[tokio::test]
    async fn test_ratchet_decrypt_without_initialization() {
        // TDD: Test déchiffrement sans initialisation
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);

        let message = RatchetMessage {
            chain_number: 0,
            message_number: 0,
            dh_public_key: None,
            ciphertext: b"Should fail".to_vec(),
            auth_tag: vec![99; 16],
        };

        let result = ratchet.decrypt(&message).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ratchet_dh_rotation_threshold() {
        // TDD: Test rotation DH au seuil configuré
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        ratchet.initialize(&shared_secret, true).await.unwrap();

        // Simuler envoi de messages jusqu'au seuil
        for i in 0..9 {
            let plaintext = format!("Message {}", i);
            let result = ratchet.encrypt(plaintext.as_bytes()).await;
            assert!(result.is_ok());

            let message = result.unwrap();
            assert!(message.dh_public_key.is_none()); // Pas encore de rotation
        }

        // Le 10ème message (send_count devient 10) devrait déclencher rotation
        let result = ratchet.encrypt(b"Message 9").await.unwrap();
        assert!(result.dh_public_key.is_some()); // Rotation DH

        // Compteur reset à 1 après rotation (car on vient d'envoyer le message)
        assert_eq!(ratchet.state().send_count, 1);
    }

    #[tokio::test]
    async fn test_ratchet_try_dh_ratchet() {
        // TDD: Test rotation DH manuelle
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        ratchet.initialize(&shared_secret, true).await.unwrap();

        // Pas encore nécessaire
        let result = ratchet.try_dh_ratchet().await.unwrap();
        assert!(!result); // Pas de rotation

        // Simuler compteur au seuil
        ratchet.state.send_count = 10;
        let result = ratchet.try_dh_ratchet().await.unwrap();
        assert!(result); // Rotation effectuée
        assert_eq!(ratchet.state().send_count, 0); // Reset
    }

    #[tokio::test]
    async fn test_ratchet_cleanup_old_keys() {
        // TDD: Test nettoyage des anciennes clés
        let config = create_test_config();
        let mut ratchet = X3dhDoubleRatchet::new(config);
        let shared_secret = vec![42; 32];

        ratchet.initialize(&shared_secret, true).await.unwrap();

        let cleaned_count = ratchet.cleanup_old_keys().await.unwrap();
        assert_eq!(cleaned_count, 0); // Aucune clé à nettoyer initialement
    }

    // TDD: Tests d'intégration avec le trait DoubleRatchet
    #[tokio::test]
    async fn test_double_ratchet_trait_compatibility() {
        // TDD: Test que X3dhDoubleRatchet implémente correctement DoubleRatchet
        let config = create_test_config();
        let ratchet: Box<dyn DoubleRatchet> = Box::new(X3dhDoubleRatchet::new(config));

        // Test configuration
        assert_eq!(ratchet.config().key_size, 32);
        assert_eq!(ratchet.config().max_skip_keys, 100);

        // Test état initial
        assert_eq!(ratchet.state().send_count, 0);
        assert_eq!(ratchet.state().receive_count, 0);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // TDD: Test aller-retour chiffrement/déchiffrement
        let config = create_test_config();
        let shared_secret = vec![42; 32];

        // Simuler communication entre 2 ratchets
        let mut alice = X3dhDoubleRatchet::new(config.clone());
        let mut bob = X3dhDoubleRatchet::new(config);

        alice.initialize(&shared_secret, true).await.unwrap();
        bob.initialize(&shared_secret, false).await.unwrap();

        // Alice chiffre un message
        let plaintext = b"Secret message from Alice";
        let encrypted = alice.encrypt(plaintext).await.unwrap();

        // Bob déchiffre le message
        let decrypted = bob.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext); // Mock égalité pour TDD
    }
}
