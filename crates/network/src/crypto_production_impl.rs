//! Cryptographie production - Implémentations réelles de Double Ratchet
//!
//! Version production remplaçant les mocks TDD par des primitives crypto réelles.
//! Utilise miaou-crypto pour ChaCha20Poly1305 et Ed25519, avec BLAKE3 pour KDF.
//!
//! Note: Pour X3DH complet, ajouter une dépendance x25519-dalek dans Cargo.toml

use crate::NetworkError;
use miaou_crypto::{blake3_hash, AeadCipher, Chacha20Poly1305Cipher, Ed25519Signer, Signer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration pour cryptographie production
#[derive(Debug, Clone)]
pub struct ProductionCryptoConfig {
    /// Taille maximale des messages à chiffrer
    pub max_message_size: usize,
    /// TTL des clés de session (secondes)
    pub session_key_ttl: u64,
}

impl Default for ProductionCryptoConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            session_key_ttl: 24 * 3600,    // 24 heures
        }
    }
}

/// Clé de chaîne Double Ratchet production
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionChainKey {
    /// Données de la clé (32 bytes)
    pub key_data: [u8; 32],
    /// Numéro de séquence dans la chaîne
    pub chain_number: u32,
}

impl ProductionChainKey {
    /// Crée une nouvelle clé de chaîne
    pub fn new(key_data: [u8; 32], chain_number: u32) -> Self {
        Self {
            key_data,
            chain_number,
        }
    }

    /// Dérive la prochaine clé de chaîne via BLAKE3
    pub fn derive_next(&self) -> ProductionChainKey {
        // Dérivation avec BLAKE3: hash(chain_key || "next")
        let input = [&self.key_data[..], b"next"].concat();
        let next_key_data = blake3_hash(&input);

        ProductionChainKey {
            key_data: next_key_data,
            chain_number: self.chain_number + 1,
        }
    }

    /// Dérive une clé de message pour chiffrement
    pub fn derive_message_key(&self) -> ProductionMessageKey {
        // Dérivation clé message via BLAKE3
        let msg_input = [&self.key_data[..], b"message"].concat();
        let message_key_material = blake3_hash(&msg_input);

        // Dériver encryption key et MAC key
        let enc_input = [&message_key_material[..], b"encrypt"].concat();
        let mac_input = [&message_key_material[..], b"mac"].concat();

        let encryption_key = blake3_hash(&enc_input);
        let mac_key = blake3_hash(&mac_input);

        ProductionMessageKey {
            encryption_key,
            mac_key,
            message_number: self.chain_number,
        }
    }
}

/// Clé de message Double Ratchet production
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionMessageKey {
    /// Clé pour encryption ChaCha20Poly1305 (32 bytes)
    pub encryption_key: [u8; 32],
    /// Clé pour MAC HMAC-SHA256 (32 bytes)
    pub mac_key: [u8; 32],
    /// Numéro de message pour nonce
    pub message_number: u32,
}

impl ProductionMessageKey {
    /// Chiffre un message avec ChaCha20Poly1305
    pub fn encrypt_message(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let cipher = Chacha20Poly1305Cipher::from_key_bytes(&self.encryption_key)
            .map_err(|e| NetworkError::General(format!("Erreur création cipher: {}", e)))?;

        // Nonce dérivé du numéro de message (12 bytes pour ChaCha20Poly1305)
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.message_number.to_le_bytes());

        cipher
            .encrypt(plaintext, &nonce, associated_data)
            .map_err(|e| NetworkError::General(format!("Erreur chiffrement: {}", e)))
    }

    /// Déchiffre un message avec ChaCha20Poly1305
    pub fn decrypt_message(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let cipher = Chacha20Poly1305Cipher::from_key_bytes(&self.encryption_key)
            .map_err(|e| NetworkError::General(format!("Erreur création cipher: {}", e)))?;

        // Même nonce que pour l'encryption
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.message_number.to_le_bytes());

        cipher
            .decrypt(ciphertext, &nonce, associated_data)
            .map_err(|e| NetworkError::General(format!("Erreur déchiffrement: {}", e)))
    }
}

/// Session de chiffrement simplifiée (production)
#[derive(Debug)]
pub struct ProductionCryptoSession {
    /// Chaîne d'envoi actuelle
    sending_chain: ProductionChainKey,
    /// Chaîne de réception actuelle
    receiving_chain: ProductionChainKey,
    /// Numéro de message dans la session
    message_counter: u32,
    /// Clé de session pour identification
    session_id: String,
}

impl ProductionCryptoSession {
    /// Crée une nouvelle session crypto (côté initiateur)
    pub fn new(shared_secret: &[u8], session_id: String) -> Self {
        Self::new_with_role(shared_secret, session_id, true)
    }

    /// Crée une nouvelle session crypto avec rôle spécifique
    pub fn new_with_role(shared_secret: &[u8], session_id: String, is_initiator: bool) -> Self {
        // Dériver clés de chaîne depuis le shared secret
        // L'initiateur utilise "alice" pour sending, "bob" pour receiving
        // Le récepteur utilise "bob" pour sending, "alice" pour receiving
        let (sending_label, receiving_label): (&[u8], &[u8]) = if is_initiator {
            (b"alice", b"bob")
        } else {
            (b"bob", b"alice")
        };

        let sending_seed = blake3_hash(&[shared_secret, sending_label].concat());
        let receiving_seed = blake3_hash(&[shared_secret, receiving_label].concat());

        let sending_chain = ProductionChainKey::new(sending_seed, 0);
        let receiving_chain = ProductionChainKey::new(receiving_seed, 0);

        Self {
            sending_chain,
            receiving_chain,
            message_counter: 0,
            session_id,
        }
    }

    /// Chiffre un message sortant
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<ProductionCryptoMessage, NetworkError> {
        // Dériver clé de message depuis la chaîne d'envoi
        let message_key = self.sending_chain.derive_message_key();

        // Avancer la chaîne d'envoi
        self.sending_chain = self.sending_chain.derive_next();

        // Chiffrer le message
        let associated_data = self.session_id.as_bytes();
        let ciphertext = message_key.encrypt_message(plaintext, associated_data)?;

        // Créer message chiffré
        let message = ProductionCryptoMessage {
            session_id: self.session_id.clone(),
            message_number: self.message_counter,
            ciphertext,
        };

        self.message_counter += 1;

        Ok(message)
    }

    /// Déchiffre un message entrant
    pub fn decrypt_message(
        &mut self,
        message: &ProductionCryptoMessage,
    ) -> Result<Vec<u8>, NetworkError> {
        // Vérifier que c'est pour cette session
        if message.session_id != self.session_id {
            return Err(NetworkError::General("Session ID mismatch".to_string()));
        }

        // Dériver clé de message depuis la chaîne de réception
        let message_key = self.receiving_chain.derive_message_key();
        self.receiving_chain = self.receiving_chain.derive_next();

        let associated_data = self.session_id.as_bytes();
        message_key.decrypt_message(&message.ciphertext, associated_data)
    }

    /// Obtient l'ID de session
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// Message chiffré production
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionCryptoMessage {
    /// ID de session
    pub session_id: String,
    /// Numéro de message dans la chaîne
    pub message_number: u32,
    /// Texte chiffré + tag d'authentification
    pub ciphertext: Vec<u8>,
}

/// Gestionnaire de cryptographie production simplifié
pub struct ProductionCryptoManager {
    /// Signeur Ed25519 pour authentification
    signer: Ed25519Signer,
    /// Sessions actives
    sessions: HashMap<String, ProductionCryptoSession>,
}

impl ProductionCryptoManager {
    /// Crée un nouveau gestionnaire crypto
    pub fn new() -> Self {
        Self {
            signer: Ed25519Signer::generate(),
            sessions: HashMap::new(),
        }
    }

    /// Crée une nouvelle session crypto (par défaut: initiateur)
    pub fn create_session(
        &mut self,
        shared_secret: &[u8],
        session_id: String,
    ) -> &mut ProductionCryptoSession {
        self.create_session_with_role(shared_secret, session_id, true)
    }

    /// Crée une nouvelle session crypto avec rôle spécifique
    pub fn create_session_with_role(
        &mut self,
        shared_secret: &[u8],
        session_id: String,
        is_initiator: bool,
    ) -> &mut ProductionCryptoSession {
        let session =
            ProductionCryptoSession::new_with_role(shared_secret, session_id.clone(), is_initiator);
        self.sessions.insert(session_id.clone(), session);
        self.sessions.get_mut(&session_id).unwrap()
    }

    /// Obtient une session existante
    pub fn get_session(&mut self, session_id: &str) -> Option<&mut ProductionCryptoSession> {
        self.sessions.get_mut(session_id)
    }

    /// Signe des données avec la clé d'identité
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, NetworkError> {
        self.signer
            .sign(data)
            .map_err(|e| NetworkError::General(format!("Erreur signature: {}", e)))
    }

    /// Obtient la clé publique d'identité
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_chain_key_derivation() {
        // TDD: Test dérivation clé de chaîne production
        let initial_key = [42u8; 32];
        let root_key = [24u8; 32];
        let chain = ProductionChainKey::new(initial_key, 0);

        // Dériver clé suivante
        let next_chain = chain.derive_next();
        assert_eq!(next_chain.chain_number, 1);
        assert_ne!(next_chain.key_data, initial_key); // Doit être différente

        // Dériver clé de message
        let message_key = chain.derive_message_key();
        assert_eq!(message_key.message_number, 0);
        assert_ne!(message_key.encryption_key, [0u8; 32]); // Pas de zéros
        assert_ne!(message_key.mac_key, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_production_message_key_encryption() {
        // TDD: Test chiffrement/déchiffrement avec clé de message
        let encryption_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let message_key = ProductionMessageKey {
            encryption_key,
            mac_key,
            message_number: 42,
        };

        let plaintext = b"Hello, Double Ratchet!";
        let associated_data = b"authenticated data";

        // Chiffrer
        let ciphertext = message_key
            .encrypt_message(plaintext, associated_data)
            .unwrap();
        assert_ne!(ciphertext, plaintext); // Doit être différent
        assert!(ciphertext.len() > plaintext.len()); // Inclut auth tag

        // Déchiffrer
        let decrypted = message_key
            .decrypt_message(&ciphertext, associated_data)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_production_crypto_session() {
        // TDD: Test session crypto production complète
        let shared_secret = b"shared_secret_from_handshake_exchange";
        let session_id = "test-session-123".to_string();

        // Créer sessions Alice (initiateur) et Bob (récepteur) avec rôles corrects
        let mut alice_session =
            ProductionCryptoSession::new_with_role(shared_secret, session_id.clone(), true);
        let mut bob_session =
            ProductionCryptoSession::new_with_role(shared_secret, session_id, false);

        // Alice chiffre un message
        let plaintext = b"Premier message Alice vers Bob";
        let encrypted_msg = alice_session.encrypt_message(plaintext).unwrap();

        // Vérifier format du message
        assert!(!encrypted_msg.session_id.is_empty());
        assert_eq!(encrypted_msg.message_number, 0);
        assert!(!encrypted_msg.ciphertext.is_empty());

        // Bob déchiffre (maintenant les clés sont synchronisées)
        let decrypted = bob_session.decrypt_message(&encrypted_msg).unwrap();
        assert_eq!(decrypted, plaintext);
        println!("✅ Chiffrement/déchiffrement crypto réussi");
    }

    #[tokio::test]
    async fn test_production_crypto_manager() {
        // TDD: Test gestionnaire crypto production
        let mut manager = ProductionCryptoManager::new();

        // Vérifier clé publique
        let public_key = manager.public_key();
        assert!(!public_key.is_empty());
        assert_eq!(public_key.len(), 32); // Ed25519 public key

        // Créer session
        let shared_secret = blake3_hash(b"test shared secret");
        let session_id = "test-session".to_string();
        let session = manager.create_session(&shared_secret, session_id.clone());

        assert_eq!(session.session_id(), &session_id);

        // Tester signature
        let data = b"test data to sign";
        let signature = manager.sign_data(data).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64); // Ed25519 signature

        println!("✅ Gestionnaire crypto production testé");
    }

    #[tokio::test]
    async fn test_full_crypto_production_flow() {
        // TDD: Test flux crypto production complet
        let mut alice_manager = ProductionCryptoManager::new();
        let mut bob_manager = ProductionCryptoManager::new();

        // Simuler handshake avec shared secret dérivé
        let alice_public = alice_manager.public_key();
        let bob_public = bob_manager.public_key();

        // Créer shared secret simple (dans une vraie impl: via X3DH)
        let combined_keys = [&alice_public[..], &bob_public[..]].concat();
        let shared_secret = blake3_hash(&combined_keys);

        // Créer sessions crypto avec rôles corrects
        let session_id = "production-session-123".to_string();
        let _alice_session =
            alice_manager.create_session_with_role(&shared_secret, session_id.clone(), true); // Alice initiateur
        let _bob_session = bob_manager.create_session_with_role(&shared_secret, session_id, false); // Bob récepteur

        // Test communication chiffrée
        let message = b"Message secure via crypto production";

        let alice_session = alice_manager.get_session("production-session-123").unwrap();
        let encrypted = alice_session.encrypt_message(message).unwrap();

        let bob_session = bob_manager.get_session("production-session-123").unwrap();
        let decrypted = bob_session.decrypt_message(&encrypted).unwrap();

        assert_eq!(decrypted, message);

        println!("✅ Flux crypto production testé avec succès");
        println!("   Shared secret: {} bytes", shared_secret.len());
        println!("   Message chiffré: {} bytes", encrypted.ciphertext.len());
    }
}
