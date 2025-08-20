//! Chiffrement authentifié avec ChaCha20-Poly1305
//! 
//! Implémentation sécurisée du chiffrement AEAD (Authenticated Encryption with Associated Data)
//! utilisant ChaCha20-Poly1305 selon RFC 8439.

use crate::crypto::{CryptoError, CryptoResult, NONCE_SIZE, KEY_SIZE};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Nonce, Key
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};

/// Trait pour les moteurs de chiffrement
pub trait EncryptionEngine {
    /// Génère une nouvelle clé de chiffrement
    fn generate_key() -> CryptoResult<Self> where Self: Sized;
    
    /// Chiffre des données avec un nonce donné
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// Déchiffre des données avec un nonce donné
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>>;
    
    /// Chiffre des données avec un nonce généré automatiquement
    fn encrypt_with_random_nonce(&self, plaintext: &[u8]) -> CryptoResult<EncryptedData>;
    
    /// Déchiffre des données qui incluent le nonce
    fn decrypt_with_nonce(&self, encrypted_data: &EncryptedData) -> CryptoResult<Vec<u8>>;
}

/// Données chiffrées avec nonce inclus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Nonce utilisé pour le chiffrement
    pub nonce: [u8; NONCE_SIZE],
    /// Données chiffrées avec tag d'authentification
    pub ciphertext: Vec<u8>,
}

/// Implémentation ChaCha20-Poly1305
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
    key_fingerprint: [u8; 4], // Pour identification, pas de sécurité
}

impl ChaCha20Poly1305Cipher {
    /// Crée un chiffreur à partir d'une clé
    pub fn from_key(key: &[u8; KEY_SIZE]) -> CryptoResult<Self> {
        let key_ref = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key_ref);
        
        // Empreinte simple pour identification (non sécurisé)
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        let hash = hasher.finalize();
        let key_fingerprint = [hash.as_bytes()[0], hash.as_bytes()[1], 
                              hash.as_bytes()[2], hash.as_bytes()[3]];
        
        Ok(Self {
            cipher,
            key_fingerprint,
        })
    }
    
    /// Génère un nonce aléatoire sécurisé
    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
    
    /// Retourne l'empreinte de la clé (pour identification uniquement)
    pub fn key_fingerprint(&self) -> [u8; 4] {
        self.key_fingerprint
    }
}

impl EncryptionEngine for ChaCha20Poly1305Cipher {
    fn generate_key() -> CryptoResult<Self> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        Self::from_key(key.as_slice().try_into()
            .map_err(|_| CryptoError::KeyGenerationError("Taille de clé invalide".into()))?)
    }
    
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidDataSize {
                expected: NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        
        let nonce_ref = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce_ref, plaintext)
            .map_err(|e| CryptoError::EncryptionError(format!("ChaCha20-Poly1305 encryption failed: {}", e)))
    }
    
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidDataSize {
                expected: NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        
        let nonce_ref = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce_ref, ciphertext)
            .map_err(|e| CryptoError::DecryptionError(format!("ChaCha20-Poly1305 decryption failed: {}", e)))
    }
    
    fn encrypt_with_random_nonce(&self, plaintext: &[u8]) -> CryptoResult<EncryptedData> {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt(plaintext, &nonce)?;
        
        Ok(EncryptedData {
            nonce,
            ciphertext,
        })
    }
    
    fn decrypt_with_nonce(&self, encrypted_data: &EncryptedData) -> CryptoResult<Vec<u8>> {
        self.decrypt(&encrypted_data.ciphertext, &encrypted_data.nonce)
    }
}

/// Protection contre la réutilisation de nonce
#[derive(Default)]
pub struct NonceTracker {
    used_nonces: std::collections::HashSet<[u8; NONCE_SIZE]>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Vérifie et enregistre un nonce pour éviter la réutilisation
    pub fn check_and_register_nonce(&mut self, nonce: &[u8; NONCE_SIZE]) -> CryptoResult<()> {
        if self.used_nonces.contains(nonce) {
            return Err(CryptoError::NonceReuse);
        }
        
        self.used_nonces.insert(*nonce);
        Ok(())
    }
    
    /// Nombre de nonces utilisés
    pub fn nonce_count(&self) -> usize {
        self.used_nonces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chacha20_poly1305_basic() {
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let plaintext = b"Hello, Miaou!";
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        
        let ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_encrypt_with_random_nonce() {
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let plaintext = b"Secret message for Miaou";
        
        let encrypted = cipher.encrypt_with_random_nonce(plaintext).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_wrong_nonce_fails() {
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let plaintext = b"Test message";
        let nonce1 = ChaCha20Poly1305Cipher::generate_nonce();
        let nonce2 = ChaCha20Poly1305Cipher::generate_nonce();
        
        let ciphertext = cipher.encrypt(plaintext, &nonce1).unwrap();
        let result = cipher.decrypt(&ciphertext, &nonce2);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_nonce_tracker() {
        let mut tracker = NonceTracker::new();
        let nonce1 = ChaCha20Poly1305Cipher::generate_nonce();
        let nonce2 = ChaCha20Poly1305Cipher::generate_nonce();
        
        // Premier usage OK
        assert!(tracker.check_and_register_nonce(&nonce1).is_ok());
        assert_eq!(tracker.nonce_count(), 1);
        
        // Réutilisation détectée
        assert!(tracker.check_and_register_nonce(&nonce1).is_err());
        
        // Nouveau nonce OK
        assert!(tracker.check_and_register_nonce(&nonce2).is_ok());
        assert_eq!(tracker.nonce_count(), 2);
    }
    
    #[test]
    fn test_key_fingerprint() {
        let cipher1 = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let cipher2 = ChaCha20Poly1305Cipher::generate_key().unwrap();
        
        // Empreintes différentes pour clés différentes
        assert_ne!(cipher1.key_fingerprint(), cipher2.key_fingerprint());
        
        // Empreinte stable pour même clé
        let fingerprint1 = cipher1.key_fingerprint();
        let fingerprint2 = cipher1.key_fingerprint();
        assert_eq!(fingerprint1, fingerprint2);
    }
}