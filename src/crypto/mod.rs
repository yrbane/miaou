//! # Module Cryptographique Miaou v0.1.0 "Première Griffe"
//! 
//! Ce module fournit des wrappers sécurisés autour de bibliothèques cryptographiques
//! auditées pour garantir la sécurité des communications Miaou.
//! 
//! ## Primitives supportées
//! 
//! - **Chiffrement authentifié** : ChaCha20-Poly1305 (via `chacha20poly1305`)
//! - **Signatures numériques** : Ed25519 (via `ed25519-dalek`)  
//! - **Hachage** : BLAKE3, Argon2 pour mots de passe
//! - **Générateurs aléatoires** : CSPRNG via `ring`
//! 
//! ## Garanties de sécurité
//! 
//! - Utilise exclusivement des crates auditées
//! - Zeroization automatique des secrets
//! - Tests avec vecteurs officiels NIST/IETF
//! - Protection contre les attaques par canaux auxiliaires

pub mod encryption;
pub mod signing;
pub mod hashing;
pub mod keyring;
pub mod primitives;

// Re-exports publics
pub use encryption::{EncryptionEngine, ChaCha20Poly1305Cipher};
pub use signing::{SigningEngine, Ed25519Signer};
pub use hashing::{HashingEngine, Blake3Hasher, Argon2Hasher};
pub use keyring::{KeyPair, SecretKey, PublicKey, KeyStore};
pub use primitives::{random_bytes, secure_compare};

/// Erreurs cryptographiques communes
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Erreur de chiffrement: {0}")]
    EncryptionError(String),
    
    #[error("Erreur de déchiffrement: {0}")]
    DecryptionError(String),
    
    #[error("Erreur de signature: {0}")]
    SignatureError(String),
    
    #[error("Erreur de vérification: {0}")]
    VerificationError(String),
    
    #[error("Erreur de génération de clé: {0}")]
    KeyGenerationError(String),
    
    #[error("Erreur de hachage: {0}")]
    HashingError(String),
    
    #[error("Taille de données invalide: attendu {expected}, reçu {actual}")]
    InvalidDataSize { expected: usize, actual: usize },
    
    #[error("Format de clé invalide")]
    InvalidKeyFormat,
    
    #[error("Nonce réutilisé - risque de sécurité critique")]
    NonceReuse,
}

/// Type de résultat standard pour les opérations cryptographiques
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Teste la disponibilité des fonctions cryptographiques
pub fn test_crypto_availability() -> Result<(), String> {
    // Test rapide de chaque primitive
    use crate::crypto::{
        encryption::{ChaCha20Poly1305Cipher, EncryptionEngine},
        signing::{Ed25519Signer, SigningEngine},
        hashing::Blake3Hasher,
        primitives::random_bytes,
    };
    
    // Test ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305Cipher::generate_key()
        .map_err(|e| format!("ChaCha20-Poly1305 indisponible: {}", e))?;
    
    let test_data = b"test";
    let encrypted = cipher.encrypt_with_random_nonce(test_data)
        .map_err(|e| format!("Chiffrement échoué: {}", e))?;
    let decrypted = cipher.decrypt_with_nonce(&encrypted)
        .map_err(|e| format!("Déchiffrement échoué: {}", e))?;
    
    if decrypted != test_data {
        return Err("Test de chiffrement échoué".into());
    }
    
    // Test Ed25519
    let (private_key, public_key) = Ed25519Signer::generate_keypair()
        .map_err(|e| format!("Génération de clés Ed25519 échouée: {}", e))?;
    
    let signature = Ed25519Signer::sign(&private_key, test_data)
        .map_err(|e| format!("Signature échouée: {}", e))?;
    let valid = Ed25519Signer::verify(&public_key, test_data, &signature)
        .map_err(|e| format!("Vérification de signature échouée: {}", e))?;
    
    if !valid {
        return Err("Test de signature échoué".into());
    }
    
    // Test BLAKE3
    let hash1 = Blake3Hasher::hash(test_data);
    let hash2 = Blake3Hasher::hash(test_data);
    if hash1 != hash2 {
        return Err("Test de hachage échoué".into());
    }
    
    // Test générateur aléatoire
    let random1 = random_bytes(16)
        .map_err(|e| format!("Génération aléatoire échouée: {}", e))?;
    let random2 = random_bytes(16)
        .map_err(|e| format!("Génération aléatoire échouée: {}", e))?;
    
    if random1 == random2 {
        return Err("Générateur aléatoire défaillant".into());
    }
    
    Ok(())
}

/// Taille standard des nonces pour ChaCha20-Poly1305 (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Taille standard des clés pour ChaCha20-Poly1305 (32 bytes) 
pub const KEY_SIZE: usize = 32;

/// Taille des signatures Ed25519 (64 bytes)
pub const SIGNATURE_SIZE: usize = 64;

/// Taille des clés publiques Ed25519 (32 bytes)
pub const PUBLIC_KEY_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
    }
}