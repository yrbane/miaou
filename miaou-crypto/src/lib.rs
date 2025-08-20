//! # Miaou Crypto v0.1.0
//!
//! Primitives cryptographiques sécurisées pour la plateforme Miaou.
//!
//! Ce crate fournit une interface cohérente et sécurisée pour toutes les
//! opérations cryptographiques de Miaou, basée sur des bibliothèques auditées.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

// Modules cryptographiques
pub mod aead;
pub mod hash;
pub mod hashing;
pub mod kdf;
pub mod sign;

// Re-exports pour API simplifiée
pub use aead::{decrypt, encrypt_auto_nonce, AeadKeyRef, SealedData};
pub use hash::{blake3_32, Blake3Engine, HashingEngine};
pub use kdf::{hash_password, verify_password, Argon2Config};
pub use sign::{Keypair, Signature, SigningKeyRef, VerifyingKeyRef};

use thiserror::Error;

/// Erreurs cryptographiques principales
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Opération de chiffrement échouée
    #[error("Encryption operation failed")]
    EncryptionFailed,

    /// Opération de déchiffrement échouée
    #[error("Decryption operation failed")]
    DecryptionFailed,

    /// Vérification de signature échouée
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Clé cryptographique invalide
    #[error("Invalid cryptographic key")]
    InvalidKey,

    /// Données d'entrée invalides
    #[error("Invalid input data")]
    InvalidInput,

    /// Taille de données incorrecte
    #[error("Invalid data size: expected {expected}, got {actual}")]
    InvalidSize {
        /// Taille attendue
        expected: usize,
        /// Taille actuelle
        actual: usize,
    },

    /// AAD vide (interdit dans Miaou)
    #[error("Empty AAD (Associated Authenticated Data) is not allowed")]
    EmptyAad,

    /// Erreur de dérivation de clé
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Erreur de hachage
    #[error("Hashing operation failed")]
    HashingFailed,

    /// Erreur de troncature (cast impossible)
    #[error("Truncation error during cast")]
    Truncation,
}

/// Type de résultat cryptographique
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Constantes cryptographiques
pub mod constants {
    /// Taille d'une clé AEAD (ChaCha20-Poly1305)
    pub const AEAD_KEY_SIZE: usize = 32;

    /// Taille d'un nonce ChaCha20-Poly1305
    pub const CHACHA20_NONCE_SIZE: usize = 12;

    /// Taille d'un tag d'authentification Poly1305
    pub const POLY1305_TAG_SIZE: usize = 16;

    /// Taille d'une clé publique Ed25519
    pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

    /// Taille d'une clé privée Ed25519
    pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

    /// Taille d'une signature Ed25519
    pub const ED25519_SIGNATURE_SIZE: usize = 64;

    /// Taille d'un hash BLAKE3 par défaut
    pub const BLAKE3_HASH_SIZE: usize = 32;
}

/// Interface commune pour les fournisseurs cryptographiques
pub trait CryptoProvider: Send + Sync {
    /// Chiffre des données avec AAD obligatoire
    ///
    /// # Errors
    /// Échec si l'AEAD échoue ou si les paramètres sont invalides.
    fn seal(
        &self,
        key: &AeadKeyRef,
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut dyn rand_core::RngCore,
    ) -> CryptoResult<SealedData>;

    /// Déchiffre des données avec AAD
    ///
    /// # Errors
    /// Échec si l'authentification échoue (tag invalide) ou en cas d'erreur interne.
    fn open(&self, key: &AeadKeyRef, aad: &[u8], sealed_data: &SealedData)
        -> CryptoResult<Vec<u8>>;

    /// Signe un message
    ///
    /// # Errors
    /// Échec si la signature ne peut pas être produite.
    fn sign(&self, signing_key: &SigningKeyRef, message: &[u8]) -> CryptoResult<Signature>;

    /// Vérifie une signature
    ///
    /// # Errors
    /// Échec si la signature est invalide.
    fn verify(
        &self,
        verifying_key: &VerifyingKeyRef,
        message: &[u8],
        signature: &Signature,
    ) -> CryptoResult<()>;

    /// Calcule un hash cryptographique
    ///
    /// # Errors
    /// Échec si le calcul de hachage échoue.
    fn hash(&self, data: &[u8]) -> CryptoResult<[u8; 32]>;
}

/// Implémentation par défaut du fournisseur cryptographique
pub struct DefaultCryptoProvider;

impl CryptoProvider for DefaultCryptoProvider {
    fn seal(
        &self,
        key: &AeadKeyRef,
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut dyn rand_core::RngCore,
    ) -> CryptoResult<SealedData> {
        encrypt_auto_nonce(key, aad, plaintext, rng)
    }

    fn open(
        &self,
        key: &AeadKeyRef,
        aad: &[u8],
        sealed_data: &SealedData,
    ) -> CryptoResult<Vec<u8>> {
        decrypt(key, aad, sealed_data)
    }

    fn sign(&self, signing_key: &SigningKeyRef, message: &[u8]) -> CryptoResult<Signature> {
        Ok(signing_key.sign(message))
    }

    fn verify(
        &self,
        verifying_key: &VerifyingKeyRef,
        message: &[u8],
        signature: &Signature,
    ) -> CryptoResult<()> {
        verifying_key.verify(message, signature)
    }

    fn hash(&self, data: &[u8]) -> CryptoResult<[u8; 32]> {
        Ok(blake3_32(data))
    }
}

/// Test de disponibilité des primitives cryptographiques
///
/// # Errors
/// Retourne une erreur si un des autotests crypto échoue.
pub fn test_crypto_availability() -> Result<(), String> {
    use rand_core::OsRng;

    // Test AEAD
    let key = AeadKeyRef::from_bytes([42u8; 32]);
    let plaintext = b"test";
    let aad = b"miaou_test";
    let mut rng = OsRng;

    let encrypted = encrypt_auto_nonce(&key, aad, plaintext, &mut rng)
        .map_err(|e| format!("AEAD test failed: {e}"))?;

    let decrypted =
        decrypt(&key, aad, &encrypted).map_err(|e| format!("AEAD decrypt test failed: {e}"))?;

    if decrypted != plaintext {
        return Err("AEAD roundtrip test failed".to_string());
    }

    // Test signatures
    let keypair = Keypair::generate();
    let message = b"test message";

    let signature = keypair.sign(message);
    keypair
        .verify(message, &signature)
        .map_err(|e| format!("Signature test failed: {e}"))?;

    // Test hachage
    let _hash = blake3_32(b"test data");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_availability_works() {
        assert!(test_crypto_availability().is_ok());
    }

    #[test]
    fn test_default_provider() {
        let provider = DefaultCryptoProvider;
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let plaintext = b"test message";
        let aad = b"test_aad";
        let mut rng = rand_core::OsRng;

        let sealed = provider.seal(&key, aad, plaintext, &mut rng).unwrap();
        let opened = provider.open(&key, aad, &sealed).unwrap();
        assert_eq!(&opened, plaintext);
    }
}
