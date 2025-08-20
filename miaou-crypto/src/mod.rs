//! # Module Cryptographique Miaou v0.1.0 "Première Griffe"
//! 
//! Ce module fournit des wrappers sécurisés autour de bibliothèques cryptographiques
//! auditées selon l'Option A cohérente (RustCrypto + Dalek).
//! 
//! ## Primitives supportées
//! 
//! - **Chiffrement authentifié** : XChaCha20-Poly1305 (nonces 192-bit)
//! - **Signatures numériques** : Ed25519 (via `ed25519-dalek`)  
//! - **Échange de clés** : X25519 (via `x25519-dalek`)
//! - **Hachage** : BLAKE3, SHA-3
//! - **KDF** : Argon2id (mots de passe) + HKDF (sessions)
//! 
//! ## Garanties de sécurité
//! 
//! - Stack cryptographique cohérente (pas de mélange ring + dalek)
//! - AAD obligatoire pour tous les AEAD
//! - Zeroization automatique des secrets
//! - Traits object-safe avec &self
//! - Tests KAT avec vecteurs IETF officiels
//! - Protection contre les attaques par canaux auxiliaires

pub mod aead;
pub mod sign;
pub mod kdf;
pub mod hash;

// Re-exports publics
pub use aead::{AeadKeyRef, SealedData, random_nonce};
pub use sign::{Keypair, SigningKeyRef, VerifyingKeyRef, Signature};
pub use kdf::{derive_key_32, Argon2Config};
pub use hash::{blake3_32, sha3_256, Blake3Output, HashingEngine, Blake3Engine};

/// Erreurs cryptographiques cohérentes
#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    /// Échec chiffrement/déchiffrement AEAD.
    #[error("encryption/decryption failure")]
    AeadFailure,
    /// Clé invalide / longueur incorrecte.
    #[error("invalid key or key length")]
    InvalidKey,
    /// Entrée invalide (format/longueur).
    #[error("invalid input")]
    InvalidInput,
    /// AAD vide (interdit).
    #[error("empty AAD not allowed")]
    EmptyAad,
    /// Signature invalide.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// Erreur de génération aléatoire.
    #[error("random generation failed")]
    RandomGenerationFailed,
}

/// Type de résultat standard pour les opérations cryptographiques
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Fournit des primitives cryptographiques de haut niveau (AEAD, signatures)
/// Implémentations basées EXCLUSIVEMENT sur des bibliothèques auditées
pub trait CryptoProvider: Send + Sync {
    /// Chiffre avec XChaCha20-Poly1305 et AAD obligatoires
    /// - `aad`: données associées (version protocole, type message, flags)
    /// - Génère automatiquement un nonce 192-bit aléatoire
    fn seal(
        &self,
        key: &AeadKeyRef,
        aad: &[u8],  // OBLIGATOIRE - jamais vide
        plaintext: &[u8],
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<SealedData, CryptoError>;

    /// Déchiffre et authentifie ; échoue si tag/nonce/AAD invalide
    fn open(
        &self,
        key: &AeadKeyRef,
        aad: &[u8],  // DOIT correspondre exactement au seal
        sealed: &SealedData,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Signe avec Ed25519 (signature 64 bytes)
    fn sign(&self, sk: &SigningKeyRef, msg: &[u8]) -> Result<Signature, CryptoError>;

    /// Vérifie signature Ed25519 - RETOURNE ERREUR (pas bool)
    fn verify(&self, pk: &VerifyingKeyRef, msg: &[u8], sig: &Signature) -> Result<(), CryptoError>;
}

/// Génère et gère le matériel cryptographique (object-safe)
pub trait KeyMaterial: Send + Sync {
    /// Génère une nouvelle identité (paire de clés Ed25519)
    fn generate_identity(&self, rng: &mut dyn rand_core::RngCore) -> Result<Keypair, CryptoError>;
    
    /// Fait la rotation d'une clé de session (nouvelle clé AEAD)
    fn rotate_session_key(&self, rng: &mut dyn rand_core::RngCore) -> Result<AeadKeyRef, CryptoError>;
}

/// Taille standard des nonces pour ChaCha20-Poly1305 (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Taille standard des clés pour ChaCha20-Poly1305 (32 bytes) 
pub const KEY_SIZE: usize = 32;

/// Taille des signatures Ed25519 (64 bytes)
pub const SIGNATURE_SIZE: usize = 64;

/// Taille des clés publiques Ed25519 (32 bytes)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Teste la disponibilité des fonctions cryptographiques
pub fn test_crypto_availability() -> Result<(), String> {
    use rand_core::OsRng;
    
    // Test BLAKE3
    let hash1 = blake3_32(b"test");
    let hash2 = blake3_32(b"test");
    if hash1 != hash2 {
        return Err("Test de hachage échoué".into());
    }
    
    // Test génération aléatoire
    let mut rng = OsRng;
    let random1 = random_nonce(&mut rng);
    let random2 = random_nonce(&mut rng);
    
    if random1 == random2 {
        return Err("Générateur aléatoire défaillant".into());
    }
    
    // Test AEAD roundtrip basique
    let key = AeadKeyRef::from_bytes([42u8; 32]);
    let nonce = random_nonce(&mut rng);
    
    match aead::encrypt(&key, nonce, b"test_aad", b"test_message") {
        Ok(sealed) => {
            match aead::decrypt(&key, b"test_aad", &sealed) {
                Ok(decrypted) => {
                    if decrypted != b"test_message" {
                        return Err("Test AEAD roundtrip échoué".into());
                    }
                }
                Err(_) => return Err("Test AEAD decrypt échoué".into()),
            }
        }
        Err(_) => return Err("Test AEAD encrypt échoué".into()),
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_constants() {
        assert_eq!(NONCE_SIZE, 12);  // ChaCha20 nonce
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
    }

    #[test]
    fn test_crypto_availability() {
        // La fonction retourne Result<(), String>
        let result = crate::crypto::test_crypto_availability();
        assert!(result.is_ok(), "Test crypto availability failed: {:?}", result);
    }
    
    #[test]
    fn test_aead_aad_enforcement() {
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let mut rng = OsRng;
        let nonce = random_nonce(&mut rng);
        
        // AAD vide doit être rejetée
        let result = aead::encrypt(&key, nonce, b"", b"plaintext");
        assert!(result.is_err());
        
        // AAD non-vide doit fonctionner
        let result = aead::encrypt(&key, nonce, b"version:1", b"plaintext");
        assert!(result.is_ok());
    }
}