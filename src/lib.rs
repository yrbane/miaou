//! # Miaou v0.1.0 "Première Griffe"
//!
//! **Phase 1 :** Fondations cryptographiques et architecture modulaire
//!
//! ## Vue d'ensemble
//!
//! Cette version établit les fondations cryptographiques sécurisées de Miaou,
//! une plateforme de communication décentralisée. Elle implémente les primitives
//! cryptographiques essentielles selon les principes de sécurité, performance
//! et décentralisation du projet.
//!
//! ## Architecture modulaire
//!
//! Miaou v0.1.0 adopte une architecture modulaire avec des crates séparés :
//! - `miaou-crypto` : Primitives cryptographiques sécurisées
//! - `miaou-core` : Logique métier centrale et abstractions
//! - `miaou-cli` : Interface en ligne de commande

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

// Re-exports des crates modulaires
pub use miaou_core as core;
pub use miaou_crypto as crypto;

// Re-exports pour compatibilité API
pub use miaou_core::{
    version_info, initialize, VERSION, VERSION_NAME, DEVELOPMENT_PHASE,
    PlatformInterface,
    storage::{SecureStorage, ProfileId, ProfileHandle},
};

pub use miaou_crypto::{
    CryptoError, CryptoResult, CryptoProvider, DefaultCryptoProvider,
    aead::{AeadKeyRef, SealedData, encrypt_auto_nonce, decrypt},
    hash::{blake3_32, Blake3Engine, HashingEngine},
    kdf::{Argon2Config, hash_password, verify_password},
    sign::{Keypair, SigningKeyRef, VerifyingKeyRef, Signature},
    constants,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modular_architecture() {
        // Test que les re-exports fonctionnent
        let info = version_info();
        assert!(info.contains("Miaou"));
        
        // Test crypto
        assert!(crypto::test_crypto_availability().is_ok());
        
        // Test core
        assert!(initialize().is_ok());
    }
    
    #[test]
    fn test_crypto_re_exports() {
        // Test AEAD
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let plaintext = b"test";
        let aad = b"test_aad";
        let mut rng = rand_core::OsRng;
        
        let encrypted = encrypt_auto_nonce(&key, aad, plaintext, &mut rng).unwrap();
        let decrypted = decrypt(&key, aad, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
        
        // Test signatures
        let keypair = Keypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
        
        // Test hachage
        let hash1 = blake3_32(b"test");
        let hash2 = blake3_32(b"test");
        assert_eq!(hash1, hash2);
    }
}