#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # Abstractions cryptographiques Miaou
//!
//! **Documentation (FR)** : Ce crate expose des *traits* cryptographiques (AEAD, signature,
//! hash, KDF) et des implémentations de référence (ChaCha20-Poly1305, Ed25519, BLAKE3).
//! Les consumers dépendent uniquement des abstractions (DIP/OCP). Les types d'erreur sont
//! convertis en `MiaouError` et les entrées sont validées.

use aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::Signer as DalekSigner; // for .sign()
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use miaou_core::{IntoMiaouError, MiaouError, MiaouResult};

/// Interface AEAD (chiffrement authentifié) indépendante de l'implémentation.
pub trait AeadCipher {
    /// Chiffre `plaintext` avec `nonce` (12 octets) et `aad`.
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>>;
    /// Déchiffre `ciphertext` avec `nonce` (12 octets) et `aad`.
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>>;
}

/// AEAD basé sur ChaCha20-Poly1305 (RFC 8439).
pub struct Chacha20Poly1305Cipher {
    key: Key,
}

impl Chacha20Poly1305Cipher {
    /// Construit depuis une clé 32 octets.
    pub fn from_key_bytes(key: &[u8]) -> MiaouResult<Self> {
        if key.len() != 32 {
            return Err(MiaouError::InvalidInput);
        }
        Ok(Self {
            key: *Key::from_slice(key),
        })
    }
}

impl AeadCipher for Chacha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .miaou()
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .miaou()
    }
}

/// Interface de signature numérique indépendante de l'implémentation.
pub trait Signer {
    /// Renvoie la clé publique (octets).
    fn public_key(&self) -> Vec<u8>;
    /// Signe un message arbitraire et renvoie la signature.
    ///
    /// # Errors
    /// Retourne une erreur si l'opération de signature échoue.
    fn sign(&self, msg: &[u8]) -> MiaouResult<Vec<u8>>;
    /// Vérifie une signature pour un message arbitraire.
    ///
    /// # Errors
    /// Retourne une erreur si la vérification de signature échoue.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> MiaouResult<bool>;
}

/// Implémentation Ed25519 basée sur `ed25519-dalek`.
pub struct Ed25519Signer {
    sk: SigningKey,
    pk: VerifyingKey,
}

impl Ed25519Signer {
    /// Génère une nouvelle paire de clés Ed25519 via `OsRng`.
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        Self { sk, pk }
    }

    /// Construit depuis une clé privée 32 octets.
    ///
    /// # Panics
    /// Panique si la conversion de slice échoue (ne devrait pas arriver avec une entrée valide).
    pub fn from_secret_key_bytes(sk: &[u8]) -> MiaouResult<Self> {
        if sk.len() != 32 {
            return Err(MiaouError::InvalidInput);
        }
        let bytes: &[u8; 32] = sk.try_into().expect("length checked");
        let sk = SigningKey::from_bytes(bytes);
        let pk = sk.verifying_key();
        Ok(Self { sk, pk })
    }

    /// Renvoie une copie des 32 octets de la clé secrète (utilisation prudente).
    #[must_use]
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    fn sign(&self, msg: &[u8]) -> MiaouResult<Vec<u8>> {
        Ok(self.sk.sign(msg).to_bytes().to_vec())
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> MiaouResult<bool> {
        let Ok(sig) = Signature::from_slice(sig) else {
            return Ok(false);
        };
        Ok(self.pk.verify(msg, &sig).is_ok())
    }
}

/// Hash BLAKE3 (utilitaire simple).
#[must_use]
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn aead_roundtrip() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let cipher = Chacha20Poly1305Cipher::from_key_bytes(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"test-aad";
        let pt = b"bonjour miaou";
        let ct = cipher.encrypt(pt, &nonce, aad).unwrap();
        let rt = cipher.decrypt(&ct, &nonce, aad).unwrap();
        assert_eq!(rt, pt);
    }

    #[test]
    fn ed25519_sign_verify() {
        let signer = Ed25519Signer::generate();
        let msg = b"miaou";
        let sig = signer.sign(msg).unwrap();
        assert!(signer.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"hello world";
        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);

        // Same input produces same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different input produces different hash
        let hash3 = blake3_hash(b"hello world!");
        assert_ne!(hash1, hash3);

        // Empty input
        let hash_empty = blake3_hash(b"");
        assert_eq!(hash_empty.len(), 32);
        assert_ne!(hash1, hash_empty);
    }

    #[test]
    fn test_chacha20_invalid_key_length() {
        // Test with wrong key length
        let short_key = vec![0u8; 16]; // Too short
        assert!(Chacha20Poly1305Cipher::from_key_bytes(&short_key).is_err());

        let long_key = vec![0u8; 64]; // Too long
        assert!(Chacha20Poly1305Cipher::from_key_bytes(&long_key).is_err());
    }

    #[test]
    fn test_ed25519_invalid_key_length() {
        // Test with wrong secret key length
        let short_key = vec![0u8; 16]; // Too short
        assert!(Ed25519Signer::from_secret_key_bytes(&short_key).is_err());

        let long_key = vec![0u8; 64]; // Too long
        assert!(Ed25519Signer::from_secret_key_bytes(&long_key).is_err());
    }

    #[test]
    fn test_ed25519_verify_invalid_signature() {
        let signer = Ed25519Signer::generate();
        let msg = b"test message";

        // Invalid signature length
        let invalid_sig = vec![0u8; 10];
        assert!(!signer.verify(msg, &invalid_sig).unwrap());

        // Wrong signature
        let wrong_sig = vec![0u8; 64];
        assert!(!signer.verify(msg, &wrong_sig).unwrap());
    }
}
