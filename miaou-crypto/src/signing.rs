//! Signatures numériques avec Ed25519
//! 
//! Implémentation des signatures numériques EdDSA avec courbes Ed25519
//! selon RFC 8032 pour authentifier les messages Miaou.

use crate::crypto::{CryptoError, CryptoResult, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
use ed25519_dalek::{
    Signature, Signer, Keypair, PublicKey, SecretKey, Verifier,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};

/// Trait pour les moteurs de signature
pub trait SigningEngine {
    type PrivateKey;
    type PublicKey;
    type Signature;
    
    /// Génère une nouvelle paire de clés
    fn generate_keypair() -> CryptoResult<(Self::PrivateKey, Self::PublicKey)>;
    
    /// Signe un message
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> CryptoResult<Self::Signature>;
    
    /// Vérifie une signature
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> CryptoResult<bool>;
}

/// Clé privée Ed25519 avec protection zeroize
#[derive(ZeroizeOnDrop)]
pub struct Ed25519PrivateKey {
    key: SigningKey,
}

/// Clé publique Ed25519
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    key: VerifyingKey,
}

/// Signature Ed25519
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature {
    signature: Signature,
}

/// Paire de clés Ed25519 complète
#[derive(ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    private_key: Ed25519PrivateKey,
    #[zeroize(skip)]
    public_key: Ed25519PublicKey,
}

/// Signeur Ed25519 principal
pub struct Ed25519Signer;

impl Ed25519PrivateKey {
    /// Crée une clé privée à partir de bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> CryptoResult<Self> {
        let key = SigningKey::from_bytes(bytes);
        Ok(Self { key })
    }
    
    /// Exporte la clé privée en bytes (attention : sensible !)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    
    /// Dérive la clé publique correspondante
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            key: self.key.verifying_key(),
        }
    }
}

impl Ed25519PublicKey {
    /// Crée une clé publique à partir de bytes
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> CryptoResult<Self> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat)?;
        Ok(Self { key })
    }
    
    /// Exporte la clé publique en bytes
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.key.to_bytes()
    }
    
    /// Empreinte de la clé publique (hash des premiers 8 bytes)
    pub fn fingerprint(&self) -> [u8; 8] {
        let bytes = self.to_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();
        [
            hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3],
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7],
        ]
    }
}

impl Ed25519Signature {
    /// Crée une signature à partir de bytes
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> CryptoResult<Self> {
        let signature = Signature::from_bytes(bytes);
        Ok(Self { signature })
    }
    
    /// Exporte la signature en bytes
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.signature.to_bytes()
    }
}

impl Ed25519KeyPair {
    /// Génère une nouvelle paire de clés
    pub fn generate() -> CryptoResult<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key = Ed25519PrivateKey { key: signing_key };
        let public_key = private_key.public_key();
        
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Accès à la clé privée
    pub fn private_key(&self) -> &Ed25519PrivateKey {
        &self.private_key
    }
    
    /// Accès à la clé publique
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }
    
    /// Signe un message avec cette paire de clés
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Ed25519Signature> {
        let signature = self.private_key.key.sign(message);
        Ok(Ed25519Signature { signature })
    }
    
    /// Vérifie une signature avec la clé publique de cette paire
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> CryptoResult<bool> {
        match self.public_key.key.verify(message, &signature.signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl SigningEngine for Ed25519Signer {
    type PrivateKey = Ed25519PrivateKey;
    type PublicKey = Ed25519PublicKey;
    type Signature = Ed25519Signature;
    
    fn generate_keypair() -> CryptoResult<(Self::PrivateKey, Self::PublicKey)> {
        let keypair = Ed25519KeyPair::generate()?;
        // Nous devons cloner car on ne peut pas move out of ZeroizeOnDrop
        let signing_key = SigningKey::from_bytes(&keypair.private_key.to_bytes());
        let private_key = Ed25519PrivateKey { key: signing_key };
        let public_key = private_key.public_key();
        
        Ok((private_key, public_key))
    }
    
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> CryptoResult<Self::Signature> {
        let signature = private_key.key.sign(message);
        Ok(Ed25519Signature { signature })
    }
    
    fn verify(
        public_key: &Self::PublicKey, 
        message: &[u8], 
        signature: &Self::Signature
    ) -> CryptoResult<bool> {
        match public_key.key.verify(message, &signature.signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Gestionnaire de signatures avec vérification d'intégrité
pub struct SignatureVerifier {
    known_keys: std::collections::HashMap<[u8; 8], Ed25519PublicKey>,
}

impl SignatureVerifier {
    /// Crée un nouveau vérificateur
    pub fn new() -> Self {
        Self {
            known_keys: std::collections::HashMap::new(),
        }
    }
    
    /// Ajoute une clé publique de confiance
    pub fn add_trusted_key(&mut self, public_key: Ed25519PublicKey) {
        let fingerprint = public_key.fingerprint();
        self.known_keys.insert(fingerprint, public_key);
    }
    
    /// Vérifie une signature avec une clé connue
    pub fn verify_with_fingerprint(
        &self,
        fingerprint: &[u8; 8],
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> CryptoResult<bool> {
        let public_key = self.known_keys.get(fingerprint)
            .ok_or_else(|| CryptoError::VerificationError("Clé publique inconnue".into()))?;
        
        Ed25519Signer::verify(public_key, message, signature)
    }
    
    /// Nombre de clés de confiance
    pub fn trusted_key_count(&self) -> usize {
        self.known_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_keypair_generation() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();
        
        // Vérifier les tailles
        assert_eq!(public_key.to_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.private_key().to_bytes().len(), 32);
    }
    
    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Message de test pour Miaou";
        
        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.to_bytes().len(), SIGNATURE_SIZE);
        
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_ed25519_sign_verify_wrong_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Message original";
        let wrong_message = b"Message modifie";
        
        let signature = keypair.sign(message).unwrap();
        let is_valid = keypair.verify(wrong_message, &signature).unwrap();
        
        assert!(!is_valid);
    }
    
    #[test]
    fn test_ed25519_signer_trait() {
        let (private_key, public_key) = Ed25519Signer::generate_keypair().unwrap();
        let message = b"Test du trait SigningEngine";
        
        let signature = Ed25519Signer::sign(&private_key, message).unwrap();
        let is_valid = Ed25519Signer::verify(&public_key, message, &signature).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_public_key_fingerprint() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let keypair2 = Ed25519KeyPair::generate().unwrap();
        
        let fingerprint1 = keypair1.public_key().fingerprint();
        let fingerprint2 = keypair2.public_key().fingerprint();
        
        assert_ne!(fingerprint1, fingerprint2);
        assert_eq!(fingerprint1.len(), 8);
    }
    
    #[test]
    fn test_signature_verifier() {
        let mut verifier = SignatureVerifier::new();
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Message avec verificateur";
        
        // Ajouter la clé publique
        verifier.add_trusted_key(keypair.public_key().clone());
        assert_eq!(verifier.trusted_key_count(), 1);
        
        // Signer et vérifier
        let signature = keypair.sign(message).unwrap();
        let fingerprint = keypair.public_key().fingerprint();
        
        let is_valid = verifier.verify_with_fingerprint(&fingerprint, message, &signature).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_key_serialization() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();
        
        // Sérialisation/désérialisation de la clé publique
        let bytes = public_key.to_bytes();
        let restored_key = Ed25519PublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(public_key.to_bytes(), restored_key.to_bytes());
    }
}