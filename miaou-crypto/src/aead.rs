//! # AEAD ChaCha20-Poly1305 (v0.1)
//!
//! Chiffrement authentifié avec nonce 96 bits (12 octets) et AAD obligatoire.
//! Utilise ChaCha20-Poly1305 standard avec gestion stricte des nonces.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce, Key,
};
use rand_core::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::CryptoError;

/// Clé AEAD opaque (32 octets) avec Zeroize automatique
#[derive(ZeroizeOnDrop)]
pub struct AeadKeyRef {
    key: Key,
}

impl AeadKeyRef {
    /// Construit une clé AEAD depuis 32 octets.
    pub fn from_bytes(k: [u8; 32]) -> Self {
        Self { 
            key: Key::from_slice(&k).to_owned() 
        }
    }
    
    /// Génère une nouvelle clé AEAD aléatoire.
    pub fn generate(rng: &mut dyn RngCore) -> Self {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let result = Self::from_bytes(key_bytes);
        key_bytes.zeroize();
        result
    }
    
    /// Retourne une référence vers la clé interne (usage interne).
    pub(crate) fn as_key(&self) -> &Key {
        &self.key
    }
}

// Pas de Debug pour éviter les fuites
impl std::fmt::Debug for AeadKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadKeyRef([REDACTED])")
    }
}

/// Données scellées avec nonce intégré
#[derive(Clone, Debug)]
pub struct SealedData {
    /// Nonce ChaCha20 (96-bit)
    pub nonce: [u8; 12],
    /// Données chiffrées avec tag Poly1305 inclus
    pub ciphertext: Vec<u8>,
}

impl SealedData {
    /// Crée un nouveau SealedData
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
    
    /// Retourne la taille totale (nonce + ciphertext)
    pub fn total_size(&self) -> usize {
        12 + self.ciphertext.len()
    }
}

/// Génère un nonce aléatoire 12 octets pour ChaCha20.
pub fn random_nonce(rng: &mut dyn RngCore) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Chiffre avec ChaCha20-Poly1305 (nonce externe).
pub fn encrypt(
    key: &AeadKeyRef, 
    nonce: [u8; 12], 
    aad: &[u8], 
    plaintext: &[u8]
) -> Result<SealedData, CryptoError> {
    // AAD ne doit jamais être vide
    if aad.is_empty() {
        return Err(CryptoError::EmptyAad);
    }
    
    let aead = ChaCha20Poly1305::new(key.as_key());
    let nonce_ref = Nonce::from_slice(&nonce);
    
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    
    let ciphertext = aead
        .encrypt(nonce_ref, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    
    Ok(SealedData::new(nonce, ciphertext))
}

/// Déchiffre avec ChaCha20-Poly1305.
pub fn decrypt(
    key: &AeadKeyRef, 
    aad: &[u8], 
    sealed: &SealedData
) -> Result<Vec<u8>, CryptoError> {
    // AAD ne doit jamais être vide
    if aad.is_empty() {
        return Err(CryptoError::EmptyAad);
    }
    
    let aead = ChaCha20Poly1305::new(key.as_key());
    let nonce_ref = Nonce::from_slice(&sealed.nonce);
    
    let payload = Payload {
        msg: &sealed.ciphertext,
        aad,
    };
    
    aead.decrypt(nonce_ref, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Chiffre avec génération automatique de nonce.
pub fn encrypt_auto_nonce(
    key: &AeadKeyRef,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut dyn RngCore,
) -> Result<SealedData, CryptoError> {
    let nonce = random_nonce(rng);
    encrypt(key, nonce, aad, plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_aead_roundtrip() {
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let nonce = [1u8; 12];
        let aad = b"miaou_v1";
        
        let sealed = encrypt(&key, nonce, aad, b"hello world").unwrap();
        let decrypted = decrypt(&key, aad, &sealed).unwrap();
        
        assert_eq!(decrypted, b"hello world");
        assert_eq!(sealed.nonce, nonce);
    }
    
    #[test]
    fn test_aad_enforcement() {
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let nonce = [1u8; 12];
        
        // AAD vide doit échouer
        let result = encrypt(&key, nonce, b"", b"plaintext");
        assert!(matches!(result, Err(CryptoError::EmptyAad)));
        
        // AAD non-vide doit fonctionner
        let result = encrypt(&key, nonce, b"version:1", b"plaintext");
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_aad_mismatch() {
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let nonce = [1u8; 12];
        
        let sealed = encrypt(&key, nonce, b"aad1", b"message").unwrap();
        
        // AAD différent doit échouer
        let result = decrypt(&key, b"aad2", &sealed);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
        
        // AAD correct doit fonctionner
        let result = decrypt(&key, b"aad1", &sealed);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_nonce_uniqueness() {
        let mut rng = OsRng;
        let mut nonces = std::collections::HashSet::new();
        
        // Générer 1000 nonces et vérifier unicité
        for _ in 0..1000 {
            let nonce = random_nonce(&mut rng);
            assert!(nonces.insert(nonce)); // Doit être unique
        }
    }
    
    #[test]
    fn test_auto_nonce_encryption() {
        let key = AeadKeyRef::generate(&mut OsRng);
        let mut rng = OsRng;
        
        let sealed = encrypt_auto_nonce(&key, b"aad", b"message", &mut rng).unwrap();
        let decrypted = decrypt(&key, b"aad", &sealed).unwrap();
        
        assert_eq!(decrypted, b"message");
    }
    
    #[test]
    fn test_key_zeroization() {
        // Test que AeadKeyRef implémente ZeroizeOnDrop
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<AeadKeyRef>();
    }
}