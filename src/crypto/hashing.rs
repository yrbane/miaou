//! Fonctions de hachage cryptographiques
//! 
//! Implémentation de BLAKE3 pour hachage général et Argon2 pour dérivation
//! de clés à partir de mots de passe.

use crate::crypto::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};

/// Trait pour les moteurs de hachage
pub trait HashingEngine {
    type Output;
    
    /// Hache des données
    fn hash(data: &[u8]) -> Self::Output;
    
    /// Hache des données avec un contexte
    fn hash_with_context(data: &[u8], context: &str) -> Self::Output;
}

/// Moteur de hachage BLAKE3
pub struct Blake3Hasher;

/// Moteur de dérivation Argon2
pub struct Argon2Hasher;

/// Hash BLAKE3 (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3Output {
    hash: [u8; 32],
}

/// Configuration simple pour Argon2
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Mémoire utilisée en KiB
    pub memory_cost: u32,
    /// Nombre d'itérations
    pub time_cost: u32,
    /// Parallélisme
    pub parallelism: u32,
    /// Longueur de sortie en bytes
    pub output_length: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 65536,  // 64 MiB
            time_cost: 3,        // 3 itérations
            parallelism: 4,      // 4 threads
            output_length: 32,   // 32 bytes
        }
    }
}

impl Argon2Config {
    /// Configuration rapide pour tests (INSÉCURISÉ pour la production)
    pub fn fast_insecure() -> Self {
        Self {
            memory_cost: 1024,   // 1 MiB
            time_cost: 1,        // 1 itération
            parallelism: 1,      // 1 thread
            output_length: 32,
        }
    }
    
    /// Configuration sécurisée pour production
    pub fn secure() -> Self {
        Self {
            memory_cost: 131072, // 128 MiB
            time_cost: 4,        // 4 itérations
            parallelism: 4,      // 4 threads
            output_length: 32,
        }
    }
}

impl Blake3Output {
    /// Crée un hash à partir de bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { hash: bytes }
    }
    
    /// Retourne les bytes du hash
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }
    
    /// Convertit en slice
    pub fn as_slice(&self) -> &[u8] {
        &self.hash
    }
    
    /// Encode en hexadécimal
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
    
    /// Décode depuis hexadécimal
    pub fn from_hex(hex_str: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::HashingError(format!("Hex decode error: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidDataSize {
                expected: 32,
                actual: bytes.len(),
            });
        }
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self { hash })
    }
}

impl HashingEngine for Blake3Hasher {
    type Output = Blake3Output;
    
    fn hash(data: &[u8]) -> Self::Output {
        let hash = blake3::hash(data);
        Blake3Output::from_bytes(*hash.as_bytes())
    }
    
    fn hash_with_context(data: &[u8], context: &str) -> Self::Output {
        let mut hasher = blake3::Hasher::new_keyed(&blake3::hash(context.as_bytes()).into());
        hasher.update(data);
        let hash = hasher.finalize();
        Blake3Output::from_bytes(*hash.as_bytes())
    }
}

impl Blake3Hasher {
    /// Hache plusieurs éléments en une seule opération
    pub fn hash_multiple(items: &[&[u8]]) -> Blake3Output {
        let mut hasher = blake3::Hasher::new();
        for item in items {
            hasher.update(item);
        }
        let hash = hasher.finalize();
        Blake3Output::from_bytes(*hash.as_bytes())
    }
    
    /// Hache avec une clé
    pub fn hash_keyed(key: &[u8; 32], data: &[u8]) -> Blake3Output {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(data);
        let hash = hasher.finalize();
        Blake3Output::from_bytes(*hash.as_bytes())
    }
}

impl Argon2Hasher {
    /// Dérive une clé avec Argon2
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        config: &Argon2Config,
    ) -> CryptoResult<Vec<u8>> {
        let argon2_config = argon2::Config {
            mem_cost: config.memory_cost,
            time_cost: config.time_cost,
            lanes: config.parallelism,
            thread_mode: argon2::ThreadMode::Parallel,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            ..Default::default()
        };
        
        let hash = argon2::hash_raw(password, salt, &argon2_config)
            .map_err(|e| CryptoError::HashingError(format!("Argon2 error: {}", e)))?;
        
        Ok(hash)
    }
    
    /// Hache un mot de passe avec un sel généré
    pub fn hash_password(
        password: &[u8],
        config: &Argon2Config,
    ) -> CryptoResult<String> {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        
        let argon2_config = argon2::Config {
            mem_cost: config.memory_cost,
            time_cost: config.time_cost,
            lanes: config.parallelism,
            thread_mode: argon2::ThreadMode::Parallel,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            ..Default::default()
        };
        
        let hash = argon2::hash_encoded(password, &salt, &argon2_config)
            .map_err(|e| CryptoError::HashingError(format!("Argon2 error: {}", e)))?;
        
        Ok(hash)
    }
    
    /// Vérifie un mot de passe contre un hash
    pub fn verify_password(password: &[u8], hash: &str) -> CryptoResult<bool> {
        let valid = argon2::verify_encoded(hash, password)
            .map_err(|e| CryptoError::VerificationError(format!("Argon2 verify error: {}", e)))?;
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash1 = Blake3Hasher::hash(data);
        let hash2 = Blake3Hasher::hash(data);
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_blake3_hash_different_data() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        let hash1 = Blake3Hasher::hash(data1);
        let hash2 = Blake3Hasher::hash(data2);
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_argon2_derive_key() {
        let password = b"test_password";
        let salt = b"test_salt_123456";
        let config = Argon2Config::fast_insecure();
        
        let key1 = Argon2Hasher::derive_key(password, salt, &config).unwrap();
        let key2 = Argon2Hasher::derive_key(password, salt, &config).unwrap();
        
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), config.output_length as usize);
    }
    
    #[test]
    fn test_argon2_password_hash() {
        let password = b"test_password";
        let config = Argon2Config::fast_insecure();
        
        let hash = Argon2Hasher::hash_password(password, &config).unwrap();
        let is_valid = Argon2Hasher::verify_password(password, &hash).unwrap();
        
        assert!(is_valid);
        
        let wrong_password = b"wrong_password";
        let is_valid = Argon2Hasher::verify_password(wrong_password, &hash).unwrap();
        assert!(!is_valid);
    }
}