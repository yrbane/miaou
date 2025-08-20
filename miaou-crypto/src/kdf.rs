//! # KDF (v0.1)
//!
//! Dérivation de clé 32 octets depuis un mot de passe (Argon2id) + HKDF pour sessions.

use argon2::{Argon2, PasswordHasher, PasswordHash, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use hkdf::Hkdf;
use sha3::Sha3_256;
use secrecy::{SecretString, ExposeSecret};
use zeroize::Zeroizing;
use crate::CryptoError;

/// Configuration Argon2id pour différents niveaux de sécurité
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Coût mémoire (m) en KiB
    pub memory_cost: u32,
    /// Coût temporel (t) - nombre d'itérations
    pub time_cost: u32,
    /// Niveau de parallélisme (p)
    pub parallelism: u32,
    /// Longueur de sortie en octets
    pub output_length: usize,
}

impl Argon2Config {
    /// Configuration rapide (tests uniquement - non sécurisée)
    pub fn fast_insecure() -> Self {
        Self {
            memory_cost: 1024,     // 1 MiB
            time_cost: 1,
            parallelism: 1,
            output_length: 32,
        }
    }
    
    /// Configuration par défaut (équilibrée)
    pub fn balanced() -> Self {
        Self {
            memory_cost: 65536,    // 64 MiB
            time_cost: 2,
            parallelism: 1,
            output_length: 32,
        }
    }
    
    /// Configuration sécurisée (haute sécurité)
    pub fn secure() -> Self {
        Self {
            memory_cost: 131072,   // 128 MiB
            time_cost: 3,
            parallelism: 2,
            output_length: 32,
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self::balanced()
    }
}

/// Dérive une clé 32 octets à partir d'un mot de passe + sel.
pub fn derive_key_32(
    password: &SecretString, 
    salt: &SaltString,
    config: &Argon2Config
) -> Result<[u8; 32], CryptoError> {
    let mut output = Zeroizing::new([0u8; 32]);
    
    // Configuration Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.output_length),
        ).map_err(|_| CryptoError::InvalidInput)?
    );
    
    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt.as_str().as_bytes(),
            &mut *output
        )
        .map_err(|_| CryptoError::InvalidInput)?;
    
    Ok(*output)
}

/// Dérive une clé avec configuration par défaut.
pub fn derive_key_default(
    password: &SecretString,
    salt: &SaltString
) -> Result<[u8; 32], CryptoError> {
    derive_key_32(password, salt, &Argon2Config::balanced())
}

/// Hash un mot de passe avec Argon2id (pour vérification).
pub fn hash_password(
    password: &SecretString,
    config: &Argon2Config
) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.output_length),
        ).map_err(|_| CryptoError::InvalidInput)?
    );
    
    argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|_| CryptoError::InvalidInput)
        .map(|hash| hash.to_string())
}

/// Vérifie un hash argon2 sérialisé.
pub fn verify_password(
    password: &SecretString, 
    serialized_hash: &str
) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(serialized_hash)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed_hash)
        .is_ok())
}

/// Dérive une sous-clé avec HKDF-SHA3-256.
pub fn derive_subkey_hkdf(
    master_key: &[u8], 
    info: &[u8], 
    length: usize
) -> Result<Vec<u8>, CryptoError> {
    if length == 0 || length > 255 * 32 {
        return Err(CryptoError::InvalidInput);
    }
    
    let hkdf = Hkdf::<Sha3_256>::new(None, master_key);
    let mut output = vec![0u8; length];
    
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::InvalidInput)?;
    
    Ok(output)
}

/// Dérive une sous-clé 32 octets avec HKDF.
pub fn derive_subkey_32(
    master_key: &[u8], 
    info: &[u8]
) -> Result<[u8; 32], CryptoError> {
    let derived = derive_subkey_hkdf(master_key, info, 32)?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&derived);
    Ok(output)
}

/// Génère un sel aléatoire pour Argon2.
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    
    #[test]
    fn test_argon2_derive_key() {
        let password = SecretString::new("test_password".to_string());
        let salt = generate_salt();
        let config = Argon2Config::fast_insecure();
        
        let key1 = derive_key_32(&password, &salt, &config).unwrap();
        let key2 = derive_key_32(&password, &salt, &config).unwrap();
        
        // Même paramètres = même clé
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
    
    #[test]
    fn test_argon2_different_salts() {
        let password = SecretString::new("test_password".to_string());
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let config = Argon2Config::fast_insecure();
        
        let key1 = derive_key_32(&password, &salt1, &config).unwrap();
        let key2 = derive_key_32(&password, &salt2, &config).unwrap();
        
        // Sels différents = clés différentes
        assert_ne!(key1, key2);
    }
    
    #[test]
    fn test_password_hash_verification() {
        let password = SecretString::new("secret_password".to_string());
        let config = Argon2Config::fast_insecure();
        
        let hash = hash_password(&password, &config).unwrap();
        
        // Bon mot de passe
        assert!(verify_password(&password, &hash).unwrap());
        
        // Mauvais mot de passe
        let wrong_password = SecretString::new("wrong_password".to_string());
        assert!(!verify_password(&wrong_password, &hash).unwrap());
    }
    
    #[test]
    fn test_hkdf_derive_subkey() {
        let master_key = [0x42u8; 32];
        let info = b"test_context";
        
        let subkey1 = derive_subkey_32(&master_key, info).unwrap();
        let subkey2 = derive_subkey_32(&master_key, info).unwrap();
        
        // Même paramètres = même sous-clé
        assert_eq!(subkey1, subkey2);
        assert_eq!(subkey1.len(), 32);
    }
    
    #[test]
    fn test_hkdf_different_info() {
        let master_key = [0x42u8; 32];
        let info1 = b"context1";
        let info2 = b"context2";
        
        let subkey1 = derive_subkey_32(&master_key, info1).unwrap();
        let subkey2 = derive_subkey_32(&master_key, info2).unwrap();
        
        // Info différent = sous-clés différentes
        assert_ne!(subkey1, subkey2);
    }
    
    #[test]
    fn test_hkdf_variable_length() {
        let master_key = [0x42u8; 32];
        let info = b"test";
        
        // Tailles différentes
        let subkey16 = derive_subkey_hkdf(&master_key, info, 16).unwrap();
        let subkey64 = derive_subkey_hkdf(&master_key, info, 64).unwrap();
        
        assert_eq!(subkey16.len(), 16);
        assert_eq!(subkey64.len(), 64);
        
        // Les 16 premiers octets doivent être identiques
        assert_eq!(&subkey64[..16], &subkey16);
    }
    
    #[test]
    fn test_configs() {
        let configs = [
            Argon2Config::fast_insecure(),
            Argon2Config::balanced(),
            Argon2Config::secure(),
        ];
        
        for config in &configs {
            assert!(config.memory_cost > 0);
            assert!(config.time_cost > 0);
            assert!(config.parallelism > 0);
            assert_eq!(config.output_length, 32);
        }
    }
}