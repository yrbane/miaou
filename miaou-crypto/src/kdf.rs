//! # KDF (v0.1)
//!
//! Dérivation de clé 32 octets depuis un mot de passe (Argon2id) + HKDF pour sessions.

use crate::CryptoError;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretString};
use sha3::Sha3_256;
use zeroize::Zeroizing;

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
    #[must_use]
    pub const fn fast_insecure() -> Self {
        Self {
            memory_cost: 1024, // 1 MiB
            time_cost: 1,
            parallelism: 1,
            output_length: 32,
        }
    }

    /// Configuration par défaut (équilibrée)
    #[must_use]
    pub const fn balanced() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 2,
            parallelism: 1,
            output_length: 32,
        }
    }

    /// Configuration sécurisée (haute sécurité)
    #[must_use]
    pub const fn secure() -> Self {
        Self {
            memory_cost: 131_072, // 128 MiB
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
///
/// # Errors
/// Échec si Argon2 échoue ou si les entrées sont invalides.
pub fn derive_key_32(
    password: &SecretString,
    salt: &SaltString,
    config: &Argon2Config,
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
        )
        .map_err(|_| CryptoError::InvalidInput)?,
    );

    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt.as_str().as_bytes(),
            &mut *output,
        )
        .map_err(|_| CryptoError::InvalidInput)?;

    Ok(*output)
}

/// Dérive une clé avec configuration par défaut.
///
/// # Errors
/// Échec si Argon2 échoue ou si les entrées sont invalides.
pub fn derive_key_default(
    password: &SecretString,
    salt: &SaltString,
) -> Result<[u8; 32], CryptoError> {
    derive_key_32(password, salt, &Argon2Config::balanced())
}

/// Hash un mot de passe avec Argon2id (pour vérification).
///
/// # Errors
/// Échec si la sérialisation Argon2 échoue.
pub fn hash_password(
    password: &SecretString,
    config: &Argon2Config,
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
        )
        .map_err(|_| CryptoError::InvalidInput)?,
    );

    argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|_| CryptoError::InvalidInput)
        .map(|hash| hash.to_string())
}

/// Vérifie un hash argon2 sérialisé.
///
/// # Errors
/// Échec si le format est invalide ou si la vérification échoue.
pub fn verify_password(
    password: &SecretString,
    serialized_hash: &str,
) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(serialized_hash).map_err(|_| CryptoError::InvalidInput)?;

    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed_hash)
        .is_ok())
}

/// Dérive une sous-clé avec HKDF-SHA3-256.
///
/// # Errors
/// Échec si la longueur demandée n'est pas supportée.
pub fn derive_subkey_hkdf(
    master_key: &[u8],
    info: &[u8],
    length: usize,
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
///
/// # Errors
/// Échec si l'expansion HKDF échoue.
pub fn derive_subkey_32(master_key: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
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

    #[test]
    fn test_default_config() {
        let default_config = Argon2Config::default();
        let balanced_config = Argon2Config::balanced();
        assert_eq!(default_config.memory_cost, balanced_config.memory_cost);
        assert_eq!(default_config.time_cost, balanced_config.time_cost);
        assert_eq!(default_config.parallelism, balanced_config.parallelism);
        assert_eq!(default_config.output_length, balanced_config.output_length);
    }

    #[test]
    fn test_derive_key_default() {
        let password = SecretString::new("test_password".to_string());
        let salt = generate_salt();

        let key1 = derive_key_default(&password, &salt).unwrap();
        let key2 = derive_key_32(&password, &salt, &Argon2Config::balanced()).unwrap();

        // Should be equivalent to balanced config
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        // Salts should be different
        assert_ne!(salt1.to_string(), salt2.to_string());

        // Should be valid base64
        assert!(!salt1.to_string().is_empty());
        assert!(!salt2.to_string().is_empty());
    }

    #[test]
    fn test_hash_password_different_configs() {
        let password = SecretString::new("test_password".to_string());

        let hash_fast = hash_password(&password, &Argon2Config::fast_insecure()).unwrap();
        let hash_balanced = hash_password(&password, &Argon2Config::balanced()).unwrap();
        let hash_secure = hash_password(&password, &Argon2Config::secure()).unwrap();

        // Different configs should produce different hashes
        assert_ne!(hash_fast, hash_balanced);
        assert_ne!(hash_balanced, hash_secure);
        assert_ne!(hash_fast, hash_secure);

        // All should start with $argon2id$
        assert!(hash_fast.starts_with("$argon2id$"));
        assert!(hash_balanced.starts_with("$argon2id$"));
        assert!(hash_secure.starts_with("$argon2id$"));
    }

    #[test]
    fn test_verify_password_wrong_password() {
        let password = SecretString::new("correct_password".to_string());
        let wrong_password = SecretString::new("wrong_password".to_string());
        let config = Argon2Config::fast_insecure();

        let hash = hash_password(&password, &config).unwrap();

        // Correct password should verify
        assert!(verify_password(&password, &hash).unwrap());

        // Wrong password should not verify
        assert!(!verify_password(&wrong_password, &hash).unwrap());
    }

    #[test]
    fn test_verify_password_invalid_hash() {
        let password = SecretString::new("test_password".to_string());

        // Invalid hash format should return error
        assert!(verify_password(&password, "invalid_hash").is_err());
        assert!(verify_password(&password, "").is_err());
        assert!(verify_password(&password, "$invalid$format$").is_err());
    }

    #[test]
    fn test_derive_subkey_hkdf_edge_cases() {
        let master_key = [42u8; 32];
        let info = b"test_info";

        // Test zero length (should error)
        assert!(derive_subkey_hkdf(&master_key, info, 0).is_err());

        // Test maximum length + 1 (should error)
        assert!(derive_subkey_hkdf(&master_key, info, 255 * 32 + 1).is_err());

        // Test valid maximum length
        assert!(derive_subkey_hkdf(&master_key, info, 255 * 32).is_ok());

        // Test length 1
        let subkey = derive_subkey_hkdf(&master_key, info, 1).unwrap();
        assert_eq!(subkey.len(), 1);
    }

    #[test]
    fn test_derive_subkey_32_different_info() {
        let master_key = [42u8; 32];
        let info1 = b"info1";
        let info2 = b"info2";

        let subkey1 = derive_subkey_32(&master_key, info1).unwrap();
        let subkey2 = derive_subkey_32(&master_key, info2).unwrap();

        // Different info should produce different subkeys
        assert_ne!(subkey1, subkey2);
    }

    #[test]
    fn test_derive_subkey_32_different_master_keys() {
        let master_key1 = [1u8; 32];
        let master_key2 = [2u8; 32];
        let info = b"same_info";

        let subkey1 = derive_subkey_32(&master_key1, info).unwrap();
        let subkey2 = derive_subkey_32(&master_key2, info).unwrap();

        // Different master keys should produce different subkeys
        assert_ne!(subkey1, subkey2);
    }

    #[test]
    fn test_argon2_params_edge_cases() {
        let password = SecretString::new("test".to_string());
        let salt = generate_salt();

        // Test with minimal valid parameters (Argon2 has higher minimums than expected)
        let config = Argon2Config {
            memory_cost: 8,    // Minimum for Argon2
            time_cost: 1,      // Minimum 1 iteration
            parallelism: 1,    // Minimum 1 thread
            output_length: 32, // Standard length
        };

        // Should succeed with minimal valid params
        let result = derive_key_32(&password, &salt, &config);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32); // Always 32 bytes output
    }
}
