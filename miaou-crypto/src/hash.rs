//! # Hash (v0.1)
//!
//! BLAKE3 (par défaut) et SHA3-256 (compatibilité).

use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
use sha3::{Digest, Sha3_256};
// use zeroize::{Zeroize, Zeroizing}; // Pour l'instant non utilisé

/// BLAKE3 32 octets (rapide, sécurisé)
#[must_use]
pub fn blake3_32(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

/// BLAKE3 avec contexte (domaine de séparation)
#[must_use]
pub fn blake3_with_context(input: &[u8], context: &str) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(context);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 avec clé (HMAC-like)
#[must_use]
pub fn blake3_keyed(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 pour plusieurs éléments (ordre sensible)
#[must_use]
pub fn blake3_multiple(items: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    for item in items {
        hasher.update(item);
    }
    *hasher.finalize().as_bytes()
}

/// SHA3-256 (compatibilité standards)
#[must_use]
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Output BLAKE3 avec encodage hex
#[derive(Clone, PartialEq, Eq)]
pub struct Blake3Output {
    hash: Blake3Hash,
}

impl Blake3Output {
    /// Crée depuis un hash BLAKE3
    #[must_use]
    pub const fn new(hash: Blake3Hash) -> Self {
        Self { hash }
    }

    /// Hash des données
    #[must_use]
    pub fn hash(input: &[u8]) -> Self {
        Self::new(blake3::hash(input))
    }

    /// Hash avec contexte
    #[must_use]
    pub fn hash_with_context(input: &[u8], context: &str) -> Self {
        let mut hasher = Blake3Hasher::new_derive_key(context);
        hasher.update(input);
        Self::new(hasher.finalize())
    }

    /// Hash avec clé
    #[must_use]
    pub fn hash_keyed(key: &[u8; 32], input: &[u8]) -> Self {
        let mut hasher = Blake3Hasher::new_keyed(key);
        hasher.update(input);
        Self::new(hasher.finalize())
    }

    /// Hash de plusieurs éléments
    #[must_use]
    pub fn hash_multiple(items: &[&[u8]]) -> Self {
        let mut hasher = Blake3Hasher::new();
        for item in items {
            hasher.update(item);
        }
        Self::new(hasher.finalize())
    }

    /// Retourne les octets du hash
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }

    /// Encode en hexadécimal
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Décode depuis l'hexadécimal
    ///
    /// # Errors
    /// Échec si `hex_str` n'est pas une chaîne hex valide de 32 octets.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);

        Ok(Self {
            hash: Blake3Hash::from(hash_bytes),
        })
    }
}

impl std::fmt::Debug for Blake3Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blake3Output({})", self.to_hex())
    }
}

impl std::fmt::Display for Blake3Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Moteur de hachage unifié
pub trait HashingEngine {
    /// Type de sortie du hachage
    type Output;

    /// Hash simple
    fn hash(input: &[u8]) -> Self::Output;

    /// Hash avec contexte optionnel
    fn hash_with_context(input: &[u8], context: &str) -> Self::Output;

    /// Hash avec clé (HMAC-like)
    fn hash_keyed(key: &[u8; 32], input: &[u8]) -> Self::Output;

    /// Hash de plusieurs éléments
    fn hash_multiple(items: &[&[u8]]) -> Self::Output;
}

/// Implémentation BLAKE3 du moteur de hachage
pub struct Blake3Engine;

impl HashingEngine for Blake3Engine {
    type Output = Blake3Output;

    fn hash(input: &[u8]) -> Self::Output {
        Blake3Output::hash(input)
    }

    fn hash_with_context(input: &[u8], context: &str) -> Self::Output {
        Blake3Output::hash_with_context(input, context)
    }

    fn hash_keyed(key: &[u8; 32], input: &[u8]) -> Self::Output {
        Blake3Output::hash_keyed(key, input)
    }

    fn hash_multiple(items: &[&[u8]]) -> Self::Output {
        Blake3Output::hash_multiple(items)
    }
}

/// Comparaison sécurisée (constant-time)
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let data = b"test data for blake3";
        let hash1 = blake3_32(data);
        let hash2 = blake3_32(data);

        // Même données = même hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Données différentes = hash différents
        let hash3 = blake3_32(b"different data");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake3_context() {
        let data = b"same data";
        let hash1 = blake3_with_context(data, "context1");
        let hash2 = blake3_with_context(data, "context2");

        // Contextes différents = hash différents
        assert_ne!(hash1, hash2);

        // Même contexte = même hash
        let hash3 = blake3_with_context(data, "context1");
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; 32];
        let data = b"test data";

        let hash1 = blake3_keyed(&key, data);
        let hash2 = blake3_keyed(&key, data);

        // Même clé = même hash
        assert_eq!(hash1, hash2);

        // Clé différente = hash différent
        let key2 = [43u8; 32];
        let hash3 = blake3_keyed(&key2, data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake3_multiple() {
        let items1 = [
            b"part1".as_slice(),
            b"part2".as_slice(),
            b"part3".as_slice(),
        ];
        let hash1 = blake3_multiple(&items1);

        // Même éléments = même hash
        let hash2 = blake3_multiple(&items1);
        assert_eq!(hash1, hash2);

        // Ordre différent = hash différent
        let items2 = [
            b"part2".as_slice(),
            b"part1".as_slice(),
            b"part3".as_slice(),
        ];
        let hash3 = blake3_multiple(&items2);
        assert_ne!(hash1, hash3);

        // Contenu équivalent mais concaténé
        let concat = b"part1part2part3";
        let hash4 = blake3_32(concat);
        assert_eq!(hash1, hash4);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"test data for sha3";
        let hash1 = sha3_256(data);
        let hash2 = sha3_256(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Différent de BLAKE3
        let blake3_hash = blake3_32(data);
        assert_ne!(hash1, blake3_hash);
    }

    #[test]
    fn test_blake3_output_hex() {
        let data = b"test";
        let output = Blake3Output::hash(data);

        let hex_string = output.to_hex();
        assert!(!hex_string.is_empty());
        assert_eq!(hex_string.len(), 64); // 32 bytes * 2 chars/byte

        let decoded = Blake3Output::from_hex(&hex_string).unwrap();
        assert_eq!(output, decoded);
    }

    #[test]
    fn test_hashing_engine() {
        let data = b"test engine";

        let output1 = Blake3Engine::hash(data);
        let output2 = Blake3Engine::hash(data);

        assert_eq!(output1, output2);
        assert_eq!(output1.as_bytes().len(), 32);
    }

    #[test]
    fn test_secure_compare() {
        let data1 = vec![1, 2, 3, 4, 5];
        let data2 = vec![1, 2, 3, 4, 5];
        let data3 = vec![1, 2, 3, 4, 6];
        let data4 = vec![1, 2, 3, 4]; // longueur différente

        assert!(secure_compare(&data1, &data2));
        assert!(!secure_compare(&data1, &data3));
        assert!(!secure_compare(&data1, &data4));
    }

    #[test]
    fn test_performance_basic() {
        use std::time::Instant;

        let data = vec![0x42; 1024]; // 1KB
        let start = Instant::now();

        for _ in 0..1000 {
            let _hash = blake3_32(&data);
        }

        let duration = start.elapsed();
        println!("1000 hashes BLAKE3 de 1KB: {:?}", duration);

        // Test basique de performance (devrait être rapide)
        assert!(duration.as_millis() < 1000);
    }

    #[test]
    fn test_blake3_with_context() {
        let data = b"test data";
        let context = "test_context";

        let hash1 = blake3_with_context(data, context);
        let hash2 = blake3_with_context(data, context);

        // Same context should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different context should produce different hash
        let hash3 = blake3_with_context(data, "different_context");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake3_keyed_function() {
        let key = [0x42; 32];
        let data = b"test data";

        let hash1 = blake3_keyed(&key, data);
        let hash2 = blake3_keyed(&key, data);

        // Same key should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different key should produce different hash
        let key2 = [0x43; 32];
        let hash3 = blake3_keyed(&key2, data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_blake3_multiple_function() {
        let items = [b"part1".as_slice(), b"part2".as_slice()];
        let hash1 = blake3_multiple(&items);
        let hash2 = blake3_multiple(&items);

        // Same items should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different order should produce different hash
        let items2 = [b"part2".as_slice(), b"part1".as_slice()];
        let hash3 = blake3_multiple(&items2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_sha3_256_function() {
        let data = b"test data";
        let hash1 = sha3_256(data);
        let hash2 = sha3_256(data);

        // Same data should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Should be different from BLAKE3
        let blake3_hash = blake3_32(data);
        assert_ne!(hash1, blake3_hash);
    }

    #[test]
    fn test_blake3_output_new() {
        let data = b"test";
        let hash = blake3::hash(data);
        let output = Blake3Output::new(hash);

        assert_eq!(output.as_bytes(), hash.as_bytes());
    }

    #[test]
    fn test_blake3_output_hash_method() {
        let data = b"test data";
        let output = Blake3Output::hash(data);
        let direct_hash = blake3_32(data);

        assert_eq!(*output.as_bytes(), direct_hash);
    }

    #[test]
    fn test_blake3_output_hash_with_context_method() {
        let data = b"test data";
        let context = "test_context";

        let output = Blake3Output::hash_with_context(data, context);
        let direct_hash = blake3_with_context(data, context);

        assert_eq!(*output.as_bytes(), direct_hash);
    }

    #[test]
    fn test_blake3_output_hash_keyed_method() {
        let key = [0x42; 32];
        let data = b"test data";

        let output = Blake3Output::hash_keyed(&key, data);
        let direct_hash = blake3_keyed(&key, data);

        assert_eq!(*output.as_bytes(), direct_hash);
    }

    #[test]
    fn test_blake3_output_hash_multiple_method() {
        let items = [b"part1".as_slice(), b"part2".as_slice()];

        let output = Blake3Output::hash_multiple(&items);
        let direct_hash = blake3_multiple(&items);

        assert_eq!(*output.as_bytes(), direct_hash);
    }

    #[test]
    fn test_blake3_output_from_hex_errors() {
        // Invalid hex characters
        assert!(Blake3Output::from_hex("invalid_hex").is_err());

        // Wrong length (too short)
        assert!(Blake3Output::from_hex("deadbeef").is_err());

        // Wrong length (too long)
        let too_long = "a".repeat(100);
        assert!(Blake3Output::from_hex(&too_long).is_err());

        // Empty string
        assert!(Blake3Output::from_hex("").is_err());
    }

    #[test]
    fn test_blake3_output_debug_display() {
        let data = b"test";
        let output = Blake3Output::hash(data);

        // Test Debug formatting
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("Blake3Output("));
        assert!(debug_str.contains(&output.to_hex()));

        // Test Display formatting
        let display_str = format!("{}", output);
        assert_eq!(display_str, output.to_hex());
    }

    #[test]
    fn test_blake3_engine_all_methods() {
        let data = b"test data";
        let key = [0x42; 32];
        let items = [b"part1".as_slice(), b"part2".as_slice()];

        // Test all HashingEngine methods for Blake3Engine
        let hash1 = Blake3Engine::hash(data);
        assert_eq!(hash1.as_bytes().len(), 32);

        let hash2 = Blake3Engine::hash_with_context(data, "context");
        assert_eq!(hash2.as_bytes().len(), 32);
        assert_ne!(hash1, hash2);

        let hash3 = Blake3Engine::hash_keyed(&key, data);
        assert_eq!(hash3.as_bytes().len(), 32);
        assert_ne!(hash1, hash3);

        let hash4 = Blake3Engine::hash_multiple(&items);
        assert_eq!(hash4.as_bytes().len(), 32);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_secure_compare_edge_cases() {
        // Empty arrays
        assert!(secure_compare(&[], &[]));

        // Single byte
        assert!(secure_compare(&[42], &[42]));
        assert!(!secure_compare(&[42], &[43]));

        // Very long arrays (test performance doesn't degrade security)
        let long1 = vec![42u8; 10000];
        let long2 = vec![42u8; 10000];
        let mut long3 = vec![42u8; 10000];
        long3[9999] = 43;

        assert!(secure_compare(&long1, &long2));
        assert!(!secure_compare(&long1, &long3));
    }
}
