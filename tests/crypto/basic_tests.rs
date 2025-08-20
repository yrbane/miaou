//! Tests de base pour validation de Phase 1
//! 
//! Tests simplifiés pour valider l'architecture cryptographique de base.

use miaou::crypto::{
    hashing::{Blake3Hasher, Blake3Output, HashingEngine, Argon2Hasher, Argon2Config},
    primitives::{random_bytes, secure_compare},
    CryptoResult,
};

#[test]
fn test_blake3_basic() {
    let data = b"test data for blake3";
    let hash1 = Blake3Hasher::hash(data);
    let hash2 = Blake3Hasher::hash(data);
    
    // Même données = même hash
    assert_eq!(hash1, hash2);
    
    // Données différentes = hash différents
    let hash3 = Blake3Hasher::hash(b"different data");
    assert_ne!(hash1, hash3);
}

#[test]
fn test_blake3_hex_encoding() {
    let data = b"test";
    let hash = Blake3Hasher::hash(data);
    
    let hex_string = hash.to_hex();
    assert!(!hex_string.is_empty());
    assert_eq!(hex_string.len(), 64); // 32 bytes * 2 chars/byte
    
    let decoded = Blake3Output::from_hex(&hex_string).unwrap();
    assert_eq!(hash, decoded);
}

#[test]
fn test_random_bytes_generation() {
    let bytes1 = random_bytes(32).unwrap();
    let bytes2 = random_bytes(32).unwrap();
    
    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(bytes1, bytes2); // Très improbable qu'ils soient identiques
}

#[test]
fn test_secure_compare() {
    let data1 = vec![1, 2, 3, 4, 5];
    let data2 = vec![1, 2, 3, 4, 5];
    let data3 = vec![1, 2, 3, 4, 6];
    
    assert!(secure_compare(&data1, &data2));
    assert!(!secure_compare(&data1, &data3));
}

#[test]
fn test_argon2_basic() {
    let password = b"test_password";
    let salt = b"test_salt_16_bytes";
    let config = Argon2Config::fast_insecure();
    
    let key1 = Argon2Hasher::derive_key(password, salt, &config).unwrap();
    let key2 = Argon2Hasher::derive_key(password, salt, &config).unwrap();
    
    assert_eq!(key1, key2);
    assert_eq!(key1.len(), config.output_length as usize);
}

#[test]
fn test_argon2_password_verification() {
    let password = b"secret_password";
    let config = Argon2Config::fast_insecure();
    
    let hash = Argon2Hasher::hash_password(password, &config).unwrap();
    
    assert!(Argon2Hasher::verify_password(password, &hash).unwrap());
    assert!(!Argon2Hasher::verify_password(b"wrong_password", &hash).unwrap());
}

#[test]
fn test_crypto_constants() {
    use miaou::crypto::{NONCE_SIZE, KEY_SIZE, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
    
    assert_eq!(NONCE_SIZE, 12);
    assert_eq!(KEY_SIZE, 32);
    assert_eq!(SIGNATURE_SIZE, 64);
    assert_eq!(PUBLIC_KEY_SIZE, 32);
}

#[test]
fn test_crypto_availability() {
    assert!(miaou::initialize().is_ok());
}

#[test]
fn test_blake3_context_different() {
    let data = b"same data";
    let hash1 = Blake3Hasher::hash_with_context(data, "context1");
    let hash2 = Blake3Hasher::hash_with_context(data, "context2");
    
    assert_ne!(hash1, hash2);
}

#[test]
fn test_blake3_keyed_hashing() {
    let key = [42u8; 32];
    let data = b"test data";
    
    let hash1 = Blake3Hasher::hash_keyed(&key, data);
    let hash2 = Blake3Hasher::hash_keyed(&key, data);
    
    assert_eq!(hash1, hash2);
    
    // Avec une clé différente
    let key2 = [43u8; 32];
    let hash3 = Blake3Hasher::hash_keyed(&key2, data);
    assert_ne!(hash1, hash3);
}

#[test] 
fn test_blake3_multiple_items() {
    let items = [b"part1".as_slice(), b"part2".as_slice(), b"part3".as_slice()];
    let hash1 = Blake3Hasher::hash_multiple(&items);
    
    // Même données = même hash
    let hash2 = Blake3Hasher::hash_multiple(&items);
    assert_eq!(hash1, hash2);
    
    // Ordre différent = hash différent
    let items_reordered = [b"part2".as_slice(), b"part1".as_slice(), b"part3".as_slice()];
    let hash3 = Blake3Hasher::hash_multiple(&items_reordered);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_performance_basic() {
    use std::time::Instant;
    
    let data = vec![0x42; 1024]; // 1KB
    let start = Instant::now();
    
    for _ in 0..1000 {
        let _hash = Blake3Hasher::hash(&data);
    }
    
    let duration = start.elapsed();
    println!("1000 hashes de 1KB: {:?}", duration);
    
    // Test basique de performance (devrait être rapide)
    assert!(duration.as_millis() < 1000);
}