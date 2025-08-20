//! Tests de propriétés cryptographiques avec proptest
//! 
//! Ces tests vérifient que les implémentations respectent les propriétés
//! mathématiques requises indépendamment des entrées spécifiques.

use miaou::crypto::{
    encryption::{ChaCha20Poly1305Cipher, EncryptionEngine},
    signing::{Ed25519Signer, SigningEngine},
    hashing::{Blake3Hasher, HashingEngine},
    primitives::{random_bytes, secure_compare, xor_bytes},
};
use proptest::prelude::*;

proptest! {
    /// Propriété : encrypt(decrypt(x)) = x pour tout x valide
    #[test]
    fn encryption_roundtrip_property(
        plaintext in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let encrypted = cipher.encrypt_with_random_nonce(&plaintext).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
        
        prop_assert_eq!(plaintext, decrypted);
    }
    
    /// Propriété : le même plaintext avec nonces différents produit des ciphertexts différents
    #[test]
    fn encryption_semantic_security(
        plaintext in prop::collection::vec(any::<u8>(), 1..100),
        nonce1 in prop::array::uniform12(any::<u8>()),
        nonce2 in prop::array::uniform12(any::<u8>())
    ) {
        prop_assume!(nonce1 != nonce2);
        
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let ciphertext1 = cipher.encrypt(&plaintext, &nonce1).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext, &nonce2).unwrap();
        
        prop_assert_ne!(ciphertext1, ciphertext2);
    }
    
    /// Propriété : verify(sign(m, sk), m, pk) = true pour toute paire (sk, pk) valide
    #[test]
    fn signature_correctness_property(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (private_key, public_key) = Ed25519Signer::generate_keypair().unwrap();
        let signature = Ed25519Signer::sign(&private_key, &message).unwrap();
        let is_valid = Ed25519Signer::verify(&public_key, &message, &signature).unwrap();
        
        prop_assert!(is_valid);
    }
    
    /// Propriété : hash(x) = hash(x) (déterminisme)
    #[test]
    fn hash_determinism_property(
        data in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let hash1 = Blake3Hasher::hash(&data);
        let hash2 = Blake3Hasher::hash(&data);
        
        prop_assert_eq!(hash1, hash2);
    }
    
    /// Propriété : hash(x) ≠ hash(y) si x ≠ y (résistance aux collisions - probabiliste)
    #[test]
    fn hash_collision_resistance_property(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(data1 != data2);
        
        let hash1 = Blake3Hasher::hash(&data1);
        let hash2 = Blake3Hasher::hash(&data2);
        
        // Note : Ce test peut théoriquement échouer avec une probabilité de 2^-256
        prop_assert_ne!(hash1, hash2);
    }
    
    /// Propriété : secure_compare est commutatif
    #[test]
    fn secure_compare_commutativity(
        data1 in prop::collection::vec(any::<u8>(), 0..100),
        data2 in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let result1 = secure_compare(&data1, &data2);
        let result2 = secure_compare(&data2, &data1);
        
        prop_assert_eq!(result1, result2);
    }
    
    /// Propriété : secure_compare(x, x) = true
    #[test]
    fn secure_compare_reflexivity(
        data in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        prop_assert!(secure_compare(&data, &data));
    }
    
    /// Propriété : XOR est son propre inverse
    #[test]
    fn xor_inverse_property(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(data1.len() == data2.len());
        
        let xor_result = xor_bytes(&data1, &data2).unwrap();
        let double_xor = xor_bytes(&xor_result, &data2).unwrap();
        
        prop_assert_eq!(data1, double_xor);
    }
    
    /// Propriété : XOR est commutatif
    #[test]
    fn xor_commutativity(
        data1 in prop::collection::vec(any::<u8>(), 1..50),
        data2 in prop::collection::vec(any::<u8>(), 1..50)
    ) {
        prop_assume!(data1.len() == data2.len());
        
        let result1 = xor_bytes(&data1, &data2).unwrap();
        let result2 = xor_bytes(&data2, &data1).unwrap();
        
        prop_assert_eq!(result1, result2);
    }
    
    /// Propriété : Les bytes aléatoires ont une entropie raisonnable
    #[test]
    fn random_bytes_entropy(
        length in 1usize..100
    ) {
        let random1 = random_bytes(length).unwrap();
        let random2 = random_bytes(length).unwrap();
        
        prop_assert_eq!(random1.len(), length);
        prop_assert_eq!(random2.len(), length);
        
        // Probabilité négligeable d'être identiques
        if length > 4 {
            prop_assert_ne!(random1, random2);
        }
    }
    
    /// Propriété : Le chiffrement préserve la longueur (+ tag)
    #[test]
    fn encryption_length_property(
        plaintext in prop::collection::vec(any::<u8>(), 0..500)
    ) {
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let encrypted = cipher.encrypt_with_random_nonce(&plaintext).unwrap();
        
        // ChaCha20-Poly1305 ajoute un tag de 16 bytes
        prop_assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16);
        prop_assert_eq!(encrypted.nonce.len(), 12);
    }
    
    /// Propriété : Les signatures ont toujours la même taille
    #[test]
    fn signature_length_property(
        message in prop::collection::vec(any::<u8>(), 0..500)
    ) {
        let (private_key, _) = Ed25519Signer::generate_keypair().unwrap();
        let signature = Ed25519Signer::sign(&private_key, &message).unwrap();
        
        prop_assert_eq!(signature.to_bytes().len(), 64);
    }
    
    /// Propriété : Les hashs ont toujours 32 bytes
    #[test]
    fn hash_length_property(
        data in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let hash = Blake3Hasher::hash(&data);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }
}

/// Tests de propriétés avec données structurées
#[cfg(test)]
mod structured_property_tests {
    use super::*;
    use miaou::crypto::keyring::{KeyStore, KeyStoreConfig, SecretKey};
    
    #[test]
    fn test_keystore_invariants() {
        // Test que le keystore maintient ses invariants
        let config = KeyStoreConfig {
            argon2_config: miaou::crypto::hashing::Argon2Config::fast_insecure(),
            ..KeyStoreConfig::default()
        };
        
        let mut keystore = KeyStore::new_with_password(b"test_password", config).unwrap();
        
        // Générer plusieurs clés
        let mut key_ids = Vec::new();
        for i in 0..10 {
            let key = SecretKey::generate_encryption_key(
                format!("key_{}", i),
                vec![format!("tag_{}", i)]
            ).unwrap();
            let key_id = key.metadata().key_id;
            key_ids.push(key_id);
            keystore.add_secret_key(key).unwrap();
        }
        
        // Vérifier que toutes les clés sont récupérables
        for key_id in &key_ids {
            let retrieved = keystore.get_secret_key(key_id).unwrap();
            assert!(retrieved.is_some());
        }
        
        // Vérifier le compte des clés
        assert_eq!(keystore.list_keys().len(), 10);
        
        // Supprimer quelques clés
        for key_id in &key_ids[0..5] {
            assert!(keystore.remove_key(key_id).unwrap());
        }
        
        // Vérifier que les clés supprimées ne sont plus là
        for key_id in &key_ids[0..5] {
            assert!(keystore.get_secret_key(key_id).unwrap().is_none());
        }
        
        // Vérifier que les autres sont encore là
        for key_id in &key_ids[5..10] {
            let retrieved = keystore.get_secret_key(key_id).unwrap();
            assert!(retrieved.is_some());
        }
    }
    
    #[test]
    fn test_encryption_with_context() {
        // Test que le contexte affecte bien le résultat
        let data = b"test data";
        
        let hash1 = Blake3Hasher::hash_with_context(data, "context1");
        let hash2 = Blake3Hasher::hash_with_context(data, "context2");
        let hash3 = Blake3Hasher::hash_with_context(data, "context1"); // Même contexte
        
        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }
    
    #[test]
    fn test_key_derivation_consistency() {
        // Test que la dérivation de clés est cohérente
        use miaou::crypto::primitives::derive_subkey;
        
        let master_key = [0x42; 32];
        
        for i in 0..10 {
            let key1 = derive_subkey(&master_key, "encryption", i);
            let key2 = derive_subkey(&master_key, "encryption", i);
            
            // Même paramètres = même clé
            assert_eq!(key1, key2);
            
            if i > 0 {
                let key_prev = derive_subkey(&master_key, "encryption", i - 1);
                // Index différent = clé différente
                assert_ne!(key1, key_prev);
            }
            
            let key_diff_context = derive_subkey(&master_key, "signing", i);
            // Contexte différent = clé différente
            assert_ne!(key1, key_diff_context);
        }
    }
}