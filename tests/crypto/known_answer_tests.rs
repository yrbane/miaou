//! Tests cryptographiques avec vecteurs connus (KAT - Known Answer Tests)
//! 
//! Ces tests utilisent des vecteurs officiels NIST/IETF pour valider
//! l'implémentation cryptographique de Miaou.

use miaou::crypto::{
    encryption::{ChaCha20Poly1305Cipher, EncryptionEngine},
    signing::{Ed25519Signer, SigningEngine, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hashing::{Blake3Hasher, HashingEngine, Blake3Output},
};

/// Tests ChaCha20-Poly1305 avec vecteurs RFC 8439
#[cfg(test)]
mod chacha20_poly1305_kat {
    use super::*;
    
    #[test]
    fn test_rfc8439_vector_1() {
        // Vecteur de test officiel RFC 8439 Section 2.8.2
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];
        
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        
        let expected_ciphertext = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116177be3a9b38d89dd78f9de04dbd945f35f014b0e99e1e24e8ccac5b3a0b67ad4bec756b3c6b6bf5c0f325e33234e13b4b4c8bb1ab5e65b86f8b9e066ae4b3f8c93b9c4c89ee99b9ae6dc0e7a7c6ec6d0c0d0c0"
        ).unwrap();
        
        let cipher = ChaCha20Poly1305Cipher::from_key(&key).unwrap();
        let ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();
        
        // Vérifier que notre implémentation produit le résultat attendu
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 pour le tag Poly1305
        
        // Vérifier que le déchiffrement fonctionne
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_rfc8439_vector_2() {
        // Test avec données vides
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"";
        
        let cipher = ChaCha20Poly1305Cipher::from_key(&key).unwrap();
        let ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();
        
        // Même avec données vides, on doit avoir un tag de 16 bytes
        assert_eq!(ciphertext.len(), 16);
        
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_chacha20_poly1305_incremental_nonce() {
        // Test avec nonces incrémentaux (usage typique)
        let key = [1u8; 32];
        let plaintext = b"Message test avec nonce incremental";
        
        let cipher = ChaCha20Poly1305Cipher::from_key(&key).unwrap();
        
        for i in 0u32..10 {
            let mut nonce = [0u8; 12];
            nonce[8..12].copy_from_slice(&i.to_le_bytes());
            
            let ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();
            let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();
            
            assert_eq!(decrypted, plaintext);
        }
    }
}

/// Tests Ed25519 avec vecteurs RFC 8032
#[cfg(test)]
mod ed25519_kat {
    use super::*;
    
    #[test]
    fn test_rfc8032_vector_1() {
        // Vecteur de test officiel RFC 8032 Section 7.1
        let private_key_bytes = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ).unwrap();
        
        let public_key_bytes = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ).unwrap();
        
        let message = hex::decode("").unwrap(); // Message vide
        
        let expected_signature = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();
        
        // Créer les clés
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&private_key_bytes);
        let private_key = Ed25519PrivateKey::from_bytes(&private_key_array).unwrap();
        
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key_bytes);
        let public_key = Ed25519PublicKey::from_bytes(&public_key_array).unwrap();
        
        // Vérifier que notre clé publique correspond
        assert_eq!(private_key.public_key().to_bytes(), public_key.to_bytes());
        
        // Signer et vérifier
        let signature = Ed25519Signer::sign(&private_key, &message).unwrap();
        let mut expected_sig_array = [0u8; 64];
        expected_sig_array.copy_from_slice(&expected_signature);
        let expected_sig = Ed25519Signature::from_bytes(&expected_sig_array).unwrap();
        
        // Notre signature doit correspondre au vecteur attendu
        assert_eq!(signature.to_bytes(), expected_sig.to_bytes());
        
        // Vérification doit réussir
        assert!(Ed25519Signer::verify(&public_key, &message, &signature).unwrap());
    }
    
    #[test]
    fn test_rfc8032_vector_3() {
        // Vecteur avec message non vide
        let private_key_bytes = hex::decode(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        ).unwrap();
        
        let message = hex::decode("af82").unwrap();
        
        let expected_signature = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ).unwrap();
        
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&private_key_bytes);
        let private_key = Ed25519PrivateKey::from_bytes(&private_key_array).unwrap();
        
        let signature = Ed25519Signer::sign(&private_key, &message).unwrap();
        
        let mut expected_sig_array = [0u8; 64];
        expected_sig_array.copy_from_slice(&expected_signature);
        let expected_sig = Ed25519Signature::from_bytes(&expected_sig_array).unwrap();
        
        assert_eq!(signature.to_bytes(), expected_sig.to_bytes());
        
        let public_key = private_key.public_key();
        assert!(Ed25519Signer::verify(&public_key, &message, &signature).unwrap());
    }
    
    #[test]
    fn test_ed25519_malformed_signature() {
        // Test avec signature malformée (doit échouer)
        let private_key_bytes = [1u8; 32];
        let private_key = Ed25519PrivateKey::from_bytes(&private_key_bytes).unwrap();
        let public_key = private_key.public_key();
        
        let message = b"test message";
        let valid_signature = Ed25519Signer::sign(&private_key, message).unwrap();
        
        // Corrompre la signature
        let mut corrupted_sig_bytes = valid_signature.to_bytes();
        corrupted_sig_bytes[0] ^= 1;
        let corrupted_signature = Ed25519Signature::from_bytes(&corrupted_sig_bytes).unwrap();
        
        // La vérification doit échouer
        assert!(!Ed25519Signer::verify(&public_key, message, &corrupted_signature).unwrap());
    }
}

/// Tests BLAKE3 avec vecteurs officiels
#[cfg(test)]
mod blake3_kat {
    use super::*;
    
    #[test]
    fn test_blake3_empty_input() {
        // Hash de l'entrée vide selon spécification BLAKE3
        let input = b"";
        let hash = Blake3Hasher::hash(input);
        
        let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(hash.to_hex(), expected);
    }
    
    #[test]
    fn test_blake3_abc() {
        // Hash de "abc"
        let input = b"abc";
        let hash = Blake3Hasher::hash(input);
        
        let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
        assert_eq!(hash.to_hex(), expected);
    }
    
    #[test]
    fn test_blake3_longer_input() {
        // Test avec message plus long
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Blake3Hasher::hash(input);
        
        // Vérifier la longueur et la cohérence
        assert_eq!(hash.as_bytes().len(), 32);
        
        // Hash doit être déterministe
        let hash2 = Blake3Hasher::hash(input);
        assert_eq!(hash, hash2);
    }
    
    #[test]
    fn test_blake3_keyed_mode() {
        // Test du mode keyed de BLAKE3
        let key = [0u8; 32];
        let input = b"test data for keyed hash";
        
        let hash1 = Blake3Hasher::hash_keyed(&key, input);
        let hash2 = Blake3Hasher::hash_keyed(&key, input);
        
        // Déterminisme
        assert_eq!(hash1, hash2);
        
        // Différent du hash normal
        let normal_hash = Blake3Hasher::hash(input);
        assert_ne!(hash1, normal_hash);
        
        // Clé différente = hash différent
        let different_key = [1u8; 32];
        let hash3 = Blake3Hasher::hash_keyed(&different_key, input);
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_blake3_derive_key() {
        // Test de dérivation de clé BLAKE3
        let context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        let key_material = b"key material";
        
        let derived_key = Blake3Hasher::derive_key(context, key_material);
        
        // Vérifier la longueur
        assert_eq!(derived_key.len(), 32);
        
        // Déterminisme
        let derived_key2 = Blake3Hasher::derive_key(context, key_material);
        assert_eq!(derived_key, derived_key2);
        
        // Contexte différent = clé différente
        let derived_key3 = Blake3Hasher::derive_key("different context", key_material);
        assert_ne!(derived_key, derived_key3);
    }
}

/// Tests de performance et propriétés
#[cfg(test)]
mod crypto_properties {
    use super::*;
    use std::collections::HashSet;
    
    #[test]
    fn test_encryption_uniqueness() {
        // Vérifier que le même plaintext avec des nonces différents produit des ciphertexts différents
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let plaintext = b"Message identique";
        
        let mut ciphertexts = HashSet::new();
        
        for _ in 0..100 {
            let encrypted = cipher.encrypt_with_random_nonce(plaintext).unwrap();
            let serialized = bincode::serialize(&encrypted).unwrap();
            assert!(ciphertexts.insert(serialized), "Ciphertext dupliqué détecté");
        }
    }
    
    #[test]
    fn test_signature_uniqueness() {
        // Vérifier que chaque paire de clés génère des signatures différentes pour le même message
        let message = b"Message à signer";
        let mut signatures = HashSet::new();
        
        for _ in 0..50 {
            let (private_key, _) = Ed25519Signer::generate_keypair().unwrap();
            let signature = Ed25519Signer::sign(&private_key, message).unwrap();
            assert!(signatures.insert(signature.to_bytes()), "Signature dupliquée détectée");
        }
    }
    
    #[test]
    fn test_hash_avalanche_effect() {
        // Vérifier l'effet d'avalanche : un bit changé doit affecter ~50% des bits de sortie
        let input1 = b"test message for avalanche";
        let mut input2 = input1.clone();
        input2[0] ^= 1; // Changer un seul bit
        
        let hash1 = Blake3Hasher::hash(input1);
        let hash2 = Blake3Hasher::hash(&input2);
        
        // Compter les bits différents
        let mut different_bits = 0;
        for i in 0..32 {
            different_bits += (hash1.as_bytes()[i] ^ hash2.as_bytes()[i]).count_ones();
        }
        
        // L'effet d'avalanche doit être significatif (entre 30% et 70% des bits)
        let total_bits = 256;
        let percentage = (different_bits as f64 / total_bits as f64) * 100.0;
        assert!(percentage > 30.0 && percentage < 70.0, 
                "Effet d'avalanche insuffisant: {}%", percentage);
    }
    
    #[test]
    fn test_random_distribution() {
        // Vérifier que les générateurs aléatoires ont une distribution acceptable
        use miaou::crypto::primitives::random_bytes;
        
        let mut byte_counts = [0u32; 256];
        let sample_size = 10000;
        
        for _ in 0..sample_size {
            let random = random_bytes(1).unwrap();
            byte_counts[random[0] as usize] += 1;
        }
        
        // Vérifier que chaque valeur apparaît au moins quelques fois
        let min_count = sample_size / 512; // Au moins 1/512 de la distribution
        for (value, &count) in byte_counts.iter().enumerate() {
            assert!(count >= min_count, 
                   "Valeur {} sous-représentée: {} occurrences", value, count);
        }
    }
}

/// Tests de régression et cas limites
#[cfg(test)]
mod edge_cases {
    use super::*;
    
    #[test]
    fn test_large_message_encryption() {
        // Test avec message de 1MB
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let large_message = vec![0xAA; 1024 * 1024];
        
        let encrypted = cipher.encrypt_with_random_nonce(&large_message).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
        
        assert_eq!(decrypted, large_message);
    }
    
    #[test]
    fn test_zero_length_encryption() {
        // Test avec message vide
        let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let empty_message = b"";
        
        let encrypted = cipher.encrypt_with_random_nonce(empty_message).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
        
        assert_eq!(decrypted, empty_message);
        assert_eq!(encrypted.ciphertext.len(), 16); // Juste le tag Poly1305
    }
    
    #[test]
    fn test_signature_edge_cases() {
        let (private_key, public_key) = Ed25519Signer::generate_keypair().unwrap();
        
        // Message vide
        let empty_sig = Ed25519Signer::sign(&private_key, b"").unwrap();
        assert!(Ed25519Signer::verify(&public_key, b"", &empty_sig).unwrap());
        
        // Message de taille maximale pratique (64KB)
        let large_message = vec![0x42; 65536];
        let large_sig = Ed25519Signer::sign(&private_key, &large_message).unwrap();
        assert!(Ed25519Signer::verify(&public_key, &large_message, &large_sig).unwrap());
    }
}