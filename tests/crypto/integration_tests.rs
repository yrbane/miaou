//! Tests d'intégration cryptographiques
//! 
//! Tests de scénarios réalistes combinant plusieurs composants cryptographiques.

use miaou::crypto::{
    encryption::{ChaCha20Poly1305Cipher, EncryptionEngine},
    signing::{Ed25519KeyPair, Ed25519Signer, SigningEngine},
    hashing::{Blake3Hasher, Argon2Hasher, Argon2Config},
    keyring::{KeyStore, KeyStoreConfig, SecretKey, KeyPair},
    primitives::{derive_subkey, SecureIdGenerator},
};

/// Test d'un scénario complet de communication sécurisée
#[test]
fn test_secure_communication_scenario() {
    // Alice et Bob génèrent leurs paires de clés
    let alice_keypair = Ed25519KeyPair::generate().unwrap();
    let bob_keypair = Ed25519KeyPair::generate().unwrap();
    
    // Alice veut envoyer un message chiffré et signé à Bob
    let message = b"Message secret d'Alice pour Bob dans Miaou";
    
    // 1. Alice génère une clé de session éphémère
    let session_cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
    
    // 2. Alice chiffre le message avec la clé de session
    let encrypted_message = session_cipher.encrypt_with_random_nonce(message).unwrap();
    
    // 3. Alice signe le message chiffré pour authentification
    let signature = alice_keypair.sign(&encrypted_message.ciphertext).unwrap();
    
    // 4. Alice sérialise tout pour transmission
    let communication_packet = CommunicationPacket {
        encrypted_message,
        signature: signature.to_bytes(),
        sender_public_key: alice_keypair.public_key().to_bytes(),
    };
    
    let serialized = bincode::serialize(&communication_packet).unwrap();
    
    // === TRANSMISSION RÉSEAU (simulée) ===
    
    // 5. Bob reçoit et désérialise
    let received_packet: CommunicationPacket = bincode::deserialize(&serialized).unwrap();
    
    // 6. Bob vérifie la signature
    let alice_public_key = miaou::crypto::signing::Ed25519PublicKey::from_bytes(
        &received_packet.sender_public_key
    ).unwrap();
    let received_signature = miaou::crypto::signing::Ed25519Signature::from_bytes(
        &received_packet.signature
    ).unwrap();
    
    let signature_valid = Ed25519Signer::verify(
        &alice_public_key,
        &received_packet.encrypted_message.ciphertext,
        &received_signature
    ).unwrap();
    
    assert!(signature_valid, "Signature invalide");
    
    // 7. Bob déchiffre le message (il faudrait un échange de clés en pratique)
    let decrypted = session_cipher.decrypt_with_nonce(&received_packet.encrypted_message).unwrap();
    
    assert_eq!(decrypted, message);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CommunicationPacket {
    encrypted_message: miaou::crypto::encryption::EncryptedData,
    signature: [u8; 64],
    sender_public_key: [u8; 32],
}

/// Test d'un trousseau de clés complet avec hiérarchie
#[test]
fn test_hierarchical_key_management() {
    let config = KeyStoreConfig {
        argon2_config: Argon2Config::fast_insecure(), // Pour test rapide
        ..KeyStoreConfig::default()
    };
    
    let mut keystore = KeyStore::new_with_password(b"master_password_123", config).unwrap();
    
    // Créer une hiérarchie de clés
    let master_seed = b"master_seed_for_miaou_user_alice";
    
    // Clés de niveau 1 : par catégorie
    let encryption_master = derive_subkey(master_seed, "encryption", 0);
    let signing_master = derive_subkey(master_seed, "signing", 0);
    let storage_master = derive_subkey(master_seed, "storage", 0);
    
    // Clés de niveau 2 : par usage spécifique
    let message_key = derive_subkey(&encryption_master, "messages", 0);
    let file_key = derive_subkey(&encryption_master, "files", 0);
    let metadata_key = derive_subkey(&storage_master, "metadata", 0);
    
    // Ajouter au trousseau
    let keys = vec![
        ("encryption_master", encryption_master.to_vec()),
        ("signing_master", signing_master.to_vec()),
        ("storage_master", storage_master.to_vec()),
        ("message_key", message_key.to_vec()),
        ("file_key", file_key.to_vec()),
        ("metadata_key", metadata_key.to_vec()),
    ];
    
    let mut key_ids = Vec::new();
    
    for (name, key_data) in keys {
        let secret_key = SecretKey::new(
            key_data,
            miaou::crypto::keyring::KeyMetadata {
                key_id: miaou::crypto::primitives::random_array().unwrap(),
                key_type: miaou::crypto::keyring::KeyType::Derived {
                    context: name.to_string()
                },
                name: name.to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                expires_at: None,
                is_active: true,
                tags: vec!["hierarchical".to_string()],
            }
        );
        
        let key_id = secret_key.metadata().key_id;
        key_ids.push((name, key_id));
        keystore.add_secret_key(secret_key).unwrap();
    }
    
    // Vérifier que toutes les clés sont récupérables
    for (name, key_id) in &key_ids {
        let retrieved = keystore.get_secret_key(key_id).unwrap();
        assert!(retrieved.is_some(), "Clé {} non trouvée", name);
        assert_eq!(retrieved.unwrap().metadata().name, *name);
    }
    
    // Test export/import du trousseau
    let exported = keystore.export_encrypted().unwrap();
    
    let mut new_keystore = KeyStore::new_with_password(
        b"master_password_123", 
        KeyStoreConfig {
            argon2_config: Argon2Config::fast_insecure(),
            ..KeyStoreConfig::default()
        }
    ).unwrap();
    
    new_keystore.import_encrypted(&exported).unwrap();
    
    // Vérifier que l'import a fonctionné
    for (name, key_id) in &key_ids {
        let retrieved = new_keystore.get_secret_key(key_id).unwrap();
        assert!(retrieved.is_some(), "Clé {} non trouvée après import", name);
    }
}

/// Test de performance et résistance aux attaques
#[test]
fn test_crypto_performance_and_security() {
    let start = std::time::Instant::now();
    
    // Test de performance du chiffrement
    let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
    let large_data = vec![0x42; 1024 * 1024]; // 1MB
    
    let encrypted = cipher.encrypt_with_random_nonce(&large_data).unwrap();
    let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
    
    assert_eq!(decrypted, large_data);
    
    let encryption_time = start.elapsed();
    println!("Chiffrement/déchiffrement 1MB: {:?}", encryption_time);
    
    // Test de performance des signatures
    let start = std::time::Instant::now();
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Message pour test de performance de signature";
    
    for _ in 0..1000 {
        let signature = keypair.sign(message).unwrap();
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
    }
    
    let signing_time = start.elapsed();
    println!("1000 signatures/vérifications: {:?}", signing_time);
    
    // Test de performance du hachage
    let start = std::time::Instant::now();
    let data = vec![0x33; 1024 * 1024]; // 1MB
    
    for _ in 0..10 {
        let _hash = Blake3Hasher::hash(&data);
    }
    
    let hashing_time = start.elapsed();
    println!("10 hachages de 1MB: {:?}", hashing_time);
    
    // Les performances doivent être raisonnables (ajustez selon votre matériel)
    assert!(encryption_time.as_millis() < 1000, "Chiffrement trop lent");
    assert!(signing_time.as_millis() < 1000, "Signatures trop lentes");
    assert!(hashing_time.as_millis() < 1000, "Hachage trop lent");
}

/// Test de sécurité : tentatives d'attaques courantes
#[test]
fn test_security_against_common_attacks() {
    // Test contre réutilisation de nonce
    let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
    let nonce = [0u8; 12]; // Nonce fixe (MAUVAISE PRATIQUE)
    
    let message1 = b"Premier message";
    let message2 = b"Second message";
    
    let ciphertext1 = cipher.encrypt(message1, &nonce).unwrap();
    let ciphertext2 = cipher.encrypt(message2, &nonce).unwrap();
    
    // Même nonce = problème de sécurité détectable
    // En pratique, on ne devrait jamais faire ça
    assert_ne!(ciphertext1, ciphertext2); // Toujours différents grâce au contenu
    
    // Test contre modification de ciphertext
    let mut corrupted_ciphertext = ciphertext1.clone();
    corrupted_ciphertext[0] ^= 1; // Corruption d'un bit
    
    let decrypt_result = cipher.decrypt(&corrupted_ciphertext, &nonce);
    assert!(decrypt_result.is_err(), "Déchiffrement corrompu aurait dû échouer");
    
    // Test contre clés faibles
    let weak_key = [0u8; 32]; // Clé nulle
    let weak_cipher = ChaCha20Poly1305Cipher::from_key(&weak_key).unwrap();
    
    // Même avec une clé faible, l'algorithme doit fonctionner
    let encrypted = weak_cipher.encrypt_with_random_nonce(b"test").unwrap();
    let decrypted = weak_cipher.decrypt_with_nonce(&encrypted).unwrap();
    assert_eq!(decrypted, b"test");
    
    // Test contre signatures malformées
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Test message";
    let valid_signature = keypair.sign(message).unwrap();
    
    // Signature avec tous les bits à 1 (invalide)
    let invalid_signature = miaou::crypto::signing::Ed25519Signature::from_bytes(&[0xFF; 64]).unwrap();
    let verification = keypair.verify(message, &invalid_signature).unwrap();
    assert!(!verification, "Signature invalide acceptée");
    
    // Signature avec tous les bits à 0 (invalide)
    let zero_signature = miaou::crypto::signing::Ed25519Signature::from_bytes(&[0x00; 64]).unwrap();
    let verification = keypair.verify(message, &zero_signature).unwrap();
    assert!(!verification, "Signature nulle acceptée");
}

/// Test de génération d'identifiants uniques
#[test]
fn test_unique_id_generation() {
    let generator = SecureIdGenerator::new().unwrap();
    let mut ids = std::collections::HashSet::new();
    
    // Générer beaucoup d'IDs rapidement
    for _ in 0..10000 {
        let id = generator.generate_id();
        assert!(ids.insert(id), "ID dupliqué détecté");
    }
    
    // Test sur plusieurs générateurs (simulation de nœuds différents)
    let generator2 = SecureIdGenerator::new().unwrap();
    let generator3 = SecureIdGenerator::new().unwrap();
    
    for _ in 0..1000 {
        let id1 = generator.generate_id();
        let id2 = generator2.generate_id();
        let id3 = generator3.generate_id();
        
        assert!(ids.insert(id1));
        assert!(ids.insert(id2));
        assert!(ids.insert(id3));
    }
    
    println!("Généré {} IDs uniques", ids.len());
}

/// Test de scénario de sauvegarde et récupération
#[test]
fn test_backup_and_recovery_scenario() {
    // Simulation d'un utilisateur qui sauvegarde ses clés
    let original_password = b"user_password_123";
    let config = KeyStoreConfig {
        argon2_config: Argon2Config::fast_insecure(),
        ..KeyStoreConfig::default()
    };
    
    let mut original_keystore = KeyStore::new_with_password(original_password, config.clone()).unwrap();
    
    // Créer plusieurs clés importantes
    let encryption_keypair = KeyPair::generate_ed25519("main_encryption".to_string(), vec!["primary".to_string()]).unwrap();
    let signing_keypair = KeyPair::generate_ed25519("main_signing".to_string(), vec!["primary".to_string()]).unwrap();
    
    let encryption_key_id = encryption_keypair.private_key().metadata().key_id;
    let signing_key_id = signing_keypair.private_key().metadata().key_id;
    
    original_keystore.add_secret_key(
        SecretKey::new(
            encryption_keypair.private_key().key_data().to_vec(),
            encryption_keypair.private_key().metadata().clone()
        )
    ).unwrap();
    
    original_keystore.add_secret_key(
        SecretKey::new(
            signing_keypair.private_key().key_data().to_vec(),
            signing_keypair.private_key().metadata().clone()
        )
    ).unwrap();
    
    // Sauvegarder
    let backup_data = original_keystore.export_encrypted().unwrap();
    
    // Simulation : l'utilisateur perd son trousseau et doit le restaurer
    let mut recovered_keystore = KeyStore::new_with_password(original_password, config).unwrap();
    recovered_keystore.import_encrypted(&backup_data).unwrap();
    
    // Vérifier que les clés sont récupérées
    let recovered_encryption = recovered_keystore.get_secret_key(&encryption_key_id).unwrap();
    let recovered_signing = recovered_keystore.get_secret_key(&signing_key_id).unwrap();
    
    assert!(recovered_encryption.is_some());
    assert!(recovered_signing.is_some());
    
    // Vérifier que les clés fonctionnent encore
    let test_message = b"Test après récupération";
    
    // Test de chiffrement
    let recovered_enc_data = recovered_encryption.unwrap().key_data();
    let mut enc_key_array = [0u8; 32];
    enc_key_array.copy_from_slice(&recovered_enc_data[0..32]);
    let cipher = ChaCha20Poly1305Cipher::from_key(&enc_key_array).unwrap();
    
    let encrypted = cipher.encrypt_with_random_nonce(test_message).unwrap();
    let decrypted = cipher.decrypt_with_nonce(&encrypted).unwrap();
    assert_eq!(decrypted, test_message);
    
    // Test de signature
    let recovered_sign_data = recovered_signing.unwrap().key_data();
    let mut sign_key_array = [0u8; 32];
    sign_key_array.copy_from_slice(&recovered_sign_data[0..32]);
    let private_key = miaou::crypto::signing::Ed25519PrivateKey::from_bytes(&sign_key_array).unwrap();
    
    let signature = Ed25519Signer::sign(&private_key, test_message).unwrap();
    let public_key = private_key.public_key();
    let is_valid = Ed25519Signer::verify(&public_key, test_message, &signature).unwrap();
    assert!(is_valid);
    
    println!("Sauvegarde et récupération réussies !");
}