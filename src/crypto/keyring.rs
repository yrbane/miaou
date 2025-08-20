//! Gestion sécurisée des clés cryptographiques
//! 
//! Système de trousseau de clés avec stockage sécurisé, dérivation de clés
//! et protection contre les accès non autorisés.

use crate::crypto::{
    CryptoError, CryptoResult,
    encryption::{ChaCha20Poly1305Cipher, EncryptionEngine, EncryptedData},
    signing::{Ed25519KeyPair},
    hashing::{Argon2Hasher, Argon2Config, Blake3Hasher, HashingEngine},
    primitives::{random_array, derive_subkey, secure_compare},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Identifiant unique d'une clé
pub type KeyId = [u8; 16];

/// Types de clés supportés
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// Clé de chiffrement ChaCha20-Poly1305
    Encryption,
    /// Clé de signature Ed25519
    Signing,
    /// Clé dérivée personnalisée
    Derived { context: String },
}

/// Métadonnées d'une clé
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Identifiant unique de la clé
    pub key_id: KeyId,
    /// Type de clé
    pub key_type: KeyType,
    /// Nom descriptif de la clé
    pub name: String,
    /// Date de création (timestamp Unix)
    pub created_at: u64,
    /// Date d'expiration optionnelle
    pub expires_at: Option<u64>,
    /// Indique si la clé est active
    pub is_active: bool,
    /// Tags pour organisation
    pub tags: Vec<String>,
}

/// Clé secrète avec protection
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    /// Données de la clé
    key_data: Vec<u8>,
    /// Métadonnées
    #[zeroize(skip)]
    metadata: KeyMetadata,
}

/// Clé publique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Données de la clé publique
    pub key_data: Vec<u8>,
    /// Métadonnées
    pub metadata: KeyMetadata,
}

/// Paire de clés complète
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    /// Clé privée
    private_key: SecretKey,
    /// Clé publique correspondante
    #[zeroize(skip)]
    public_key: PublicKey,
}

/// Trousseau de clés sécurisé
pub struct KeyStore {
    /// Clé maître pour chiffrer le trousseau
    master_key: [u8; 32],
    /// Clés stockées (chiffrées)
    encrypted_keys: HashMap<KeyId, EncryptedKeyEntry>,
    /// Cache des clés déchiffrées (temporaire)
    key_cache: HashMap<KeyId, SecretKey>,
    /// Configuration Argon2 pour dérivation de clés
    argon2_config: Argon2Config,
}

/// Entrée de clé chiffrée dans le stockage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyEntry {
    /// Métadonnées (non chiffrées pour recherche)
    metadata: KeyMetadata,
    /// Données de clé chiffrées
    encrypted_data: EncryptedData,
    /// Hash d'intégrité
    integrity_hash: [u8; 32],
}

/// Configuration du trousseau
#[derive(Debug, Clone)]
pub struct KeyStoreConfig {
    /// Utiliser un cache en mémoire pour les clés
    pub enable_cache: bool,
    /// Durée de vie du cache en secondes
    pub cache_lifetime: u64,
    /// Configuration Argon2 pour dérivation
    pub argon2_config: Argon2Config,
    /// Taille maximale du trousseau (nombre de clés)
    pub max_keys: usize,
}

impl Default for KeyStoreConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_lifetime: 300, // 5 minutes
            argon2_config: Argon2Config::secure(),
            max_keys: 1000,
        }
    }
}

impl SecretKey {
    /// Crée une nouvelle clé secrète
    pub fn new(key_data: Vec<u8>, metadata: KeyMetadata) -> Self {
        Self { key_data, metadata }
    }
    
    /// Accès aux données de la clé (lecture seule)
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }
    
    /// Accès aux métadonnées
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }
    
    /// Vérifie si la clé est expirée
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.metadata.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }
    
    /// Génère une clé de chiffrement
    pub fn generate_encryption_key(name: String, tags: Vec<String>) -> CryptoResult<Self> {
        let key_data = random_array::<32>()?;
        let metadata = KeyMetadata {
            key_id: random_array::<16>()?,
            key_type: KeyType::Encryption,
            name,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: None,
            is_active: true,
            tags,
        };
        
        Ok(Self::new(key_data.to_vec(), metadata))
    }
    
    /// Génère une clé dérivée
    pub fn derive_key(
        master_key: &[u8], 
        context: String, 
        index: u32,
        name: String,
        tags: Vec<String>
    ) -> CryptoResult<Self> {
        let derived_key = derive_subkey(master_key, &context, index);
        let metadata = KeyMetadata {
            key_id: random_array::<16>()?,
            key_type: KeyType::Derived { context },
            name,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: None,
            is_active: true,
            tags,
        };
        
        Ok(Self::new(derived_key.to_vec(), metadata))
    }
}

impl PublicKey {
    /// Crée une nouvelle clé publique
    pub fn new(key_data: Vec<u8>, metadata: KeyMetadata) -> Self {
        Self { key_data, metadata }
    }
    
    /// Calcule l'empreinte de la clé publique
    pub fn fingerprint(&self) -> [u8; 8] {
        let hash = Blake3Hasher::hash(&self.key_data);
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&hash.as_bytes()[0..8]);
        fingerprint
    }
}

impl KeyPair {
    /// Génère une nouvelle paire de clés Ed25519
    pub fn generate_ed25519(name: String, tags: Vec<String>) -> CryptoResult<Self> {
        let ed25519_keypair = Ed25519KeyPair::generate()?;
        let key_id = random_array::<16>()?;
        
        let private_metadata = KeyMetadata {
            key_id,
            key_type: KeyType::Signing,
            name: name.clone(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: None,
            is_active: true,
            tags: tags.clone(),
        };
        
        let public_metadata = private_metadata.clone();
        
        let private_key = SecretKey::new(
            ed25519_keypair.private_key().to_bytes().to_vec(),
            private_metadata,
        );
        
        let public_key = PublicKey::new(
            ed25519_keypair.public_key().to_bytes().to_vec(),
            public_metadata,
        );
        
        Ok(Self { private_key, public_key })
    }
    
    /// Accès à la clé privée
    pub fn private_key(&self) -> &SecretKey {
        &self.private_key
    }
    
    /// Accès à la clé publique
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl KeyStore {
    /// Crée un nouveau trousseau avec mot de passe
    pub fn new_with_password(password: &[u8], config: KeyStoreConfig) -> CryptoResult<Self> {
        let salt = random_array::<16>()?;
        let master_key = Argon2Hasher::derive_key(password, &salt, &config.argon2_config)?;
        
        if master_key.len() != 32 {
            return Err(CryptoError::KeyGenerationError("Taille de clé maître invalide".into()));
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&master_key[0..32]);
        
        Ok(Self {
            master_key: key_array,
            encrypted_keys: HashMap::new(),
            key_cache: HashMap::new(),
            argon2_config: config.argon2_config,
        })
    }
    
    /// Ajoute une clé secrète au trousseau
    pub fn add_secret_key(&mut self, key: SecretKey) -> CryptoResult<()> {
        let key_id = key.metadata().key_id;
        
        // Chiffrer la clé avec la clé maître
        let cipher = ChaCha20Poly1305Cipher::from_key(&self.master_key)?;
        let encrypted_data = cipher.encrypt_with_random_nonce(key.key_data())?;
        
        // Calculer hash d'intégrité
        let integrity_data = [key.key_data(), &key_id].concat();
        let integrity_hash = Blake3Hasher::hash(&integrity_data);
        
        let entry = EncryptedKeyEntry {
            metadata: key.metadata().clone(),
            encrypted_data,
            integrity_hash: *integrity_hash.as_bytes(),
        };
        
        self.encrypted_keys.insert(key_id, entry);
        self.key_cache.insert(key_id, key);
        
        Ok(())
    }
    
    /// Récupère une clé par son ID
    pub fn get_secret_key(&mut self, key_id: &KeyId) -> CryptoResult<Option<&SecretKey>> {
        // Vérifier le cache d'abord
        if let Some(key) = self.key_cache.get(key_id) {
            if !key.is_expired() {
                return Ok(Some(key));
            } else {
                // Supprimer la clé expirée du cache
                self.key_cache.remove(key_id);
                return Err(CryptoError::VerificationError("Clé expirée".into()));
            }
        }
        
        // Déchiffrer depuis le stockage
        if let Some(entry) = self.encrypted_keys.get(key_id) {
            let cipher = ChaCha20Poly1305Cipher::from_key(&self.master_key)?;
            let key_data = cipher.decrypt_with_nonce(&entry.encrypted_data)?;
            
            // Vérifier l'intégrité
            let integrity_data = [&key_data, key_id.as_slice()].concat();
            let computed_hash = Blake3Hasher::hash(&integrity_data);
            
            if !secure_compare(computed_hash.as_bytes(), &entry.integrity_hash) {
                return Err(CryptoError::VerificationError("Intégrité de clé corrompue".into()));
            }
            
            let key = SecretKey::new(key_data, entry.metadata.clone());
            
            if key.is_expired() {
                return Err(CryptoError::VerificationError("Clé expirée".into()));
            }
            
            self.key_cache.insert(*key_id, key);
            Ok(self.key_cache.get(key_id))
        } else {
            Ok(None)
        }
    }
    
    /// Liste toutes les clés (métadonnées uniquement)
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.encrypted_keys.values().map(|entry| &entry.metadata).collect()
    }
    
    /// Supprime une clé
    pub fn remove_key(&mut self, key_id: &KeyId) -> CryptoResult<bool> {
        let removed_encrypted = self.encrypted_keys.remove(key_id).is_some();
        let removed_cached = self.key_cache.remove(key_id).is_some();
        
        Ok(removed_encrypted || removed_cached)
    }
    
    /// Nettoie le cache des clés
    pub fn clear_cache(&mut self) {
        self.key_cache.clear();
    }
    
    /// Exporte le trousseau chiffré
    pub fn export_encrypted(&self) -> CryptoResult<Vec<u8>> {
        let data = bincode::serialize(&self.encrypted_keys)
            .map_err(|e| CryptoError::EncryptionError(format!("Serialization failed: {}", e)))?;
        
        let cipher = ChaCha20Poly1305Cipher::from_key(&self.master_key)?;
        cipher.encrypt_with_random_nonce(&data)
            .map(|encrypted| bincode::serialize(&encrypted).unwrap())
    }
    
    /// Importe un trousseau chiffré
    pub fn import_encrypted(&mut self, data: &[u8]) -> CryptoResult<()> {
        let encrypted_data: EncryptedData = bincode::deserialize(data)
            .map_err(|e| CryptoError::DecryptionError(format!("Deserialization failed: {}", e)))?;
        
        let cipher = ChaCha20Poly1305Cipher::from_key(&self.master_key)?;
        let decrypted_data = cipher.decrypt_with_nonce(&encrypted_data)?;
        
        let imported_keys: HashMap<KeyId, EncryptedKeyEntry> = bincode::deserialize(&decrypted_data)
            .map_err(|e| CryptoError::DecryptionError(format!("Key data deserialization failed: {}", e)))?;
        
        // Fusionner avec les clés existantes
        self.encrypted_keys.extend(imported_keys);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_key_generation() {
        let key = SecretKey::generate_encryption_key(
            "test_key".to_string(),
            vec!["test".to_string()],
        ).unwrap();
        
        assert_eq!(key.key_data().len(), 32);
        assert_eq!(key.metadata().name, "test_key");
        assert_eq!(key.metadata().key_type, KeyType::Encryption);
        assert!(!key.is_expired());
    }
    
    #[test]
    fn test_key_derivation() {
        let master = &[1u8; 32];
        let key1 = SecretKey::derive_key(
            master, 
            "encryption".to_string(),
            0,
            "derived_key".to_string(),
            vec![]
        ).unwrap();
        
        let key2 = SecretKey::derive_key(
            master,
            "encryption".to_string(),
            1,
            "derived_key2".to_string(),
            vec![]
        ).unwrap();
        
        assert_ne!(key1.key_data(), key2.key_data());
        assert_eq!(key1.key_data().len(), 32);
    }
    
    #[test]
    fn test_ed25519_keypair() {
        let keypair = KeyPair::generate_ed25519(
            "signing_key".to_string(),
            vec!["ed25519".to_string()],
        ).unwrap();
        
        assert_eq!(keypair.private_key().key_data().len(), 32);
        assert_eq!(keypair.public_key().key_data.len(), 32);
        assert_eq!(keypair.private_key().metadata().key_id, 
                   keypair.public_key().metadata.key_id);
    }
    
    #[test]
    fn test_keystore_basic_operations() {
        let config = KeyStoreConfig::default();
        let mut keystore = KeyStore::new_with_password(b"test_password", config).unwrap();
        
        let key = SecretKey::generate_encryption_key(
            "test_key".to_string(),
            vec![],
        ).unwrap();
        let key_id = key.metadata().key_id;
        
        // Ajouter la clé
        keystore.add_secret_key(key).unwrap();
        
        // Récupérer la clé
        let retrieved_key = keystore.get_secret_key(&key_id).unwrap();
        assert!(retrieved_key.is_some());
        
        // Lister les clés
        let keys = keystore.list_keys();
        assert_eq!(keys.len(), 1);
        
        // Supprimer la clé
        assert!(keystore.remove_key(&key_id).unwrap());
        assert!(keystore.get_secret_key(&key_id).unwrap().is_none());
    }
    
    #[test]
    fn test_keystore_export_import() {
        let config = KeyStoreConfig::default();
        let mut keystore1 = KeyStore::new_with_password(b"test_password", config.clone()).unwrap();
        
        let key = SecretKey::generate_encryption_key("test_key".to_string(), vec![]).unwrap();
        let key_id = key.metadata().key_id;
        keystore1.add_secret_key(key).unwrap();
        
        // Exporter
        let exported_data = keystore1.export_encrypted().unwrap();
        
        // Importer dans nouveau trousseau
        let mut keystore2 = KeyStore::new_with_password(b"test_password", config).unwrap();
        keystore2.import_encrypted(&exported_data).unwrap();
        
        // Vérifier que la clé est présente
        let retrieved_key = keystore2.get_secret_key(&key_id).unwrap();
        assert!(retrieved_key.is_some());
    }
    
    #[test]
    fn test_public_key_fingerprint() {
        let keypair = KeyPair::generate_ed25519("test".to_string(), vec![]).unwrap();
        let fingerprint = keypair.public_key().fingerprint();
        
        assert_eq!(fingerprint.len(), 8);
        
        // Même clé = même empreinte
        let fingerprint2 = keypair.public_key().fingerprint();
        assert_eq!(fingerprint, fingerprint2);
    }
    
    #[test]
    fn test_key_integrity_check() {
        let config = KeyStoreConfig::default();
        let mut keystore = KeyStore::new_with_password(b"password", config).unwrap();
        
        let key = SecretKey::generate_encryption_key("test".to_string(), vec![]).unwrap();
        let key_id = key.metadata().key_id;
        
        keystore.add_secret_key(key).unwrap();
        
        // Corrompre l'entrée chiffrée
        if let Some(entry) = keystore.encrypted_keys.get_mut(&key_id) {
            entry.integrity_hash[0] ^= 1; // Corruption d'un bit
        }
        
        // Clear cache pour forcer la lecture du stockage
        keystore.clear_cache();
        
        // La récupération doit échouer
        let result = keystore.get_secret_key(&key_id);
        assert!(result.is_err());
    }
}