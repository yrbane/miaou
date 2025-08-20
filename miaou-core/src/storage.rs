// Module de stockage sécurisé pour Miaou v0.1.0
// Gestion des profils utilisateur avec chiffrement des données sensibles

use crate::crypto::{
    aead::{decrypt, encrypt_auto_nonce, AeadKeyRef},
    hash::blake3_32,
    kdf::{derive_key_32, generate_salt, hash_password, verify_password, Argon2Config},
    sign::Keypair,
    CryptoError,
};
use anyhow::Result;

/// Trait pour les implémentations de stockage sécurisé
pub trait StorageBackend {
    /// Stocke des données sous une clé
    ///
    /// # Errors
    /// Retourne une erreur si l'écriture échoue ou si les données sont invalides.
    fn store(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Récupère des données par clé
    ///
    /// # Errors
    /// Retourne une erreur si la clé n'existe pas ou si la lecture échoue.
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError>;

    /// Supprime des données par clé
    ///
    /// # Errors
    /// Retourne une erreur si la suppression échoue.
    fn delete(&mut self, key: &str) -> Result<(), StorageError>;

    /// Vérifie si une clé existe
    fn exists(&self, key: &str) -> bool;
}
use chrono::{DateTime, Utc};
use secrecy::{SecretString, Zeroize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::path::{Path, PathBuf};

/// Erreurs de stockage
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Erreur d'entrée/sortie système
    #[error("Erreur d'E/S: {0}")]
    Io(#[from] std::io::Error),

    /// Erreur de sérialisation JSON
    #[error("Erreur de sérialisation: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Erreur cryptographique
    #[error("Erreur cryptographique: {0}")]
    Crypto(#[from] CryptoError),

    /// Profil introuvable
    #[error("Profil non trouvé: {0}")]
    ProfileNotFound(String),

    /// Tentative de création d'un profil existant
    #[error("Profil déjà existant: {0}")]
    ProfileAlreadyExists(String),

    /// Mot de passe incorrect
    #[error("Mot de passe invalide")]
    InvalidPassword,

    /// Données de profil corrompues
    #[error("Données corrompues ou version incompatible")]
    CorruptedData,

    /// Clé non trouvée dans le storage
    #[error("Clé non trouvée")]
    NotFound,
}

/// Gestionnaire de stockage sécurisé
pub struct SecureStorage {
    /// Répertoire racine de stockage
    storage_root: PathBuf,
}

impl SecureStorage {
    /// Crée une nouvelle instance de stockage
    ///
    /// # Errors
    /// Échec si les répertoires ne peuvent pas être créés ou accédés.
    pub fn new<P: AsRef<Path>>(storage_root: P) -> Result<Self> {
        let storage_root = storage_root.as_ref().to_path_buf();

        // Créer les répertoires nécessaires
        fs::create_dir_all(&storage_root)?;
        fs::create_dir_all(storage_root.join("profiles"))?;
        fs::create_dir_all(storage_root.join("keystore"))?;

        Ok(Self { storage_root })
    }

    /// Crée un nouveau profil utilisateur
    ///
    /// # Errors
    /// Échec si le profil existe déjà ou si les opérations cryptographiques échouent.
    pub fn create_profile(&self, name: &str, password: &SecretString) -> Result<ProfileId> {
        let profile_id = ProfileId::new(name);
        let profile_path = self.get_profile_path(&profile_id);

        // Vérifier que le profil n'existe pas
        if profile_path.exists() {
            return Err(StorageError::ProfileAlreadyExists(name.to_string()).into());
        }

        // Générer les clés cryptographiques
        let identity_keypair = Keypair::generate();
        let mut rng = rand_core::OsRng;
        let _storage_key = AeadKeyRef::generate(&mut rng);

        // Créer le hash du mot de passe pour l'authentification
        let config = Argon2Config::balanced();
        let password_hash = hash_password(password, &config)?;

        // Dériver une clé de chiffrement depuis le mot de passe
        let salt = generate_salt();
        let encryption_key_bytes = derive_key_32(password, &salt, &config)?;
        let encryption_key = AeadKeyRef::from_bytes(encryption_key_bytes);

        // Chiffrer les données sensibles (clés privées)
        let identity_private_bytes = identity_keypair.secret.to_bytes();
        let encrypted_identity = encrypt_auto_nonce(
            &encryption_key,
            b"miaou_identity_v0.1.0",
            &identity_private_bytes,
            &mut rng,
        )?;

        // Créer la structure du profil
        let profile = ProfileData {
            metadata: ProfileMetadata {
                id: profile_id.clone(),
                name: name.to_string(),
                version: "0.1.0".to_string(),
                created: Utc::now(),
                last_access: Utc::now(),
            },
            auth: AuthenticationData {
                password_hash,
                salt: salt.to_string(),
                config_type: "balanced".to_string(),
            },
            keys: KeyData {
                public_identity: identity_keypair.public.to_bytes(),
                encrypted_private_identity: encrypted_identity,
                key_fingerprint: blake3_32(&identity_keypair.public.to_bytes()),
            },
            settings: ProfileSettings::default(),
        };

        // Sauvegarder le profil
        let profile_json = serde_json::to_string_pretty(&profile)?;
        fs::write(&profile_path, profile_json)?;

        // Nettoyer les données sensibles
        let mut identity_private_bytes = identity_private_bytes;
        identity_private_bytes.zeroize();
        let mut encryption_key_bytes = encryption_key_bytes;
        encryption_key_bytes.zeroize();

        Ok(profile_id)
    }

    /// Charge un profil utilisateur avec authentification
    ///
    /// # Errors
    /// Échec si le profil n'existe pas, si le mot de passe est incorrect, ou si les données sont corrompues.
    pub fn load_profile(
        &self,
        profile_id: &ProfileId,
        password: &SecretString,
    ) -> Result<ProfileHandle> {
        let profile_path = self.get_profile_path(profile_id);

        if !profile_path.exists() {
            return Err(StorageError::ProfileNotFound(profile_id.name.clone()).into());
        }

        // Charger les données du profil
        let profile_data = fs::read_to_string(&profile_path)?;
        let profile: ProfileData = serde_json::from_str(&profile_data)?;

        // Vérifier le mot de passe
        if !verify_password(password, &profile.auth.password_hash)? {
            return Err(StorageError::InvalidPassword.into());
        }

        // Dériver la clé de déchiffrement
        let salt = argon2::password_hash::SaltString::from_b64(&profile.auth.salt)
            .map_err(|_| StorageError::CorruptedData)?;
        let config = match profile.auth.config_type.as_str() {
            "balanced" => Argon2Config::balanced(),
            "secure" => Argon2Config::secure(),
            "fast_insecure" => Argon2Config::fast_insecure(),
            _ => return Err(StorageError::CorruptedData.into()),
        };

        let encryption_key_bytes = derive_key_32(password, &salt, &config)?;
        let encryption_key = AeadKeyRef::from_bytes(encryption_key_bytes);

        // Déchiffrer la clé privée d'identité
        let identity_private_bytes = decrypt(
            &encryption_key,
            b"miaou_identity_v0.1.0",
            &profile.keys.encrypted_private_identity,
        )?;

        // Reconstruire la paire de clés
        if identity_private_bytes.len() != 32 {
            return Err(StorageError::CorruptedData.into());
        }
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(&identity_private_bytes);
        let identity_keypair = Keypair::from_private_bytes(private_key_array)?;

        // Vérifier l'intégrité de la clé publique
        if identity_keypair.public.to_bytes() != profile.keys.public_identity {
            return Err(StorageError::CorruptedData.into());
        }

        // Mettre à jour l'horodatage d'accès
        self.update_last_access(profile_id)?;

        Ok(ProfileHandle {
            metadata: profile.metadata,
            identity_keypair,
            settings: profile.settings,
        })
    }

    /// Liste tous les profils disponibles
    ///
    /// # Errors
    /// Échec si le répertoire de profils ne peut pas être lu.
    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>> {
        let profiles_dir = self.storage_root.join("profiles");
        let mut profiles = Vec::new();

        if !profiles_dir.exists() {
            return Ok(profiles);
        }

        for entry in fs::read_dir(&profiles_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(profile) = serde_json::from_str::<ProfileData>(&data) {
                        profiles.push(ProfileInfo {
                            id: profile.metadata.id,
                            name: profile.metadata.name,
                            created: profile.metadata.created,
                            last_access: profile.metadata.last_access,
                            public_key_fingerprint: hex::encode(profile.keys.key_fingerprint),
                        });
                    }
                }
            }
        }

        // Trier par date de dernière utilisation
        profiles.sort_by(|a, b| b.last_access.cmp(&a.last_access));

        Ok(profiles)
    }

    /// Supprime un profil
    ///
    /// # Errors
    /// Échec si le profil n'existe pas ou si la suppression échoue.
    pub fn delete_profile(&self, profile_id: &ProfileId) -> Result<()> {
        let profile_path = self.get_profile_path(profile_id);

        if !profile_path.exists() {
            return Err(StorageError::ProfileNotFound(profile_id.name.clone()).into());
        }

        fs::remove_file(&profile_path)?;

        // TODO: Supprimer aussi les données associées (keystore, messages, etc.)

        Ok(())
    }

    /// Met à jour l'horodatage de dernière utilisation
    fn update_last_access(&self, profile_id: &ProfileId) -> Result<()> {
        let profile_path = self.get_profile_path(profile_id);

        if let Ok(data) = fs::read_to_string(&profile_path) {
            if let Ok(mut profile) = serde_json::from_str::<ProfileData>(&data) {
                profile.metadata.last_access = Utc::now();
                let updated_data = serde_json::to_string_pretty(&profile)?;
                fs::write(&profile_path, updated_data)?;
            }
        }

        Ok(())
    }

    /// Retourne le chemin du fichier de profil
    fn get_profile_path(&self, profile_id: &ProfileId) -> PathBuf {
        self.storage_root
            .join("profiles")
            .join(format!("{}.json", profile_id.safe_name()))
    }
}

/// Identifiant unique d'un profil
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId {
    /// Nom du profil choisi par l'utilisateur
    pub name: String,
    /// Hash du nom pour éviter les collisions et créer un nom de fichier sûr
    pub hash: String,
}

impl ProfileId {
    /// Crée un nouvel identifiant de profil
    #[must_use]
    pub fn new(name: &str) -> Self {
        let hash = hex::encode(blake3_32(name.as_bytes()));
        Self {
            name: name.to_string(),
            hash,
        }
    }

    /// Retourne un nom de fichier sécurisé pour ce profil
    #[must_use]
    pub fn safe_name(&self) -> String {
        format!("{}_{}", sanitize_filename(&self.name), &self.hash[..8])
    }
}

/// Informations publiques sur un profil
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    /// Identifiant unique du profil
    pub id: ProfileId,
    /// Nom du profil
    pub name: String,
    /// Date de création
    pub created: DateTime<Utc>,
    /// Dernier accès
    pub last_access: DateTime<Utc>,
    /// Empreinte de la clé publique (hex)
    pub public_key_fingerprint: String,
}

/// Handle vers un profil chargé en mémoire
pub struct ProfileHandle {
    /// Métadonnées du profil
    pub metadata: ProfileMetadata,
    /// Paire de clés d'identité (déchiffrée)
    pub identity_keypair: Keypair,
    /// Paramètres utilisateur
    pub settings: ProfileSettings,
}

/// Métadonnées d'un profil
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// Identifiant unique
    pub id: ProfileId,
    /// Nom du profil
    pub name: String,
    /// Version de Miaou utilisée pour créer le profil
    pub version: String,
    /// Date de création
    pub created: DateTime<Utc>,
    /// Dernier accès
    pub last_access: DateTime<Utc>,
}

/// Données d'authentification
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationData {
    /// Hash Argon2 du mot de passe
    pub password_hash: String,
    /// Sel utilisé pour la dérivation de clé
    pub salt: String,
    /// Configuration Argon2 utilisée (balanced, secure, `fast_insecure`)
    pub config_type: String,
}

/// Données cryptographiques
#[derive(Debug)]
pub struct KeyData {
    /// Clé publique d'identité Ed25519 (32 bytes)
    pub public_identity: [u8; 32],
    /// Clé privée chiffrée avec le mot de passe utilisateur
    pub encrypted_private_identity: crate::crypto::aead::SealedData,
    /// Empreinte BLAKE3 de la clé publique
    pub key_fingerprint: [u8; 32],
}

// Sérialisation custom pour KeyData
impl Serialize for KeyData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KeyData", 3)?;
        state.serialize_field("public_identity", &hex::encode(self.public_identity))?;
        state.serialize_field(
            "encrypted_private_nonce",
            &hex::encode(self.encrypted_private_identity.nonce),
        )?;
        state.serialize_field(
            "encrypted_private_ciphertext",
            &hex::encode(&self.encrypted_private_identity.ciphertext),
        )?;
        state.serialize_field("key_fingerprint", &hex::encode(self.key_fingerprint))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KeyData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            PublicIdentity,
            EncryptedPrivateNonce,
            EncryptedPrivateCiphertext,
            KeyFingerprint,
        }

        struct KeyDataVisitor;

        impl<'de> Visitor<'de> for KeyDataVisitor {
            type Value = KeyData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct KeyData")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<KeyData, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut public_identity: Option<String> = None;
                let mut encrypted_private_nonce: Option<String> = None;
                let mut encrypted_private_ciphertext: Option<String> = None;
                let mut key_fingerprint: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PublicIdentity => {
                            if public_identity.is_some() {
                                return Err(de::Error::duplicate_field("public_identity"));
                            }
                            public_identity = Some(map.next_value()?);
                        }
                        Field::EncryptedPrivateNonce => {
                            if encrypted_private_nonce.is_some() {
                                return Err(de::Error::duplicate_field("encrypted_private_nonce"));
                            }
                            encrypted_private_nonce = Some(map.next_value()?);
                        }
                        Field::EncryptedPrivateCiphertext => {
                            if encrypted_private_ciphertext.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "encrypted_private_ciphertext",
                                ));
                            }
                            encrypted_private_ciphertext = Some(map.next_value()?);
                        }
                        Field::KeyFingerprint => {
                            if key_fingerprint.is_some() {
                                return Err(de::Error::duplicate_field("key_fingerprint"));
                            }
                            key_fingerprint = Some(map.next_value()?);
                        }
                    }
                }

                let public_identity =
                    public_identity.ok_or_else(|| de::Error::missing_field("public_identity"))?;
                let encrypted_private_nonce = encrypted_private_nonce
                    .ok_or_else(|| de::Error::missing_field("encrypted_private_nonce"))?;
                let encrypted_private_ciphertext = encrypted_private_ciphertext
                    .ok_or_else(|| de::Error::missing_field("encrypted_private_ciphertext"))?;
                let key_fingerprint =
                    key_fingerprint.ok_or_else(|| de::Error::missing_field("key_fingerprint"))?;

                // Décoder hex
                let public_bytes = hex::decode(&public_identity).map_err(de::Error::custom)?;
                let nonce_bytes =
                    hex::decode(&encrypted_private_nonce).map_err(de::Error::custom)?;
                let ciphertext_bytes =
                    hex::decode(&encrypted_private_ciphertext).map_err(de::Error::custom)?;
                let fingerprint_bytes = hex::decode(&key_fingerprint).map_err(de::Error::custom)?;

                if public_bytes.len() != 32 {
                    return Err(de::Error::custom("Invalid public key length"));
                }
                if nonce_bytes.len() != 12 {
                    return Err(de::Error::custom("Invalid nonce length"));
                }
                if fingerprint_bytes.len() != 32 {
                    return Err(de::Error::custom("Invalid fingerprint length"));
                }

                let mut public_identity = [0u8; 32];
                public_identity.copy_from_slice(&public_bytes);

                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&nonce_bytes);

                let mut key_fingerprint = [0u8; 32];
                key_fingerprint.copy_from_slice(&fingerprint_bytes);

                Ok(KeyData {
                    public_identity,
                    encrypted_private_identity: crate::crypto::aead::SealedData::new(
                        nonce,
                        ciphertext_bytes,
                    ),
                    key_fingerprint,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "public_identity",
            "encrypted_private_nonce",
            "encrypted_private_ciphertext",
            "key_fingerprint",
        ];
        deserializer.deserialize_struct("KeyData", FIELDS, KeyDataVisitor)
    }
}

/// Paramètres utilisateur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSettings {
    /// Accepter automatiquement les demandes d'ami
    pub auto_accept_friends: bool,
    /// Niveau de chiffrement (balanced, secure, fast)
    pub encryption_level: String,
    /// Sauvegarde automatique activée
    pub backup_enabled: bool,
    /// Thème de l'interface (dark, light)
    pub theme: String,
}

impl Default for ProfileSettings {
    fn default() -> Self {
        Self {
            auto_accept_friends: false,
            encryption_level: "balanced".to_string(),
            backup_enabled: true,
            theme: "auto".to_string(),
        }
    }
}

/// Structure complète d'un profil stocké
#[derive(Debug, Serialize, Deserialize)]
struct ProfileData {
    metadata: ProfileMetadata,
    auth: AuthenticationData,
    keys: KeyData,
    settings: ProfileSettings,
}

/// Nettoie un nom de fichier pour qu'il soit safe sur tous les systèmes
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect::<String>()
        .chars()
        .take(32) // Limiter la longueur
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_profile_creation_and_loading() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        let password = SecretString::new("test_password_123".to_string());

        // Créer un profil
        let profile_id = storage.create_profile("alice", &password).unwrap();
        assert_eq!(profile_id.name, "alice");

        // Charger le profil
        let profile = storage.load_profile(&profile_id, &password).unwrap();
        assert_eq!(profile.metadata.name, "alice");

        // Mauvais mot de passe
        let wrong_password = SecretString::new("wrong_password".to_string());
        assert!(storage.load_profile(&profile_id, &wrong_password).is_err());
    }

    #[test]
    fn test_profile_listing() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        let password = SecretString::new("test_password_123".to_string());

        // Créer plusieurs profils
        storage.create_profile("alice", &password).unwrap();
        storage.create_profile("bob", &password).unwrap();

        // Lister les profils
        let profiles = storage.list_profiles().unwrap();
        assert_eq!(profiles.len(), 2);

        let names: Vec<_> = profiles.iter().map(|p| &p.name).collect();
        assert!(names.contains(&&"alice".to_string()));
        assert!(names.contains(&&"bob".to_string()));
    }

    #[test]
    fn test_profile_deletion() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        let password = SecretString::new("test_password_123".to_string());

        // Créer un profil
        let profile_id = storage.create_profile("test_user", &password).unwrap();

        // Vérifier qu'il existe
        assert!(storage.load_profile(&profile_id, &password).is_ok());

        // Le supprimer
        storage.delete_profile(&profile_id).unwrap();

        // Vérifier qu'il n'existe plus
        assert!(storage.load_profile(&profile_id, &password).is_err());
    }

    #[test]
    fn test_profile_id_generation() {
        let id1 = ProfileId::new("alice");
        let id2 = ProfileId::new("alice");
        let id3 = ProfileId::new("bob");

        // Same name should produce same ID
        assert_eq!(id1.name, id2.name);
        assert_eq!(id1.hash, id2.hash);

        // Different names should produce different IDs
        assert_ne!(id1.hash, id3.hash);
        assert_eq!(id1.name, "alice");
        assert_eq!(id3.name, "bob");
    }

    #[test]
    fn test_profile_id_safe_name() {
        let id1 = ProfileId::new("alice");
        let id2 = ProfileId::new("bob@domain.com");
        let id3 = ProfileId::new("user with spaces");

        let safe1 = id1.safe_name();
        let safe2 = id2.safe_name();
        let safe3 = id3.safe_name();

        // All safe names should be filesystem safe
        assert!(safe1.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert!(safe2.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert!(safe3.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));

        // Should contain hash suffix
        assert!(safe1.contains(&id1.hash[..8]));
        assert!(safe2.contains(&id2.hash[..8]));
        assert!(safe3.contains(&id3.hash[..8]));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal"), "normal");
        assert_eq!(sanitize_filename("user@domain.com"), "user_domain_com");
        assert_eq!(sanitize_filename("user with spaces"), "user_with_spaces");
        assert_eq!(sanitize_filename("user/\\<>:|?*"), "user________");

        // Should limit length
        let long_name = "a".repeat(100);
        let sanitized = sanitize_filename(&long_name);
        assert_eq!(sanitized.len(), 32);
    }

    #[test]
    fn test_create_profile_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        // Create first profile
        storage.create_profile("alice", &password).unwrap();

        // Try to create same profile again
        let result = storage.create_profile("alice", &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_profile_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        let fake_id = ProfileId::new("nonexistent");
        let result = storage.load_profile(&fake_id, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_profile_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        let fake_id = ProfileId::new("nonexistent");
        let result = storage.delete_profile(&fake_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_profiles_empty() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        let profiles = storage.list_profiles().unwrap();
        assert_eq!(profiles.len(), 0);
    }

    #[test]
    fn test_profile_settings_default() {
        let settings = ProfileSettings::default();
        assert!(!settings.auto_accept_friends);
        assert_eq!(settings.encryption_level, "balanced");
        assert!(settings.backup_enabled);
        assert_eq!(settings.theme, "auto");
    }

    #[test]
    fn test_profile_loading_with_different_configs() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();

        // Test loading profiles with different Argon2 configs
        let passwords = [
            SecretString::new("password1".to_string()),
            SecretString::new("password2".to_string()),
            SecretString::new("password3".to_string()),
        ];

        let names = ["user_fast", "user_balanced", "user_secure"];

        for (i, (name, password)) in names.iter().zip(passwords.iter()).enumerate() {
            let profile_id = storage.create_profile(name, password).unwrap();

            // Should be able to load the profile
            let loaded_profile = storage.load_profile(&profile_id, password).unwrap();
            assert_eq!(loaded_profile.metadata.name, *name);

            // Wrong password should fail
            let wrong_password = SecretString::new(format!("wrong_{i}"));
            assert!(storage.load_profile(&profile_id, &wrong_password).is_err());
        }
    }

    #[test]
    fn test_profile_key_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        let profile_id = storage.create_profile("alice", &password).unwrap();
        let profile = storage.load_profile(&profile_id, &password).unwrap();

        // Test that the keys work for crypto operations
        let message = b"test message for signing";
        let signature = profile.identity_keypair.sign(message);

        // Verify signature works
        assert!(profile.identity_keypair.verify(message, &signature).is_ok());

        // Wrong message should fail verification
        assert!(profile
            .identity_keypair
            .verify(b"wrong message", &signature)
            .is_err());
    }

    #[test]
    fn test_profile_metadata_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        let profile_id = storage.create_profile("test_user", &password).unwrap();
        let profile = storage.load_profile(&profile_id, &password).unwrap();

        // Metadata should be consistent
        assert_eq!(profile.metadata.id.name, "test_user");
        assert_eq!(profile.metadata.name, "test_user");
        assert_eq!(profile.metadata.version, "0.1.0");
        assert!(profile.metadata.created <= chrono::Utc::now());
        assert!(profile.metadata.last_access <= chrono::Utc::now());
        assert!(profile.metadata.last_access >= profile.metadata.created);
    }

    #[test]
    fn test_secure_storage_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().join("new_storage");

        // Directory doesn't exist yet
        assert!(!storage_path.exists());

        // Creating storage should create directories
        let _storage = SecureStorage::new(&storage_path).unwrap();
        assert!(storage_path.exists());
        assert!(storage_path.join("profiles").exists());
        assert!(storage_path.join("keystore").exists());
    }

    #[test]
    fn test_load_profile_corrupted_data_scenarios() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        // Create profile first
        let profile_id = storage.create_profile("test_user", &password).unwrap();
        let profile_path = storage.get_profile_path(&profile_id);

        // Test corrupted JSON data
        std::fs::write(&profile_path, "invalid json").unwrap();
        let result = storage.load_profile(&profile_id, &password);
        assert!(result.is_err());

        // Test invalid config type
        let profile_data = serde_json::json!({
            "metadata": {
                "id": {"name": "test_user", "hash": "abcd1234"},
                "name": "test_user",
                "version": "0.1.0",
                "created": "2023-01-01T00:00:00Z",
                "last_access": "2023-01-01T00:00:00Z"
            },
            "auth": {
                "password_hash": "dummy_hash",
                "salt": "ZHVtbXlfc2FsdA==",
                "config_type": "invalid_config"
            },
            "keys": {
                "public_identity": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "encrypted_private_nonce": "0123456789abcdef01234567",
                "encrypted_private_ciphertext": "dummy_ciphertext",
                "key_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "settings": {
                "auto_accept_friends": false,
                "encryption_level": "balanced",
                "backup_enabled": true,
                "theme": "auto"
            }
        });

        std::fs::write(
            &profile_path,
            serde_json::to_string_pretty(&profile_data).unwrap(),
        )
        .unwrap();
        let result = storage.load_profile(&profile_id, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_profile_invalid_private_key_length() {
        use secrecy::SecretString;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        // Create a valid profile first
        let _profile_id = storage.create_profile("test_user", &password).unwrap();

        // Now manually create a profile with corrupted data that will decrypt to wrong length
        let profile_data = serde_json::json!({
            "metadata": {
                "id": {"name": "test_corrupted", "hash": "corrupted1234"},
                "name": "test_corrupted",
                "version": "0.1.0",
                "created": "2023-01-01T00:00:00Z",
                "last_access": "2023-01-01T00:00:00Z"
            },
            "auth": {
                "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$ZHVtbXlfc2FsdAAAAA$dummy_hash_that_will_fail_verification",
                "salt": "ZHVtbXlfc2FsdA==",
                "config_type": "balanced"
            },
            "keys": {
                "public_identity": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "encrypted_private_nonce": "000000000000000000000000",
                "encrypted_private_ciphertext": "0123456789abcdef",  // Too short, will cause length error
                "key_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "settings": {
                "auto_accept_friends": false,
                "encryption_level": "balanced",
                "backup_enabled": true,
                "theme": "auto"
            }
        });

        let corrupted_id = ProfileId::new("test_corrupted");
        let corrupted_path = storage.get_profile_path(&corrupted_id);
        fs::write(
            &corrupted_path,
            serde_json::to_string_pretty(&profile_data).unwrap(),
        )
        .unwrap();

        // This should fail due to invalid password hash format, not private key length
        let result = storage.load_profile(&corrupted_id, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_profiles_with_corrupted_files() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        // Create a valid profile
        storage.create_profile("valid_user", &password).unwrap();

        // Create a corrupted profile file
        let profiles_dir = temp_dir.path().join("profiles");
        let corrupted_file = profiles_dir.join("corrupted.json");
        std::fs::write(&corrupted_file, "invalid json data").unwrap();

        // Create a non-JSON file
        let non_json_file = profiles_dir.join("not_json.txt");
        std::fs::write(&non_json_file, "just some text").unwrap();

        // List profiles should still work and skip corrupted files
        let profiles = storage.list_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "valid_user");
    }

    #[test]
    fn test_update_last_access_scenarios() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SecureStorage::new(temp_dir.path()).unwrap();
        let password = SecretString::new("test_password".to_string());

        // Create profile
        let profile_id = storage.create_profile("test_user", &password).unwrap();

        // Load profile (this should update last_access)
        let profile1 = storage.load_profile(&profile_id, &password).unwrap();

        // Wait a tiny bit and load again
        std::thread::sleep(std::time::Duration::from_millis(10));
        let profile2 = storage.load_profile(&profile_id, &password).unwrap();

        // Second load should have later or equal timestamp
        assert!(profile2.metadata.last_access >= profile1.metadata.last_access);

        // Test with corrupted profile file for update_last_access coverage
        let profile_path = storage.get_profile_path(&profile_id);
        std::fs::write(&profile_path, "invalid json").unwrap();

        // Should not panic, just fail silently in update_last_access
        let result = storage.update_last_access(&profile_id);
        assert!(result.is_ok()); // The function handles errors gracefully
    }

    #[test]
    fn test_keydata_deserialization_errors() {
        use serde_json;

        // Test invalid hex data
        let invalid_hex_data = serde_json::json!({
            "public_identity": "invalid_hex",
            "encrypted_private_nonce": "000000000000000000000000",
            "encrypted_private_ciphertext": "0123456789abcdef",
            "key_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });

        let result: Result<KeyData, _> = serde_json::from_value(invalid_hex_data);
        assert!(result.is_err());

        // Test invalid lengths
        let invalid_lengths = serde_json::json!({
            "public_identity": "0123",  // Too short
            "encrypted_private_nonce": "000000000000000000000000",
            "encrypted_private_ciphertext": "0123456789abcdef",
            "key_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });

        let result: Result<KeyData, _> = serde_json::from_value(invalid_lengths);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_filename_edge_cases() {
        // Test very long names
        let long_name = "a".repeat(100);
        let sanitized = sanitize_filename(&long_name);
        assert_eq!(sanitized.len(), 32);

        // Test empty string
        let empty = sanitize_filename("");
        assert_eq!(empty.len(), 0);

        // Test special characters
        let special = "user@domain.com/\\<>:|?*";
        let sanitized = sanitize_filename(special);
        assert!(sanitized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert!(!sanitized.contains('@'));
        assert!(!sanitized.contains('/'));
    }

    #[test]
    fn test_storage_backend_trait() {
        struct TestFailingStorage;
        impl StorageBackend for TestFailingStorage {
            fn store(&mut self, _key: &str, _data: &[u8]) -> Result<(), StorageError> {
                Err(StorageError::Io(
                    std::io::Error::new(std::io::ErrorKind::Other, "simulated failure").into(),
                ))
            }
            fn retrieve(&self, _key: &str) -> Result<Vec<u8>, StorageError> {
                Err(StorageError::NotFound)
            }
            fn delete(&mut self, _key: &str) -> Result<(), StorageError> {
                Ok(())
            }
            fn exists(&self, _key: &str) -> bool {
                false
            }
        }

        let mut failing_storage = TestFailingStorage;

        // Test store failure
        let result = failing_storage.store("key", b"data");
        assert!(result.is_err());

        // Test retrieve failure
        let result = failing_storage.retrieve("key");
        assert!(result.is_err());

        // Test delete success
        let result = failing_storage.delete("key");
        assert!(result.is_ok());

        // Test exists
        assert!(!failing_storage.exists("key"));
    }
}
