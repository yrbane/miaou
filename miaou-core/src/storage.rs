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
use chrono::{DateTime, Utc};
use secrecy::{SecretString, Zeroize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::path::{Path, PathBuf};

/// Erreurs de stockage
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Erreur d'E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("Erreur de sérialisation: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Erreur cryptographique: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Profil non trouvé: {0}")]
    ProfileNotFound(String),

    #[error("Profil déjà existant: {0}")]
    ProfileAlreadyExists(String),

    #[error("Mot de passe invalide")]
    InvalidPassword,

    #[error("Données corrompues ou version incompatible")]
    CorruptedData,
}

/// Gestionnaire de stockage sécurisé
pub struct SecureStorage {
    /// Répertoire racine de stockage
    storage_root: PathBuf,
}

impl SecureStorage {
    /// Crée une nouvelle instance de stockage
    pub fn new<P: AsRef<Path>>(storage_root: P) -> Result<Self> {
        let storage_root = storage_root.as_ref().to_path_buf();

        // Créer les répertoires nécessaires
        fs::create_dir_all(&storage_root)?;
        fs::create_dir_all(storage_root.join("profiles"))?;
        fs::create_dir_all(storage_root.join("keystore"))?;

        Ok(Self { storage_root })
    }

    /// Crée un nouveau profil utilisateur
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
    pub name: String,
    pub hash: String, // Hash du nom pour éviter les collisions
}

impl ProfileId {
    pub fn new(name: &str) -> Self {
        let hash = hex::encode(blake3_32(name.as_bytes()));
        Self {
            name: name.to_string(),
            hash,
        }
    }

    pub fn safe_name(&self) -> String {
        format!("{}_{}", sanitize_filename(&self.name), &self.hash[..8])
    }
}

/// Informations publiques sur un profil
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub id: ProfileId,
    pub name: String,
    pub created: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
    pub public_key_fingerprint: String,
}

/// Handle vers un profil chargé en mémoire
pub struct ProfileHandle {
    pub metadata: ProfileMetadata,
    pub identity_keypair: Keypair,
    pub settings: ProfileSettings,
}

/// Métadonnées d'un profil
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub id: ProfileId,
    pub name: String,
    pub version: String,
    pub created: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
}

/// Données d'authentification
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationData {
    pub password_hash: String,
    pub salt: String,
    pub config_type: String,
}

/// Données cryptographiques
#[derive(Debug)]
pub struct KeyData {
    pub public_identity: [u8; 32],
    pub encrypted_private_identity: crate::crypto::aead::SealedData,
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
    pub auto_accept_friends: bool,
    pub encryption_level: String,
    pub backup_enabled: bool,
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
}
