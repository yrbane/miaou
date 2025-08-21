#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # Keyring Miaou (MVP)
//!
//! **Documentation (FR)** : Ce crate gère un keyring minimal en mémoire pour Phase 1. Les
//! secrets sont détenus en mémoire et effacés à la destruction (`zeroize`). Une API simple
//! expose la génération de clés, l'export de clé publique et la signature Ed25519. Le stockage
//! disque chiffré est laissé pour Phase 1+ (TODO), mais l'interface `KeyStore` permet d'ajouter
//! des backends sans modifier les consommateurs (OCP/DIP).

use miaou_core::{MiaouError, MiaouResult};
use miaou_crypto::{Ed25519Signer, Signer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Identifiant logique de clé.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// Entrée de keyring (clé privée en mémoire sensible).
#[derive(Serialize, Deserialize)]
struct KeyEntry {
    #[serde(with = "serde_bytes")]
    sk: Vec<u8>,
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

/// API de key store minimal.
pub trait KeyStore {
    /// Génère et enregistre une nouvelle clé Ed25519, renvoie son `KeyId`.
    fn generate_ed25519(&mut self) -> MiaouResult<KeyId>;
    /// Exporte la clé publique binaire.
    fn export_public(&self, id: &KeyId) -> MiaouResult<Vec<u8>>;
    /// Signe un message arbitraire avec la clé désignée.
    fn sign(&self, id: &KeyId, msg: &[u8]) -> MiaouResult<Vec<u8>>;
}

/// Implémentation en mémoire (non persistante).
#[derive(Default)]
pub struct MemoryKeyStore {
    pub(crate) map: HashMap<KeyId, KeyEntry>,
}

impl MemoryKeyStore {
    /// Construit un key store vide.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        KeyId(s)
    }
}
impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        KeyId(s.to_string())
    }
}

impl KeyStore for MemoryKeyStore {
    fn generate_ed25519(&mut self) -> MiaouResult<KeyId> {
        let signer = Ed25519Signer::generate();
        let id = KeyId(hex(&signer.public_key()[..8]));
        let sk = signer.secret_key_bytes().to_vec();
        self.map.insert(id.clone(), KeyEntry { sk });
        Ok(id)
    }

    fn export_public(&self, id: &KeyId) -> MiaouResult<Vec<u8>> {
        let Some(entry) = self.map.get(id) else {
            return Err(MiaouError::InvalidInput);
        };
        let signer = Ed25519Signer::from_secret_key_bytes(&entry.sk)?;
        Ok(signer.public_key())
    }

    fn sign(&self, id: &KeyId, msg: &[u8]) -> MiaouResult<Vec<u8>> {
        let Some(entry) = self.map.get(id) else {
            return Err(MiaouError::InvalidInput);
        };
        let signer = Ed25519Signer::from_secret_key_bytes(&entry.sk)?;
        signer.sign(msg)
    }
}

/// Encodage hex minimal (pour un `KeyId` lisible) — sans secrets.
fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_keystore_lifecycle() {
        let mut ks = MemoryKeyStore::new();
        let id = ks.generate_ed25519().unwrap();
        let pk = ks.export_public(&id).unwrap();
        let sig = ks.sign(&id, b"miaou").unwrap();
        // Vérification hors API (Ed25519Signer) pour l'exemple
        let signer =
            miaou_crypto::Ed25519Signer::from_secret_key_bytes(&ks.map.get(&id).unwrap().sk)
                .unwrap();
        assert!(signer.verify(b"miaou", &sig).unwrap());
        assert_eq!(pk, signer.public_key());
    }

    #[test]
    fn test_key_id_from_string() {
        let id1 = KeyId::from("test-key".to_string());
        let id2 = KeyId::from("test-key");
        assert_eq!(id1, id2);
        assert_eq!(id1.0, "test-key");
        assert_eq!(id2.0, "test-key");
    }

    #[test]
    fn test_export_public_invalid_key() {
        let ks = MemoryKeyStore::new();
        let invalid_id = KeyId::from("nonexistent");
        let result = ks.export_public(&invalid_id);
        assert!(matches!(result, Err(MiaouError::InvalidInput)));
    }

    #[test]
    fn test_sign_invalid_key() {
        let ks = MemoryKeyStore::new();
        let invalid_id = KeyId::from("nonexistent");
        let result = ks.sign(&invalid_id, b"message");
        assert!(matches!(result, Err(MiaouError::InvalidInput)));
    }

    #[test]
    fn test_memory_keystore_default() {
        let ks1 = MemoryKeyStore::new();
        let ks2 = MemoryKeyStore::default();
        assert_eq!(ks1.map.len(), 0);
        assert_eq!(ks2.map.len(), 0);
    }

    #[test]
    fn test_key_id_debug_and_clone() {
        let id = KeyId::from("test-debug");
        let cloned = id.clone();
        assert_eq!(id, cloned);

        let debug_str = format!("{:?}", id);
        assert!(debug_str.contains("test-debug"));
    }

    #[test]
    fn test_hex_function() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0]), "00");
        assert_eq!(hex(&[255]), "ff");
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert_eq!(hex(&[0x12, 0x34, 0xab, 0xcd]), "1234abcd");
    }

    #[test]
    fn test_key_entry_drop() {
        let entry = KeyEntry {
            sk: vec![1, 2, 3, 4, 5],
        };
        // Le drop sera appelé automatiquement et zeroize les données
        drop(entry);
        // Note: On ne peut pas tester directement la zeroization car entry est moved
    }

    #[test]
    fn test_multiple_keys() {
        let mut ks = MemoryKeyStore::new();

        // Génère plusieurs clés
        let id1 = ks.generate_ed25519().unwrap();
        let id2 = ks.generate_ed25519().unwrap();

        // Vérifie qu'elles sont différentes
        assert_ne!(id1, id2);

        // Vérifie que chaque clé fonctionne
        let pk1 = ks.export_public(&id1).unwrap();
        let pk2 = ks.export_public(&id2).unwrap();
        assert_ne!(pk1, pk2);

        let sig1 = ks.sign(&id1, b"message1").unwrap();
        let sig2 = ks.sign(&id2, b"message2").unwrap();
        assert_ne!(sig1, sig2);
    }
}
