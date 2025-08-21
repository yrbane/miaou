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
}
