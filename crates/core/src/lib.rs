#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # Coeur du projet Miaou — Types communs et erreurs
//!
//! **Documentation (FR)** : Ce crate fournit les erreurs typées, les alias de types sensibles,
//! et quelques traits utilitaires communs aux autres crates. Aucun secret n'est loggé via
//! `Display`/`Debug`. Les valeurs sensibles utilisent `zeroize`.

use thiserror::Error;
use zeroize::Zeroize;

/// Bytes container that zeroizes its content on drop.
///
/// *Code in English; doc in French.*
#[derive(Debug, Default)]
pub struct SensitiveBytes(pub Vec<u8>);

impl core::ops::Deref for SensitiveBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for SensitiveBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Erreur commune du projet Miaou.
#[derive(Debug, Error)]
pub enum MiaouError {
    /// Erreur d'initialisation.
    #[error("Initialization failed: {0}")]
    Init(String),
    /// Entrée invalide (domaine).
    #[error("Invalid input")]
    InvalidInput,
    /// Erreur cryptographique encapsulée (message non-sensible).
    #[error("Crypto error: {0}")]
    Crypto(String),
    /// Erreur d'E/S (fichiers, etc.).
    #[error("I/O error: {0}")]
    Io(String),
}

/// Résultat standardisé du projet Miaou.
pub type MiaouResult<T> = Result<T, MiaouError>;

/// Trait utilitaire pour normaliser les conversions d'erreur externes.
pub trait IntoMiaouError<T> {
    /// Convertit une erreur en `MiaouError` avec message non-sensible.
    fn miaou(self) -> MiaouResult<T>;
}

impl<T, E: core::fmt::Display> IntoMiaouError<T> for Result<T, E> {
    fn miaou(self) -> MiaouResult<T> {
        self.map_err(|e| MiaouError::Crypto(e.to_string()))
    }
}
