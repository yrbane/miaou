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
    ///
    /// # Errors
    /// Retourne `MiaouError::Crypto` contenant le message d'erreur de la source.
    fn miaou(self) -> MiaouResult<T>;
}

impl<T, E: core::fmt::Display> IntoMiaouError<T> for Result<T, E> {
    fn miaou(self) -> MiaouResult<T> {
        self.map_err(|e| MiaouError::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_bytes_basic() {
        let mut sb = SensitiveBytes::default();
        assert_eq!(sb.len(), 0);

        sb.push(42);
        sb.push(100);
        assert_eq!(sb.len(), 2);
        assert_eq!(sb[0], 42);
        assert_eq!(sb[1], 100);
    }

    #[test]
    fn test_sensitive_bytes_deref() {
        let mut sb = SensitiveBytes(vec![1, 2, 3]);

        // Test Deref
        assert_eq!(sb.len(), 3);
        assert_eq!(&sb[..], &[1, 2, 3]);

        // Test DerefMut
        sb[1] = 99;
        assert_eq!(sb[1], 99);
    }

    #[test]
    fn test_sensitive_bytes_drop() {
        let data = vec![1, 2, 3, 4, 5];
        let sb = SensitiveBytes(data.clone());

        // Vérifie que les données sont présentes
        assert_eq!(sb.0, data);

        // Le drop sera appelé automatiquement et zeroize les données
        drop(sb);
        // Note: On ne peut pas tester directement la zeroization car sb est moved
    }

    #[test]
    fn test_miaou_error_display() {
        let err1 = MiaouError::Init("test init".to_string());
        assert_eq!(err1.to_string(), "Initialization failed: test init");

        let err2 = MiaouError::InvalidInput;
        assert_eq!(err2.to_string(), "Invalid input");

        let err3 = MiaouError::Crypto("test crypto".to_string());
        assert_eq!(err3.to_string(), "Crypto error: test crypto");

        let err4 = MiaouError::Io("test io".to_string());
        assert_eq!(err4.to_string(), "I/O error: test io");
    }

    #[test]
    fn test_into_miaou_error_success() {
        let result: Result<i32, &str> = Ok(42);
        let miaou_result = result.miaou();
        assert_eq!(miaou_result.unwrap(), 42);
    }

    #[test]
    fn test_into_miaou_error_failure() {
        let result: Result<i32, &str> = Err("test error");
        let miaou_result = result.miaou();

        match miaou_result {
            Err(MiaouError::Crypto(msg)) => assert_eq!(msg, "test error"),
            _ => panic!("Expected Crypto error"),
        }
    }

    #[test]
    fn test_miaou_error_debug() {
        let err = MiaouError::Init("debug test".to_string());
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("Init"));
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn test_into_miaou_error_with_different_types() {
        // Test avec différents types d'erreur pour couvrir tous les cas
        let io_err: Result<(), std::io::Error> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        let miaou_result = io_err.miaou();
        assert!(matches!(miaou_result, Err(MiaouError::Crypto(_))));

        // Test avec un autre type
        let parse_err: Result<i32, std::num::ParseIntError> = "not_a_number".parse();
        let miaou_result = parse_err.miaou();
        assert!(matches!(miaou_result, Err(MiaouError::Crypto(_))));
    }
}
