//! # Miaou Core v0.1.0
//!
//! Fonctionnalités principales et abstractions pour la plateforme Miaou.
//! 
//! Ce crate contient la logique métier centrale, la gestion des profils
//! et les abstractions communes utilisées par tous les autres composants.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

// Re-export crypto primitives
pub use miaou_crypto as crypto;

pub mod storage;
pub mod mobile;

// Re-exports publics
pub use storage::{SecureStorage, ProfileId, ProfileHandle};

/// Version actuelle de Miaou
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Nom de la version actuelle
pub const VERSION_NAME: &str = "Première Griffe";

/// Phase de développement actuelle
pub const DEVELOPMENT_PHASE: u8 = 1;

/// Interface commune pour toutes les plateformes
pub trait PlatformInterface {
    /// Initialise la plateforme
    fn initialize(&mut self) -> Result<(), String>;
    
    /// Retourne le nom de la plateforme
    fn get_platform_name(&self) -> &'static str;
    
    /// Retourne la version supportée
    fn get_supported_version(&self) -> &'static str {
        VERSION
    }
}

/// Informations sur la version et compilation
pub fn version_info() -> String {
    format!(
        "Miaou v{} \"{}\" (Phase {})",
        VERSION,
        VERSION_NAME,
        DEVELOPMENT_PHASE
    )
}

/// Fonction principale d'initialisation de Miaou
pub fn initialize() -> Result<(), String> {
    // Vérification des dépendances cryptographiques
    crypto::test_crypto_availability()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(info.contains("Miaou"));
        assert!(info.contains("Première Griffe"));
        assert!(info.contains("Phase 1"));
    }

    #[test]
    fn test_initialize() {
        assert!(initialize().is_ok());
    }

    #[test]
    fn test_constants() {
        assert_eq!(VERSION_NAME, "Première Griffe");
        assert_eq!(DEVELOPMENT_PHASE, 1);
        #[allow(clippy::const_is_empty)]
        {
            assert!(!VERSION.is_empty());
        }
    }
}