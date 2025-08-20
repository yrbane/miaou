// Module core - Logique métier commune
// Fonctionnalités partagées entre toutes les plateformes

/// Noyau central de l'application Miaou
pub struct MiaouCore {
    /// Version actuelle de Miaou
    pub version: String,
    /// État d'initialisation
    pub initialized: bool,
}

impl MiaouCore {
    /// Crée une nouvelle instance du noyau
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            initialized: false,
        }
    }

    /// Initialise le noyau Miaou
    pub fn initialize(&mut self) -> Result<(), String> {
        // Initialisation commune à toutes les plateformes
        self.initialized = true;
        Ok(())
    }

    /// Retourne la version actuelle
    pub fn get_version(&self) -> &str {
        &self.version
    }
}

impl Default for MiaouCore {
    fn default() -> Self {
        Self::new()
    }
}