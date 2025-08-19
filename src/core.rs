// Module core - Logique métier commune
// Fonctionnalités partagées entre toutes les plateformes

pub struct MiaouCore {
    pub version: String,
    pub initialized: bool,
}

impl MiaouCore {
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            initialized: false,
        }
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        // Initialisation commune à toutes les plateformes
        self.initialized = true;
        Ok(())
    }

    pub fn get_version(&self) -> &str {
        &self.version
    }
}

impl Default for MiaouCore {
    fn default() -> Self {
        Self::new()
    }
}