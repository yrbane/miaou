// Bibliothèque principale Miaou
// Point d'entrée pour la logique métier partagée entre toutes les plateformes

pub mod core;
pub mod mobile;

pub fn hello_miaou() -> String {
    "Miaou - Communication décentralisée".to_string()
}

// Interface commune pour toutes les plateformes
pub trait PlatformInterface {
    fn initialize(&mut self) -> Result<(), String>;
    fn get_platform_name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_miaou() {
        assert_eq!(hello_miaou(), "Miaou - Communication décentralisée");
    }
}