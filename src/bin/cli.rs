// CLI binary pour Miaou
// Point d'entrée principal pour l'application de ligne de commande

use miaou::version_info;

fn main() {
    println!("{}", version_info());
    println!("CLI {}", env!("CARGO_PKG_VERSION"));
    
    match miaou::initialize() {
        Ok(()) => println!("✅ Miaou initialisé avec succès"),
        Err(e) => println!("❌ Erreur d'initialisation: {}", e),
    }
    
    #[cfg(target_os = "android")]
    println!("📱 Support Android activé");
    
    #[cfg(target_os = "ios")]
    println!("📱 Support iOS activé");
    
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    println!("🖥️  Version desktop");
}