// CLI binary pour Miaou
// Point d'entrée principal pour l'application de ligne de commande

use miaou::hello_miaou;

fn main() {
    println!("{}", hello_miaou());
    println!("CLI Miaou v{}", env!("CARGO_PKG_VERSION"));
    
    #[cfg(target_os = "android")]
    println!("Support Android activé");
    
    #[cfg(target_os = "ios")]
    println!("Support iOS activé");
    
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    println!("Version desktop");
}