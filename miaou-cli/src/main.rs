// CLI interactif pour Miaou v0.1.0 avec stockage sécurisé
// Interface de ligne de commande avec gestion des profils et tests crypto

use std::io::{self, Write};
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use secrecy::{SecretString, ExposeSecret};
use miaou_core::{
    version_info, initialize,
    crypto::{
        aead::{AeadKeyRef, encrypt_auto_nonce, decrypt},
        sign::Keypair,
        kdf::{Argon2Config, hash_password, verify_password},
        hash::blake3_32,
    },
    storage::{SecureStorage, ProfileId},
};

#[derive(Parser)]
#[command(name = "miaou-cli")]
#[command(about = "Interface de ligne de commande pour Miaou v0.1.0")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Répertoire de données Miaou
    #[arg(long, default_value = "~/.miaou")]
    data_dir: PathBuf,
    
    /// Mode verbeux
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Informations sur la version et l'état
    Status,
    
    /// Tests des primitives cryptographiques
    CryptoTest,
    
    /// Gestion des profils utilisateur
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    
    /// Tests interactifs de chiffrement
    TestEncrypt {
        /// Message à chiffrer
        #[arg(short, long)]
        message: Option<String>,
    },
    
    /// Tests interactifs de signature
    TestSign {
        /// Message à signer
        #[arg(short, long)]
        message: Option<String>,
    },
    
    /// Benchmarks de performance
    Benchmark,
    
    /// Mode interactif (par défaut)
    Interactive,
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Créer un nouveau profil
    Create {
        /// Nom du profil
        name: String,
    },
    /// Lister les profils existants
    List,
    /// Supprimer un profil
    Delete {
        /// Nom du profil
        name: String,
    },
    /// Afficher les détails d'un profil
    Show {
        /// Nom du profil
        name: String,
    },
}

struct MiaouCli {
    data_dir: PathBuf,
    verbose: bool,
    storage: SecureStorage,
}

impl MiaouCli {
    fn new(data_dir: PathBuf, verbose: bool) -> Result<Self> {
        // Créer le répertoire de données si nécessaire
        let data_dir = expand_path(data_dir)?;
        std::fs::create_dir_all(&data_dir)
            .context("Impossible de créer le répertoire de données")?;
        
        // Initialiser le système de stockage sécurisé
        let storage = SecureStorage::new(&data_dir)?;
        
        Ok(Self { data_dir, verbose, storage })
    }
    
    fn run_command(&self, command: Commands) -> Result<()> {
        match command {
            Commands::Status => self.show_status(),
            Commands::CryptoTest => self.run_crypto_tests(),
            Commands::Profile { action } => self.handle_profile(action),
            Commands::TestEncrypt { message } => self.test_encryption(message),
            Commands::TestSign { message } => self.test_signing(message),
            Commands::Benchmark => self.run_benchmarks(),
            Commands::Interactive => self.interactive_mode(),
        }
    }
    
    fn show_status(&self) -> Result<()> {
        println!("🐱 {}", version_info());
        println!();
        
        // Test d'initialisation
        match initialize() {
            Ok(()) => {
                println!("✅ Système cryptographique: OK");
                println!("✅ Modules chargés: OK");
            }
            Err(e) => {
                println!("❌ Erreur d'initialisation: {}", e);
                return Ok(());
            }
        }
        
        // Informations sur le répertoire de données
        println!("📁 Répertoire de données: {}", self.data_dir.display());
        println!("📊 Espace disque: {}", get_disk_space(&self.data_dir)?);
        
        // Informations sur les profils
        let profiles = self.storage.list_profiles()?;
        println!("👤 Profils configurés: {}", profiles.len());
        
        // Informations système
        println!();
        println!("🖥️  Plateforme: {}", std::env::consts::OS);
        println!("🏗️  Architecture: {}", std::env::consts::ARCH);
        
        #[cfg(target_os = "android")]
        println!("📱 Support Android: activé");
        #[cfg(target_os = "ios")]  
        println!("📱 Support iOS: activé");
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        println!("🖥️  Version desktop");
        
        Ok(())
    }
    
    fn run_crypto_tests(&self) -> Result<()> {
        println!("🧪 Tests des primitives cryptographiques Miaou v0.1.0");
        println!();
        
        // Test AEAD (ChaCha20-Poly1305)
        print!("🔒 Test AEAD ChaCha20-Poly1305... ");
        io::stdout().flush()?;
        
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let plaintext = b"Message secret pour test AEAD";
        let aad = b"miaou_v0.1.0_test";
        let mut rng = rand_core::OsRng;
        
        let encrypted = encrypt_auto_nonce(&key, aad, plaintext, &mut rng)
            .context("Échec du chiffrement AEAD")?;
        let decrypted = decrypt(&key, aad, &encrypted)
            .context("Échec du déchiffrement AEAD")?;
        
        if &decrypted == plaintext {
            println!("✅ OK");
        } else {
            println!("❌ ÉCHEC");
            return Err(anyhow::anyhow!("Les données déchiffrées ne correspondent pas"));
        }
        
        // Test signatures Ed25519
        print!("✍️  Test signatures Ed25519... ");
        io::stdout().flush()?;
        
        let keypair = Keypair::generate();
        let message = b"Message a signer pour test Ed25519";
        
        let signature = keypair.sign(message);
        match keypair.verify(message, &signature) {
            Ok(()) => println!("✅ OK"),
            Err(_) => {
                println!("❌ ÉCHEC");
                return Err(anyhow::anyhow!("Échec de vérification de signature"));
            }
        }
        
        // Test hachage BLAKE3
        print!("#️⃣  Test hachage BLAKE3... ");
        io::stdout().flush()?;
        
        let data = "Données test pour hachage BLAKE3".as_bytes();
        let hash1 = blake3_32(data);
        let hash2 = blake3_32(data);
        
        if hash1 == hash2 {
            println!("✅ OK ({})", hex::encode(&hash1[..8]));
        } else {
            println!("❌ ÉCHEC");
            return Err(anyhow::anyhow!("Hashes BLAKE3 inconsistants"));
        }
        
        // Test Argon2 KDF
        print!("🔑 Test dérivation Argon2id... ");
        io::stdout().flush()?;
        
        let password = SecretString::new("mot_de_passe_test".to_string());
        let config = Argon2Config::fast_insecure(); // Rapide pour tests CLI
        
        let hash = hash_password(&password, &config)
            .context("Échec du hachage Argon2")?;
        let valid = verify_password(&password, &hash)
            .context("Échec de vérification Argon2")?;
        
        if valid {
            println!("✅ OK");
        } else {
            println!("❌ ÉCHEC");
            return Err(anyhow::anyhow!("Vérification Argon2 échouée"));
        }
        
        println!();
        println!("🎉 Tous les tests cryptographiques sont passés avec succès !");
        
        Ok(())
    }
    
    fn handle_profile(&self, action: ProfileAction) -> Result<()> {
        match action {
            ProfileAction::Create { name } => self.create_profile(name),
            ProfileAction::List => self.list_profiles_cmd(),
            ProfileAction::Delete { name } => self.delete_profile(name),
            ProfileAction::Show { name } => self.show_profile(name),
        }
    }
    
    fn create_profile(&self, name: String) -> Result<()> {
        println!("🆕 Création du profil '{}'", name);
        
        // Demander le mot de passe
        let password = prompt_password("Mot de passe du profil: ")?;
        let password_confirm = prompt_password("Confirmer le mot de passe: ")?;
        
        if password.expose_secret() != password_confirm.expose_secret() {
            return Err(anyhow::anyhow!("Les mots de passe ne correspondent pas"));
        }
        
        // Créer le profil avec le système de stockage sécurisé
        println!("🔑 Génération des clés cryptographiques...");
        let profile_id = self.storage.create_profile(&name, &password)?;
        
        println!("✅ Profil '{}' créé avec succès", name);
        println!("🆔 ID: {}", &profile_id.hash[..8]);
        
        // Charger le profil pour afficher la clé publique
        if let Ok(profile) = self.storage.load_profile(&profile_id, &password) {
            println!("🔑 Clé publique: {}", hex::encode(profile.identity_keypair.public.to_bytes()));
            println!("📅 Créé le: {}", profile.metadata.created.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        
        Ok(())
    }
    
    fn list_profiles_cmd(&self) -> Result<()> {
        let profiles = self.storage.list_profiles()?;
        
        if profiles.is_empty() {
            println!("👤 Aucun profil configuré");
            println!("💡 Utilisez 'miaou-cli profile create <nom>' pour créer un profil");
            return Ok(());
        }
        
        println!("👤 Profils Miaou ({} trouvés):", profiles.len());
        println!();
        
        for profile in profiles {
            println!("  📋 {}", profile.name);
            println!("     🆔 ID: {}", &profile.id.hash[..8]);
            println!("     📅 Créé: {}", profile.created.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("     🕒 Dernier accès: {}", profile.last_access.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("     🔑 Empreinte: {}...{}", 
                     &profile.public_key_fingerprint[..8], 
                     &profile.public_key_fingerprint[profile.public_key_fingerprint.len()-8..]);
            println!();
        }
        
        Ok(())
    }
    
    fn show_profile(&self, name: String) -> Result<()> {
        let profiles = self.storage.list_profiles()?;
        let profile_info = profiles.iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("Profil '{}' non trouvé", name))?;
        
        // Demander le mot de passe pour charger le profil
        let password = prompt_password(&format!("Mot de passe pour '{}': ", name))?;
        let profile = self.storage.load_profile(&profile_info.id, &password)?;
        
        println!("👤 Détails du profil '{}'", profile.metadata.name);
        println!();
        println!("🆔 ID: {}", profile.metadata.id.hash);
        println!("📅 Créé: {}", profile.metadata.created);
        println!("🕒 Dernier accès: {}", profile.metadata.last_access);
        println!("📦 Version: {}", profile.metadata.version);
        println!();
        println!("🔑 Clés cryptographiques:");
        println!("   Publique: {}", hex::encode(profile.identity_keypair.public.to_bytes()));
        println!("   Empreinte: {}", hex::encode(blake3_32(&profile.identity_keypair.public.to_bytes())));
        println!();
        println!("⚙️  Paramètres:");
        println!("   Accepter amis auto: {}", profile.settings.auto_accept_friends);
        println!("   Niveau chiffrement: {}", profile.settings.encryption_level);
        println!("   Sauvegarde: {}", profile.settings.backup_enabled);
        println!("   Thème: {}", profile.settings.theme);
        
        Ok(())
    }
    
    fn delete_profile(&self, name: String) -> Result<()> {
        let profiles = self.storage.list_profiles()?;
        let profile_info = profiles.iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("Profil '{}' non trouvé", name))?;
        
        // Confirmation
        print!("⚠️  Êtes-vous sûr de vouloir supprimer le profil '{}' ? [y/N]: ", name);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if input.trim().to_lowercase() != "y" {
            println!("Suppression annulée");
            return Ok(());
        }
        
        self.storage.delete_profile(&profile_info.id)?;
        println!("✅ Profil '{}' supprimé", name);
        
        Ok(())
    }
    
    fn test_encryption(&self, message: Option<String>) -> Result<()> {
        let message = match message {
            Some(msg) => msg,
            None => prompt_string("Message à chiffrer: ")?,
        };
        
        println!("🔒 Test de chiffrement interactif");
        println!("📝 Message: {}", message);
        
        // Générer une clé de test
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let aad = b"miaou_cli_test";
        let mut rng = rand_core::OsRng;
        
        // Chiffrer
        let encrypted = encrypt_auto_nonce(&key, aad, message.as_bytes(), &mut rng)?;
        println!("🔐 Chiffré: {} octets (tag inclus)", encrypted.ciphertext.len());
        println!("🎲 Nonce: {}", hex::encode(&encrypted.nonce));
        
        // Déchiffrer
        let decrypted = decrypt(&key, aad, &encrypted)?;
        let decrypted_str = String::from_utf8(decrypted)?;
        
        println!("🔓 Déchiffré: {}", decrypted_str);
        
        if decrypted_str == message {
            println!("✅ Test de chiffrement réussi !");
        } else {
            println!("❌ Erreur: les données ne correspondent pas");
        }
        
        Ok(())
    }
    
    fn test_signing(&self, message: Option<String>) -> Result<()> {
        let message = match message {
            Some(msg) => msg,
            None => prompt_string("Message à signer: ")?,
        };
        
        println!("✍️  Test de signature interactif");
        println!("📝 Message: {}", message);
        
        // Générer une paire de clés
        let keypair = Keypair::generate();
        println!("🔑 Clé publique: {}", hex::encode(keypair.public.to_bytes()));
        
        // Signer
        let signature = keypair.sign(message.as_bytes());
        println!("✍️  Signature: {}", hex::encode(signature.to_bytes()));
        
        // Vérifier
        match keypair.verify(message.as_bytes(), &signature) {
            Ok(()) => println!("✅ Signature valide !"),
            Err(e) => println!("❌ Signature invalide: {:?}", e),
        }
        
        Ok(())
    }
    
    fn run_benchmarks(&self) -> Result<()> {
        println!("⚡ Benchmarks de performance Miaou v0.1.0");
        println!("⏱️  Mesures approximatives (utilisez 'cargo bench' pour des mesures précises)");
        println!();
        
        use std::time::Instant;
        
        // Benchmark BLAKE3
        let data = vec![0u8; 1024 * 1024]; // 1 MB
        let start = Instant::now();
        for _ in 0..100 {
            let _ = blake3_32(&data);
        }
        let duration = start.elapsed();
        let throughput = (100.0 * data.len() as f64) / duration.as_secs_f64() / (1024.0 * 1024.0);
        println!("🏃 BLAKE3 (1 MB): {:.2} MiB/s", throughput);
        
        // Benchmark Ed25519
        let keypair = Keypair::generate();
        let message = b"benchmark message";
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = keypair.sign(message);
        }
        let duration = start.elapsed();
        let rate = 1000.0 / duration.as_secs_f64();
        println!("✍️  Ed25519 signatures: {:.0} sig/s", rate);
        
        // Benchmark ChaCha20-Poly1305
        let key = AeadKeyRef::from_bytes([42u8; 32]);
        let data = vec![0u8; 1024];
        let aad = b"benchmark";
        let mut rng = rand_core::OsRng;
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = encrypt_auto_nonce(&key, aad, &data, &mut rng);
        }
        let duration = start.elapsed();
        let rate = 1000.0 / duration.as_secs_f64();
        println!("🔒 ChaCha20-Poly1305: {:.0} ops/s", rate);
        
        println!();
        println!("💡 Pour des benchmarks détaillés: cargo bench");
        
        Ok(())
    }
    
    fn interactive_mode(&self) -> Result<()> {
        println!("🐱 Miaou CLI v0.1.0 - Mode interactif");
        println!("Tapez 'help' pour voir les commandes disponibles, 'quit' pour quitter");
        println!();
        
        loop {
            print!("miaou> ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            
            if input.is_empty() {
                continue;
            }
            
            match input {
                "quit" | "exit" | "q" => {
                    println!("👋 Au revoir !");
                    break;
                }
                "help" | "h" => {
                    self.show_interactive_help();
                }
                "status" => {
                    if let Err(e) = self.show_status() {
                        println!("❌ Erreur: {}", e);
                    }
                }
                "crypto-test" => {
                    if let Err(e) = self.run_crypto_tests() {
                        println!("❌ Erreur: {}", e);
                    }
                }
                "profiles" => {
                    if let Err(e) = self.list_profiles_cmd() {
                        println!("❌ Erreur: {}", e);
                    }
                }
                "benchmark" => {
                    if let Err(e) = self.run_benchmarks() {
                        println!("❌ Erreur: {}", e);
                    }
                }
                _ => {
                    println!("❓ Commande inconnue: '{}'. Tapez 'help' pour l'aide.", input);
                }
            }
            
            println!();
        }
        
        Ok(())
    }
    
    fn show_interactive_help(&self) {
        println!("📚 Commandes disponibles:");
        println!("  status        - Afficher l'état du système");
        println!("  crypto-test   - Tests des primitives cryptographiques");
        println!("  profiles      - Lister les profils");
        println!("  benchmark     - Benchmarks de performance");
        println!("  help, h       - Afficher cette aide");
        println!("  quit, exit, q - Quitter");
        println!();
        println!("💡 Utilisez les sous-commandes pour plus d'options:");
        println!("  profile create <nom>  - Créer un profil");
        println!("  profile show <nom>    - Afficher un profil");
        println!("  profile delete <nom>  - Supprimer un profil");
    }
}

// Fonctions utilitaires

fn expand_path(path: PathBuf) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        if let Some(home) = home::home_dir() {
            Ok(home.join(&path_str[2..]))
        } else {
            Ok(path)
        }
    } else {
        Ok(path)
    }
}

fn prompt_password(prompt: &str) -> Result<SecretString> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    Ok(SecretString::new(password))
}

fn prompt_string(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn get_disk_space(path: &PathBuf) -> Result<String> {
    // Approximation simple pour l'espace disque
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.is_dir() {
            Ok("Disponible".to_string())
        } else {
            Ok("Inconnu".to_string())
        }
    } else {
        Ok("Inconnu".to_string())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let miaou_cli = MiaouCli::new(cli.data_dir, cli.verbose)?;
    
    // Vérifier l'initialisation de Miaou
    if let Err(e) = initialize() {
        return Err(anyhow::anyhow!("Échec de l'initialisation de Miaou: {}", e));
    }
    
    match cli.command {
        Some(command) => miaou_cli.run_command(command),
        None => miaou_cli.interactive_mode(), // Mode interactif par défaut
    }
}