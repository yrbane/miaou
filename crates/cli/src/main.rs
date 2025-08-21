#![forbid(unsafe_code)]

//! **Documentation (FR)** : CLI de démonstration pour la Phase 1. Fournit des sous-commandes
//! `key` (génération, export) et `sign`/`verify` ainsi que `aead` (encrypt/decrypt) basées
//! sur les abstractions du projet. Les erreurs renvoient des codes retour non-ambigus.

use clap::{Parser, Subcommand};
use miaou_core::MiaouError;
use miaou_crypto::{AeadCipher, Chacha20Poly1305Cipher};
use miaou_keyring::{KeyId, KeyStore, MemoryKeyStore};
use std::process::ExitCode;
use tracing::Level;

// For verify path (public key -> verifying key)
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug, Parser)]
#[command(name = "miaou", version, about = "Miaou CLI (Phase 1)")]
struct Cli {
    /// Niveau de log (trace,debug,info,warn,error)
    #[arg(long, default_value = "info")]
    log: String,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Génère une paire de clés Ed25519 en mémoire et renvoie l'ID
    KeyGenerate,
    /// Exporte la clé publique (binaire en hex) pour un `KeyId`
    KeyExport { id: String },
    /// Signe un message (entrée UTF-8) avec la clé `id`
    Sign { id: String, message: String },
    /// Vérifie une signature hexadécimale pour `message` avec `id`
    Verify {
        id: String,
        message: String,
        signature_hex: String,
    },
    /// AEAD encrypt (key=32 hex, nonce=12 hex, aad=hex, pt=string)
    AeadEncrypt {
        key_hex: String,
        nonce_hex: String,
        aad_hex: String,
        plaintext: String,
    },
    /// AEAD decrypt (key=32 hex, nonce=12 hex, aad=hex, ct=hex)
    AeadDecrypt {
        key_hex: String,
        nonce_hex: String,
        aad_hex: String,
        ciphertext_hex: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), MiaouError> {
    // MVP: key store en mémoire pour la session
    let mut ks = MemoryKeyStore::new();
    match cli.cmd {
        Command::KeyGenerate => {
            let id = ks.generate_ed25519()?;
            println!("{}", id.0);
            Ok(())
        }
        Command::KeyExport { id } => {
            let pk = ks.export_public(&KeyId(id))?;
            println!("{}", hex(&pk));
            Ok(())
        }
        Command::Sign { id, message } => {
            let sig = ks.sign(&KeyId(id), message.as_bytes())?;
            println!("{}", hex(&sig));
            Ok(())
        }
        Command::Verify {
            id,
            message,
            signature_hex,
        } => {
            // Use exported public key to verify (no internal map access)
            let pk_bytes = ks.export_public(&KeyId(id))?;
            if pk_bytes.len() != 32 {
                return Err(MiaouError::InvalidInput);
            }
            let vk = VerifyingKey::from_bytes(pk_bytes[..].try_into().unwrap())
                .map_err(|e| MiaouError::Crypto(e.to_string()))?;
            let sig = Signature::from_slice(&from_hex(&signature_hex)?)
                .map_err(|e| MiaouError::Crypto(e.to_string()))?;
            let ok = vk.verify(message.as_bytes(), &sig).is_ok();
            println!("{}", if ok { "OK" } else { "FAIL" });
            Ok(())
        }
        Command::AeadEncrypt {
            key_hex,
            nonce_hex,
            aad_hex,
            plaintext,
        } => {
            let cipher = Chacha20Poly1305Cipher::from_key_bytes(&from_hex(&key_hex)?)?;
            let ct = cipher.encrypt(
                plaintext.as_bytes(),
                &from_hex(&nonce_hex)?,
                &from_hex(&aad_hex)?,
            )?;
            println!("{}", hex(&ct));
            Ok(())
        }
        Command::AeadDecrypt {
            key_hex,
            nonce_hex,
            aad_hex,
            ciphertext_hex,
        } => {
            let cipher = Chacha20Poly1305Cipher::from_key_bytes(&from_hex(&key_hex)?)?;
            let pt = cipher.decrypt(
                &from_hex(&ciphertext_hex)?,
                &from_hex(&nonce_hex)?,
                &from_hex(&aad_hex)?,
            )?;
            println!("{}", String::from_utf8_lossy(&pt));
            Ok(())
        }
    }
}

fn init_tracing(level: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_max_level(Level::INFO)
        .without_time()
        .init();
}

fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Result<Vec<u8>, MiaouError> {
    if s.len() % 2 != 0 {
        return Err(MiaouError::InvalidInput);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        let h = (hex_val(bytes[i]) << 4) | hex_val(bytes[i + 1]);
        out.push(h);
    }
    Ok(out)
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + (c - b'a'),
        b'A'..=b'F' => 10 + (c - b'A'),
        _ => 0,
    }
}
