//! # Signatures Ed25519 (v0.1)
//!
//! Génère une paire, signe et vérifie des messages (aucun Debug sur secrets).
//! Utilise ed25519-dalek v2 avec zeroization automatique.

use crate::CryptoError;
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::ZeroizeOnDrop;

/// Clé de signature secrète (zeroized on drop, non clonable, non affichable)
#[derive(ZeroizeOnDrop)]
pub struct SigningKeyRef {
    inner: SigningKey,
}

impl SigningKeyRef {
    /// Crée une clé de signature depuis 32 octets.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(&bytes),
        }
    }

    /// Génère une nouvelle clé de signature aléatoire.
    #[must_use]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            inner: SigningKey::generate(rng),
        }
    }

    /// Retourne la clé publique correspondante.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKeyRef {
        VerifyingKeyRef {
            inner: self.inner.verifying_key(),
        }
    }

    /// Retourne les octets de la clé secrète (usage keystore).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Signe un message.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature {
            inner: self.inner.sign(msg),
        }
    }
}

// Pas de Debug pour éviter les fuites
impl std::fmt::Debug for SigningKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyRef([REDACTED])")
    }
}

/// Clé de vérification publique
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKeyRef {
    inner: VerifyingKey,
}

impl VerifyingKeyRef {
    /// Crée une clé de vérification depuis 32 octets.
    ///
    /// # Errors
    /// Échec si les octets ne représentent pas une clé publique Ed25519 valide.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(&bytes)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Retourne les octets de la clé publique.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Vérifie une signature.
    ///
    /// # Errors
    /// Échec si la signature est invalide pour le message donné.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        self.inner
            .verify(msg, &sig.inner)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Encode la clé publique en hexadécimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Décode une clé publique depuis l'hexadécimal.
    ///
    /// # Errors
    /// Échec si `hex_str` n'est pas une chaîne hexadécimale valide de 32 octets.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str).map_err(|_| CryptoError::InvalidInput)?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Self::from_bytes(key_bytes)
    }
}

/// Signature Ed25519 (64 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    inner: DalekSignature,
}

impl Signature {
    /// Crée une signature depuis 64 octets.
    ///
    /// # Errors
    /// Échec si les octets ne représentent pas une signature Ed25519 valide.
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: DalekSignature::from_bytes(&bytes),
        })
    }

    /// Retourne les octets de la signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }

    /// Encode la signature en hexadécimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Décode une signature depuis l'hexadécimal.
    ///
    /// # Errors
    /// Échec si `hex_str` n'est pas une chaîne hexadécimale valide de 64 octets.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str).map_err(|_| CryptoError::InvalidInput)?;

        if bytes.len() != 64 {
            return Err(CryptoError::InvalidInput);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes);

        Self::from_bytes(sig_bytes)
    }
}

/// Paire de clés (secret/public)
pub struct Keypair {
    /// Clé secrète (non clonable, non affichable).
    pub secret: SigningKeyRef,
    /// Clé publique (vérification).
    pub public: VerifyingKeyRef,
}

impl Keypair {
    /// Génère une paire Ed25519.
    #[must_use]
    pub fn generate() -> Self {
        let secret = SigningKeyRef {
            inner: SigningKey::generate(&mut OsRng),
        };
        let public = secret.verifying_key();
        Self { secret, public }
    }

    /// Génère une paire avec un RNG spécifique.
    #[must_use]
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = SigningKeyRef::generate(rng);
        let public = secret.verifying_key();
        Self { secret, public }
    }

    /// Crée une paire depuis une clé secrète.
    #[must_use]
    pub fn from_secret_key(secret: SigningKeyRef) -> Self {
        let public = secret.verifying_key();
        Self { secret, public }
    }

    /// Crée une paire depuis les octets d'une clé privée.
    ///
    /// # Errors
    /// Cette fonction ne peut pas échouer car `SigningKeyRef::from_bytes` est infaillible.
    pub fn from_private_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let secret = SigningKeyRef::from_bytes(bytes);
        let public = secret.verifying_key();
        Ok(Self { secret, public })
    }

    /// Signe un message.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.secret.sign(msg)
    }

    /// Vérifie une signature.
    ///
    /// # Errors
    /// Échec si la signature est invalide pour le message donné.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        self.public.verify(msg, sig)
    }

    /// Retourne les octets de la clé publique.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Retourne les octets de la clé secrète (usage keystore).
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Retourne une référence vers la clé publique.
    #[must_use]
    pub const fn public_key(&self) -> &VerifyingKeyRef {
        &self.public
    }

    /// Retourne une référence vers la clé secrète.
    #[must_use]
    pub const fn secret_key(&self) -> &SigningKeyRef {
        &self.secret
    }
}

// Pas de Debug pour éviter les fuites de la clé secrète
impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate();
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::generate();
        let message = b"hello world";

        let signature = keypair.sign(message);

        // Bonne signature
        assert!(keypair.public.verify(message, &signature).is_ok());

        // Mauvais message
        assert!(keypair.public.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_key_serialization() {
        let keypair = Keypair::generate();

        // Test sérialisation clé publique
        let public_bytes = keypair.public.to_bytes();
        let public_restored = VerifyingKeyRef::from_bytes(public_bytes).unwrap();
        assert_eq!(keypair.public, public_restored);

        // Test sérialisation signature
        let message = b"test";
        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();
        let sig_restored = Signature::from_bytes(sig_bytes).unwrap();
        assert_eq!(signature, sig_restored);
    }

    #[test]
    fn test_hex_encoding() {
        let keypair = Keypair::generate();

        // Test hex clé publique
        let hex = keypair.public.to_hex();
        let restored = VerifyingKeyRef::from_hex(&hex).unwrap();
        assert_eq!(keypair.public, restored);

        // Test hex signature
        let signature = keypair.sign(b"test");
        let hex_sig = signature.to_hex();
        let restored_sig = Signature::from_hex(&hex_sig).unwrap();
        assert_eq!(signature, restored_sig);
    }

    #[test]
    fn test_zeroization() {
        // Test que SigningKeyRef implémente ZeroizeOnDrop
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningKeyRef>();
    }

    #[test]
    fn test_no_debug_on_secrets() {
        // Les types secrets ne doivent pas leak d'informations via Debug
        let keypair = Keypair::generate();
        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("SigningKey"));
    }
}
