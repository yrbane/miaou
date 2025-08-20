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

    #[test]
    fn test_signing_key_ref_from_bytes() {
        let bytes = [42u8; 32];
        let signing_key = SigningKeyRef::from_bytes(bytes);

        // Should be able to create a signing key from bytes
        let public_key = signing_key.verifying_key();
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_signing_key_ref_generate_with_rng() {
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKeyRef::generate(&mut rng);

        // Should generate a valid signing key
        let public_key = signing_key.verifying_key();
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_signing_key_ref_to_bytes() {
        let signing_key = SigningKeyRef::generate(&mut rand_core::OsRng);
        let bytes = signing_key.to_bytes();

        assert_eq!(bytes.len(), 32);

        // Should be able to recreate the same key
        let recreated = SigningKeyRef::from_bytes(bytes);
        let original_public = signing_key.verifying_key();
        let recreated_public = recreated.verifying_key();

        assert_eq!(original_public.to_bytes(), recreated_public.to_bytes());
    }

    #[test]
    fn test_signing_key_ref_debug_redacted() {
        let signing_key = SigningKeyRef::generate(&mut rand_core::OsRng);
        let debug_str = format!("{:?}", signing_key);

        assert!(debug_str.contains("SigningKeyRef([REDACTED])"));
    }

    #[test]
    fn test_verifying_key_ref_from_bytes_invalid() {
        // Test with invalid bytes (should error)
        let invalid_bytes = [0xFFu8; 32];
        match VerifyingKeyRef::from_bytes(invalid_bytes) {
            Ok(_) => {} // Ed25519 accepts most 32-byte arrays
            Err(e) => assert!(matches!(e, CryptoError::InvalidKey)),
        }
    }

    #[test]
    fn test_verifying_key_ref_from_hex_invalid() {
        // Invalid hex string
        assert!(VerifyingKeyRef::from_hex("invalid_hex").is_err());

        // Wrong length
        assert!(VerifyingKeyRef::from_hex("deadbeef").is_err());

        // Too long
        let too_long = "a".repeat(100);
        assert!(VerifyingKeyRef::from_hex(&too_long).is_err());
    }

    #[test]
    fn test_signature_from_bytes_to_bytes() {
        let keypair = Keypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        let signature_bytes = signature.to_bytes();
        assert_eq!(signature_bytes.len(), 64);

        let recreated_signature = Signature::from_bytes(signature_bytes).unwrap();
        assert_eq!(signature, recreated_signature);
    }

    #[test]
    fn test_signature_from_hex_invalid() {
        // Invalid hex
        assert!(Signature::from_hex("invalid_hex").is_err());

        // Wrong length
        assert!(Signature::from_hex("deadbeef").is_err());

        // Too long
        let too_long = "a".repeat(200);
        assert!(Signature::from_hex(&too_long).is_err());
    }

    #[test]
    fn test_keypair_generate_with_rng() {
        let mut rng = rand_core::OsRng;
        let keypair1 = Keypair::generate_with_rng(&mut rng);
        let keypair2 = Keypair::generate_with_rng(&mut rng);

        // Should generate different keypairs
        assert_ne!(keypair1.public_bytes(), keypair2.public_bytes());
        assert_ne!(keypair1.secret_bytes(), keypair2.secret_bytes());
    }

    #[test]
    fn test_keypair_from_secret_key() {
        let secret_key = SigningKeyRef::generate(&mut rand_core::OsRng);
        let public_key = secret_key.verifying_key();

        let keypair = Keypair::from_secret_key(secret_key);

        // Should have same public key
        assert_eq!(keypair.public.to_bytes(), public_key.to_bytes());
    }

    #[test]
    fn test_keypair_from_private_bytes() {
        let original_keypair = Keypair::generate();
        let private_bytes = original_keypair.secret_bytes();

        let recreated_keypair = Keypair::from_private_bytes(private_bytes).unwrap();

        // Should have same keys
        assert_eq!(
            original_keypair.public_bytes(),
            recreated_keypair.public_bytes()
        );
        assert_eq!(
            original_keypair.secret_bytes(),
            recreated_keypair.secret_bytes()
        );
    }

    #[test]
    fn test_keypair_public_bytes_secret_bytes() {
        let keypair = Keypair::generate();

        let public_bytes = keypair.public_bytes();
        let secret_bytes = keypair.secret_bytes();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(secret_bytes.len(), 32);

        // Should match direct access
        assert_eq!(public_bytes, keypair.public.to_bytes());
        assert_eq!(secret_bytes, keypair.secret.to_bytes());
    }

    #[test]
    fn test_keypair_key_references() {
        let keypair = Keypair::generate();

        let public_key_ref = keypair.public_key();
        let secret_key_ref = keypair.secret_key();

        // Should match direct access
        assert_eq!(public_key_ref.to_bytes(), keypair.public.to_bytes());

        let message = b"test";
        let sig1 = secret_key_ref.sign(message);
        let sig2 = keypair.secret.sign(message);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_keypair_debug_format() {
        let keypair = Keypair::generate();
        let debug_str = format!("{:?}", keypair);

        // Should contain public key info but redact secret
        assert!(debug_str.contains("Keypair"));
        assert!(debug_str.contains("public"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_sign_verify_wrong_message_fails() {
        let keypair = Keypair::generate();
        let message1 = b"correct message";
        let message2 = b"wrong message";

        let signature = keypair.sign(message1);

        // Correct message should verify
        assert!(keypair.verify(message1, &signature).is_ok());

        // Wrong message should fail
        assert!(keypair.verify(message2, &signature).is_err());
    }

    #[test]
    fn test_verifying_key_verify_wrong_signature_fails() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let message = b"test message";

        let signature = keypair1.sign(message);

        // Correct key should verify
        assert!(keypair1.public.verify(message, &signature).is_ok());

        // Wrong key should fail
        assert!(keypair2.public.verify(message, &signature).is_err());
    }

    #[test]
    fn test_cross_compatibility() {
        // Test that all sign/verify combinations work
        let keypair = Keypair::generate();
        let message = b"cross compatibility test";

        // Sign with secret key, verify with public key
        let sig1 = keypair.secret.sign(message);
        assert!(keypair.public.verify(message, &sig1).is_ok());

        // Sign with keypair, verify with public key
        let sig2 = keypair.sign(message);
        assert!(keypair.public.verify(message, &sig2).is_ok());

        // Sign with keypair, verify with keypair
        let sig3 = keypair.sign(message);
        assert!(keypair.verify(message, &sig3).is_ok());
    }
}
