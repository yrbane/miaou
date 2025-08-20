//! Primitives cryptographiques de base
//! 
//! Fonctions utilitaires sécurisées pour opérations cryptographiques communes.

use crate::{CryptoError, CryptoResult};
use crate::crypto::hashing::{Blake3Hasher, HashingEngine};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Générateur de nombres aléatoires cryptographiquement sûr
static SECURE_RNG: std::sync::LazyLock<SystemRandom> = std::sync::LazyLock::new(|| SystemRandom::new());

/// Génère des bytes aléatoires cryptographiquement sûrs
/// 
/// # Arguments
/// * `length` - Nombre de bytes à générer
/// 
/// # Returns
/// * `Vec<u8>` - Bytes aléatoires générés
/// 
/// # Examples
/// ```
/// use miaou::crypto::primitives::random_bytes;
/// 
/// let random_data = random_bytes(32).unwrap();
/// assert_eq!(random_data.len(), 32);
/// ```
pub fn random_bytes(length: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    (&*SECURE_RNG)
        .fill(&mut bytes)
        .map_err(|e| CryptoError::KeyGenerationError(format!("RNG failed: {:?}", e)))?;
    Ok(bytes)
}

/// Génère un tableau de bytes aléatoires de taille fixe
/// 
/// # Examples
/// ```
/// use miaou::crypto::primitives::random_array;
/// 
/// let random_key: [u8; 32] = random_array().unwrap();
/// assert_eq!(random_key.len(), 32);
/// ```
pub fn random_array<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut array = [0u8; N];
    (&*SECURE_RNG)
        .fill(&mut array)
        .map_err(|e| CryptoError::KeyGenerationError(format!("RNG failed: {:?}", e)))?;
    Ok(array)
}

/// Comparaison en temps constant pour éviter les attaques par canaux auxiliaires
/// 
/// # Arguments
/// * `a` - Premier slice à comparer
/// * `b` - Second slice à comparer
/// 
/// # Returns
/// * `bool` - true si les slices sont identiques, false sinon
/// 
/// # Security
/// Cette fonction utilise une comparaison en temps constant pour éviter
/// les attaques par analyse temporelle.
/// 
/// # Examples
/// ```
/// use miaou::crypto::primitives::secure_compare;
/// 
/// let data1 = b"secret";
/// let data2 = b"secret";
/// let data3 = b"public";
/// 
/// assert!(secure_compare(data1, data2));
/// assert!(!secure_compare(data1, data3));
/// ```
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    // Vérification des longueurs d'abord
    if a.len() != b.len() {
        return false;
    }
    
    // Comparaison en temps constant
    a.ct_eq(b).into()
}

/// XOR de deux slices de même taille
/// 
/// # Arguments
/// * `a` - Premier slice
/// * `b` - Second slice (doit avoir la même taille que `a`)
/// 
/// # Returns
/// * `Result<Vec<u8>, CryptoError>` - XOR des deux slices
/// 
/// # Examples
/// ```
/// use miaou::crypto::primitives::xor_bytes;
/// 
/// let a = &[0xFF, 0x00, 0xAA];
/// let b = &[0x0F, 0xFF, 0x55];
/// let result = xor_bytes(a, b).unwrap();
/// assert_eq!(result, vec![0xF0, 0xFF, 0xFF]);
/// ```
pub fn xor_bytes(a: &[u8], b: &[u8]) -> CryptoResult<Vec<u8>> {
    if a.len() != b.len() {
        return Err(CryptoError::InvalidDataSize {
            expected: a.len(),
            actual: b.len(),
        });
    }
    
    let result: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
    Ok(result)
}

/// Combine deux clés de manière sécurisée (XOR après hachage)
/// 
/// # Arguments
/// * `key1` - Première clé
/// * `key2` - Seconde clé  
/// 
/// # Returns
/// * `[u8; 32]` - Clé combinée de 32 bytes
/// 
/// # Security
/// Les clés sont d'abord hachées avec BLAKE3 avant XOR pour éviter
/// les faiblesses cryptographiques du XOR direct.
pub fn combine_keys(key1: &[u8], key2: &[u8]) -> [u8; 32] {
    use crate::crypto::hashing::Blake3Hasher;
    
    let hash1 = Blake3Hasher::hash(key1);
    let hash2 = Blake3Hasher::hash(key2);
    
    let mut combined = [0u8; 32];
    for i in 0..32 {
        combined[i] = hash1.as_bytes()[i] ^ hash2.as_bytes()[i];
    }
    
    combined
}

/// Dérive une sous-clé à partir d'une clé maître et d'un contexte
/// 
/// # Arguments
/// * `master_key` - Clé maître
/// * `context` - Contexte de dérivation (ex: "encryption", "signature")
/// * `index` - Index de la sous-clé (pour générer plusieurs clés)
/// 
/// # Returns
/// * `[u8; 32]` - Sous-clé dérivée
/// 
/// # Examples
/// ```
/// use miaou::crypto::primitives::derive_subkey;
/// 
/// let master = &[0u8; 32];
/// let encryption_key = derive_subkey(master, "encryption", 0);
/// let signing_key = derive_subkey(master, "signing", 0);
/// 
/// assert_ne!(encryption_key, signing_key);
/// ```
pub fn derive_subkey(master_key: &[u8], context: &str, index: u32) -> [u8; 32] {
    let context_with_index = format!("miaou.{}.{}", context, index);
    let combined = [master_key, context_with_index.as_bytes()].concat();
    let hash = blake3::hash(&combined);
    *hash.as_bytes()
}

/// Mélange sécurisé de données (shuffle cryptographique)
/// 
/// # Arguments
/// * `data` - Données à mélanger
/// * `seed` - Graine pour le mélange (doit être aléatoire)
/// 
/// # Returns
/// * `Vec<u8>` - Données mélangées
/// 
/// # Security
/// Utilise Fisher-Yates avec un PRNG seedé pour un mélange déterministe
/// mais cryptographiquement sûr.
pub fn secure_shuffle(data: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut result = data.to_vec();
    
    // Fisher-Yates shuffle
    for i in (1..result.len()).rev() {
        let j = rng.gen_range(0..=i);
        result.swap(i, j);
    }
    
    result
}

/// Génère un sel aléatoire pour Argon2 ou autres KDF
/// 
/// # Returns
/// * `[u8; 16]` - Sel aléatoire de 16 bytes
pub fn generate_salt() -> CryptoResult<[u8; 16]> {
    random_array::<16>()
}

/// Génère un nonce aléatoire pour ChaCha20-Poly1305
/// 
/// # Returns
/// * `[u8; 12]` - Nonce aléatoire de 12 bytes
pub fn generate_nonce() -> CryptoResult<[u8; 12]> {
    random_array::<12>()
}

/// Efface de manière sécurisée un buffer en mémoire
/// 
/// # Arguments
/// * `buffer` - Buffer mutable à effacer
/// 
/// # Security
/// Utilise zeroize pour garantir que les données sensibles
/// sont bien effacées de la mémoire.
pub fn secure_erase(buffer: &mut [u8]) {
    buffer.zeroize();
}

/// Générateur d'identifiants uniques cryptographiquement sûrs
pub struct SecureIdGenerator {
    counter: std::sync::atomic::AtomicU64,
    node_id: [u8; 8],
}

impl SecureIdGenerator {
    /// Crée un nouveau générateur avec un ID de nœud aléatoire
    pub fn new() -> CryptoResult<Self> {
        let node_id = random_array::<8>()?;
        Ok(Self {
            counter: std::sync::atomic::AtomicU64::new(0),
            node_id,
        })
    }
    
    /// Génère un ID unique de 16 bytes
    pub fn generate_id(&self) -> [u8; 16] {
        use std::sync::atomic::Ordering;
        
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let mut id = [0u8; 16];
        id[0..8].copy_from_slice(&timestamp.to_be_bytes());
        id[8..16].copy_from_slice(&(counter ^ u64::from_be_bytes(self.node_id)).to_be_bytes());
        
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Probabilité négligeable d'être égaux
    }
    
    #[test]
    fn test_random_array() {
        let array1: [u8; 16] = random_array().unwrap();
        let array2: [u8; 16] = random_array().unwrap();
        
        assert_ne!(array1, array2);
    }
    
    #[test]
    fn test_secure_compare() {
        let data1 = b"secret_data";
        let data2 = b"secret_data";
        let data3 = b"public_data";
        let data4 = b"secret"; // Longueur différente
        
        assert!(secure_compare(data1, data2));
        assert!(!secure_compare(data1, data3));
        assert!(!secure_compare(data1, data4));
    }
    
    #[test]
    fn test_xor_bytes() {
        let a = &[0xFF, 0x00, 0xAA, 0x55];
        let b = &[0x0F, 0xFF, 0x55, 0xAA];
        let expected = vec![0xF0, 0xFF, 0xFF, 0xFF];
        
        let result = xor_bytes(a, b).unwrap();
        assert_eq!(result, expected);
        
        // Test tailles différentes
        let c = &[0xFF];
        assert!(xor_bytes(a, c).is_err());
    }
    
    #[test]
    fn test_combine_keys() {
        let key1 = &[1u8; 32];
        let key2 = &[2u8; 32];
        let key3 = &[1u8; 32]; // Identique à key1
        
        let combined1 = combine_keys(key1, key2);
        let combined2 = combine_keys(key1, key3);
        let combined3 = combine_keys(key2, key1); // Ordre différent
        
        assert_ne!(combined1, combined2);
        assert_eq!(combined1, combined3); // XOR est commutatif après hash
    }
    
    #[test]
    fn test_derive_subkey() {
        let master = &[0u8; 32];
        
        let enc_key = derive_subkey(master, "encryption", 0);
        let sig_key = derive_subkey(master, "signing", 0);
        let enc_key2 = derive_subkey(master, "encryption", 1);
        
        // Contextes différents = clés différentes
        assert_ne!(enc_key, sig_key);
        
        // Index différents = clés différentes
        assert_ne!(enc_key, enc_key2);
        
        // Déterminisme
        let enc_key_again = derive_subkey(master, "encryption", 0);
        assert_eq!(enc_key, enc_key_again);
    }
    
    #[test]
    fn test_secure_shuffle() {
        let data = b"Hello, World!";
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        
        let shuffled1 = secure_shuffle(data, &seed1);
        let shuffled2 = secure_shuffle(data, &seed2);
        let shuffled1_again = secure_shuffle(data, &seed1);
        
        // Même seed = même résultat
        assert_eq!(shuffled1, shuffled1_again);
        
        // Seeds différents = résultats différents (très probable)
        assert_ne!(shuffled1, shuffled2);
        
        // Même longueur
        assert_eq!(shuffled1.len(), data.len());
    }
    
    #[test]
    fn test_salt_and_nonce_generation() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();
        
        assert_eq!(salt1.len(), 16);
        assert_eq!(nonce1.len(), 12);
        assert_ne!(salt1, salt2);
        assert_ne!(nonce1, nonce2);
    }
    
    #[test]
    fn test_secure_erase() {
        let mut buffer = vec![0xAA; 100];
        secure_erase(&mut buffer);
        
        // Vérifier que tout est à zéro
        assert!(buffer.iter().all(|&x| x == 0));
    }
    
    #[test]
    fn test_secure_id_generator() {
        let generator = SecureIdGenerator::new().unwrap();
        
        let id1 = generator.generate_id();
        let id2 = generator.generate_id();
        
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_secure_id_generator_uniqueness() {
        let generator = SecureIdGenerator::new().unwrap();
        let mut ids = std::collections::HashSet::new();
        
        // Générer 1000 IDs et vérifier l'unicité
        for _ in 0..1000 {
            let id = generator.generate_id();
            assert!(ids.insert(id), "ID dupliqué détecté");
        }
    }
}