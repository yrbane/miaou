# Guide de Démarrage Rapide - Développeurs

**Objectif :** Comprendre et contribuer au workspace Miaou en 15 minutes

## 🚀 Setup Environnement

### Prérequis
```bash
# Rust toolchain récente
rustup update stable
rustc --version  # >= 1.70.0 recommandé

# Outils de développement
cargo install cargo-tarpaulin    # Couverture de tests
cargo install cargo-audit        # Audit sécurité
```

### Clone et Build
```bash
git clone https://github.com/yrbane/miaou.git
cd miaou

# Build workspace complet
cargo build --workspace
# ✅ Should compile without warnings

# Tests complets
cargo test --workspace
# ✅ 300+ tests should pass

# Linting strict
cargo clippy --workspace --all-targets -- -D warnings
# ✅ Should pass with zero warnings
```

## 🏗️ Architecture Workspace (5 min)

### Structure Logique
```
miaou/
├── crates/core/      # Types communs, MiaouError, SensitiveBytes
├── crates/crypto/    # AEAD, Signer traits + implémentations
├── crates/keyring/   # KeyStore trait + MemoryKeyStore
├── crates/network/   # mDNS, WebRTC MVP, DHT MVP, E2E tests
└── crates/cli/       # 14 commandes + 243 tests
```

### Dépendances
```
core ← crypto ← keyring
  ↓      ↓        ↓
network ← ← ← ← cli
```

### Pattern de Développement
1. **core** : Types de base, erreurs
2. **crypto** : Traits + implémentations référence  
3. **keyring** : Stockage avec sérialisation
4. **network** : Composants P2P (progressif)
5. **cli** : Interface utilisateur

## 🔧 Workflow de Développement

### Ajout d'une Nouvelle Fonctionnalité

1. **Créer une branche**
   ```bash
   git checkout -b feature/issue-XX-description
   ```

2. **TDD : Tests d'abord**
   ```bash
   # Exemple : Nouvelle primitive crypto
   cd crates/crypto
   
   # 1. Écrire le test qui échoue
   vim src/lib.rs  # Ajouter test pour nouvelle fonction
   cargo test      # ❌ Devrait échouer
   
   # 2. Implémenter le minimum pour passer
   # 3. Refactorer et optimiser
   # 4. Documenter avec # Errors et # Panics
   ```

3. **Standards de Qualité**
   ```bash
   # Format automatique
   cargo fmt
   
   # Linting strict (zero tolerance)
   cargo clippy --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery
   
   # Tests avec couverture
   cargo tarpaulin --all-features --out Xml
   # Target: >90% sur nouveaux modules
   ```

4. **Documentation**
   ```rust
   /// Description claire de ce que fait la fonction
   /// 
   /// # Arguments
   /// * `param` - Description du paramètre
   /// 
   /// # Returns
   /// Description du retour
   /// 
   /// # Errors
   /// * `MiaouError::InvalidInput` - Si param invalide
   /// * `MiaouError::Crypto` - Si échec cryptographique
   /// 
   /// # Examples
   /// ```
   /// use miaou_crypto::*;
   /// let result = my_function("valid_input")?;
   /// assert_eq!(result, expected);
   /// ```
   pub fn my_function(param: &str) -> MiaouResult<String> {
       // Implementation
   }
   ```

## 🧪 Guide de Tests

### Hiérarchie de Tests
1. **Tests unitaires** : Dans chaque `src/lib.rs`
2. **Tests d'intégration** : Dans `tests/` de chaque crate  
3. **Tests CLI** : `assert_cmd` dans `crates/cli/tests/`
4. **Tests E2E** : `crates/network/tests/e2e_*`

### Pattern de Test Standard
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_function_success() {
        // Arrange
        let input = "valid_input";
        
        // Act  
        let result = my_function(input).unwrap();
        
        // Assert
        assert_eq!(result, "expected_output");
    }
    
    #[test]
    fn test_function_error_case() {
        let result = my_function("invalid_input");
        assert!(matches!(result, Err(MiaouError::InvalidInput)));
    }
    
    #[test]
    fn test_function_edge_cases() {
        // Empty input, very long input, special chars, etc.
    }
}
```

## 📦 Composants par Crate

### **miaou-core** - Fondations
```rust
use miaou_core::*;

// Gestion d'erreurs unifiée
let result: MiaouResult<String> = risky_operation().miaou()?;

// Données sensibles avec zeroization
let secret = SensitiveBytes(vec![1, 2, 3, 4]);
// Zéroization automatique au drop
```

### **miaou-crypto** - Cryptographie
```rust
use miaou_crypto::*;

// AEAD (Authenticated Encryption)
let cipher = ChaCha20Poly1305Cipher::new(&key)?;
let ciphertext = cipher.encrypt(b"hello", &nonce)?;
let plaintext = cipher.decrypt(&ciphertext, &nonce)?;

// Signatures numériques
let signer = Ed25519Signer::new(&private_key)?;
let signature = signer.sign(b"message")?;
let is_valid = signer.verify(b"message", &signature, &public_key)?;
```

### **miaou-keyring** - Clés
```rust
use miaou_keyring::*;

// Stockage en mémoire
let mut keystore = MemoryKeyStore::new();
keystore.store_key("alice", KeyEntry::new_signing(signing_key)).await?;

let key = keystore.get_key("alice").await?.unwrap();
```

### **miaou-network** - P2P
```rust
use miaou_network::*;

// Découverte mDNS
let mut discovery = UnifiedDiscovery::new(vec![DiscoveryMethod::Mdns]).await?;
discovery.start_discovery().await?;
discovery.announce("alice").await?;

let peers = discovery.get_discovered_peers().await?;
```

### **miaou-cli** - Interface
```bash
# Génération de clés
miaou key generate --name alice

# Découverte réseau avec JSON
miaou --json net unified list-peers --timeout 10

# Tests CLI
cargo test --package miaou-cli
```

## 🎯 Prochaines Contributions Possibles

### **Facilité (Good First Issues)**
- Ajouter tests unitaires manquants
- Améliorer documentation des modules
- Ajouter exemples dans `/examples`

### **Intermédiaire**  
- Finaliser WebRTC DataChannels
- Étendre tests de charge messaging
- Améliorer gestion d'erreurs réseau

### **Avancé**
- DHT Kademlia réseau complet
- ICE avec STUN/TURN
- Optimisations performances crypto

## ⚡ Commandes de Développement Utiles

```bash
# Build rapide (dev)
cargo build

# Build optimisé (release)  
cargo build --release

# Tests spécifiques
cargo test --package miaou-crypto
cargo test test_aead_encrypt

# Documentation locale
cargo doc --open

# Benchmark (si disponible)
cargo bench

# Audit sécurité
cargo audit

# Clean rebuild
cargo clean && cargo build
```

## 🔍 Debugging et Logs

```rust
use tracing::{debug, info, warn, error};

// Dans le code
info!("Démarrage découverte mDNS");
debug!("Peer découvert: {}", peer_id);
warn!("Timeout discovery: {}", duration);
error!("Échec connexion: {}", error);
```

```bash
# Activer logs détaillés
RUST_LOG=miaou_network=debug cargo test

# Logs pour CLI
RUST_LOG=info ./target/debug/miaou-cli net status
```

---

**Prêt à contribuer ! Le workspace est conçu pour être facile à comprendre et à étendre 🚀**