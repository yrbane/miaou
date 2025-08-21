# 🐱 Miaou v0.1.0 "Première Griffe"

**Bibliothèque cryptographique Rust sécurisée avec CLI de démonstration**

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-54%20passing-green.svg)](#tests)
[![Coverage](https://img.shields.io/badge/coverage-95.5%25-brightgreen.svg)](#coverage)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-passing-green.svg)](/.github/workflows/ci-cd.yml)

Miaou v0.1.0 fournit des **primitives cryptographiques sécurisées** et une architecture workspace moderne pour le développement Rust. Cette version se concentre sur la robustesse, la sécurité et la qualité de code exceptionnelle.

## ✨ Fonctionnalités

### 🔐 **Cryptographie robuste**
- **ChaCha20-Poly1305** : Chiffrement authentifié (AEAD) avec validation stricte
- **Ed25519** : Signatures numériques haute performance avec verification
- **BLAKE3** : Hachage cryptographique ultra-rapide (implémentation pure Rust)
- **Interfaces abstraites** : Traits object-safe pour extensibilité future

### 🏗️ **Architecture workspace moderne**
- **miaou-core** : Types communs, gestion d'erreurs, données sensibles avec zeroization
- **miaou-crypto** : Primitives cryptographiques avec implémentations de référence
- **miaou-keyring** : Gestion de clés en mémoire avec sérialisation sécurisée
- **miaou-cli** : Interface ligne de commande avec toutes les opérations crypto

### 🧪 **Qualité de code exceptionnelle**
- **54 tests complets** : Tests unitaires, d'intégration et edge cases
- **Couverture 95.5%** : Mesurée avec cargo-llvm-cov et validation automatique
- **Clippy pedantic/nursery** : Compliance stricte avec tous les lints
- **Documentation complète** : `# Errors` et `# Panics` pour toutes les fonctions
- **Tests de mutation** : Robustesse validée avec cargo-mutants

### 📦 **Déploiement multi-plateformes**
- **Desktop** : Linux (x86_64, ARM64), Windows, macOS (Intel & Apple Silicon)
- **WebAssembly** : Support complet avec profil release-wasm optimisé
- **Android** : Builds locaux avec profil release-mobile (pure Rust)
- **CI/CD automatisé** : Pipeline GitHub Actions complet avec artifacts

## 🚀 Démarrage rapide

### Installation et build

```bash
# Clone du repository
git clone https://github.com/username/miaou.git
cd miaou

# Build du workspace complet
cargo build --workspace

# Tests avec couverture
cargo test --workspace

# Build CLI optimisé
cargo build --release -p miaou-cli
```

### Utilisation de la CLI

```bash
# Générer une paire de clés Ed25519
./target/release/miaou-cli key-generate

# Exporter la clé publique (format hex)
./target/release/miaou-cli key-export <key-id>

# Signer un message
./target/release/miaou-cli sign <key-id> "Hello, world!"

# Vérifier une signature
./target/release/miaou-cli verify <key-id> "Hello, world!" <signature-hex>

# Chiffrement AEAD ChaCha20-Poly1305
./target/release/miaou-cli aead-encrypt <key-hex> <nonce-hex> <aad-hex> "message secret"

# Déchiffrement AEAD
./target/release/miaou-cli aead-decrypt <key-hex> <nonce-hex> <aad-hex> <ciphertext-hex>
```

### Builds spécialisés

```bash
# Build WebAssembly (pour le web)
cargo build --target wasm32-unknown-unknown --profile release-wasm --lib

# Build Android (local, avec NDK configuré)
cargo build --target i686-linux-android --profile release-mobile -p miaou-cli
```

## 🏗️ Architecture

### Structure du workspace

```
miaou/
├── Cargo.toml                 # Configuration workspace
├── crates/                    # Crates modernes
│   ├── core/                  # Types communs et erreurs
│   │   ├── Cargo.toml
│   │   └── src/lib.rs         # SensitiveBytes, MiaouError, traits
│   ├── crypto/                # Primitives cryptographiques
│   │   ├── Cargo.toml  
│   │   └── src/lib.rs         # AeadCipher, Signer, implémentations
│   ├── keyring/               # Gestion de clés
│   │   ├── Cargo.toml
│   │   └── src/lib.rs         # KeyStore, MemoryKeyStore
│   └── cli/                   # Interface ligne de commande
│       ├── Cargo.toml
│       └── src/main.rs        # CLI complète avec toutes les commandes
├── docs/                      # Documentation détaillée
├── scripts/                   # Scripts d'automatisation
└── .github/workflows/         # CI/CD pipeline unifié
    └── ci-cd.yml              # Pipeline complet (validation, build, test, release)
```

### Traits et abstractions

```rust
// Chiffrement authentifié générique
pub trait AeadCipher {
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> MiaouResult<Vec<u8>>;
}

// Signature numérique générique  
pub trait Signer {
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> MiaouResult<Vec<u8>>;
    fn verify(&self, msg: &[u8], sig: &[u8]) -> MiaouResult<bool>;
}

// Stockage de clés générique
pub trait KeyStore {
    fn generate_ed25519(&mut self) -> MiaouResult<KeyId>;
    fn export_public(&self, id: &KeyId) -> MiaouResult<Vec<u8>>;
    fn sign(&self, id: &KeyId, msg: &[u8]) -> MiaouResult<Vec<u8>>;
}
```

## 🔐 Sécurité

### Implémentations cryptographiques

- **ChaCha20-Poly1305** : `chacha20poly1305` crate (RustCrypto)
- **Ed25519** : `ed25519-dalek` crate avec validation stricte
- **BLAKE3** : `blake3` crate avec feature "pure" pour compatibilité multi-plateformes
- **Zeroization** : Effacement sécurisé des données sensibles avec `zeroize`

### Propriétés de sécurité

- **Pas de `unsafe`** : `#![forbid(unsafe_code)]` sur tous les crates
- **Gestion d'erreurs stricte** : Tous les cas d'erreur sont gérés explicitement
- **Tests d'edge cases** : Validation avec entrées invalides, tailles incorrectes
- **Audit trail** : Toutes les opérations sensibles sont tracées

### Validation et tests

```bash
# Tests complets avec couverture
cargo test --workspace --all-features

# Linting strict (pedantic + nursery + cargo)
cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery -D clippy::cargo

# Vérification du formatage
cargo fmt --all -- --check

# Tests de mutation (robustesse)
cargo install cargo-mutants
cargo mutants --check
```

## 📊 Métriques de qualité

### Tests et couverture
- **54 tests** tous types confondus (unitaires, intégration, edge cases)
- **95.5% de couverture** validée avec cargo-llvm-cov
- **Seuil minimum 90%** appliqué automatiquement en CI

### Distribution des tests par crate
- **miaou-cli** : 31 tests (workflow complet, validations, edge cases)
- **miaou-core** : 8 tests (types sensibles, gestion erreurs, traits)
- **miaou-crypto** : 6 tests (primitives crypto, validations, security)
- **miaou-keyring** : 9 tests (gestion clés, sérialisation, lifecycle)

### Compliance et qualité
- **Clippy pedantic** : 100% compliance
- **Documentation** : Toutes les APIs publiques documentées
- **Performance** : Benchmarks intégrés avec criterion
- **Sécurité** : Audit automatique avec cargo-audit

## 🤖 CI/CD Pipeline

Le projet utilise un pipeline GitHub Actions unifié avec :

### Validation multi-OS
- **Plateformes** : Ubuntu, Windows, macOS
- **Checks** : Formatage, Clippy strict, build, tests, doc-tests

### Builds multi-plateformes
- **Desktop** : 5 targets (Linux x86_64/ARM64, Windows, macOS Intel/M1)
- **WebAssembly** : 2 targets (wasm32-unknown-unknown, wasm32-wasip1)
- **Release automatique** : Artifacts packagés pour tous les targets

### Quality gates
- **Tests** : 54 tests sur toutes plateformes
- **Couverture** : Minimum 90% appliqué automatiquement
- **Sécurité** : Audit des vulnérabilités hebdomadaire
- **Performance** : Benchmarks de régression

## 🚀 Évolution future

Cette version v0.1.0 établit les **fondations techniques solides** pour :

- **Communication P2P** : Protocole de messagerie décentralisé
- **Interfaces utilisateur** : Applications desktop et mobiles natives
- **Interopérabilité** : Ponts vers messageries existantes
- **Blockchain intégrée** : Système d'incitations économiques

La qualité de code exceptionnelle et l'architecture modulaire garantissent une extensibilité future sans dette technique.

## 🤝 Contribution

Les contributions sont bienvenues ! Voir [CONTRIBUTING.md](docs/CONTRIBUTING.md) pour :

- Guidelines de développement (TDD, SOLID, sécurité)
- Processus de review et standards de qualité
- Architecture détaillée et conventions de code

## 📋 Documentation complète

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture détaillée du système
- **[CHANGELOG.md](docs/CHANGELOG.md)** - Historique des versions
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Guide de contribution
- **[SECURITY.md](docs/SECURITY.md)** - Politique de sécurité et audit
- **[DEPENDENCIES.md](docs/DEPENDENCIES.md)** - Gestion des dépendances
- **[ROADMAP.md](docs/ROADMAP.md)** - Évolution future du projet

## 📄 Licence

Dual-licensed sous MIT OR Apache-2.0

---

**Miaou v0.1.0 "Première Griffe"** - Une base cryptographique solide pour l'avenir de la communication décentralisée 🏴‍☠️