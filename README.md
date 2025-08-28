# 🐱 Miaou v0.2.0 "Radar Moustaches"

**Plateforme P2P décentralisée avec cryptographie intégrée et réseau production-ready**

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-369%20passing-green.svg)](#tests)
[![Coverage](https://img.shields.io/badge/coverage-95.5%25-brightgreen.svg)](#coverage)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-passing-green.svg)](/.github/workflows/ci-cd.yml)

Miaou v0.2.0 introduit un **réseau P2P complet production-ready** avec découverte mDNS, connexions WebRTC, messagerie persistante et annuaire DHT distribué. Cette version majeure multiplie par 4 le nombre de tests (369 vs 91) et offre une infrastructure réseau complète.

## ✨ Fonctionnalités

### 🌐 **Réseau P2P production-ready**
- **mDNS Discovery LAN** : Découverte automatique avec résolution d'adresses IP non-loopback
- **WebRTC Data Channels** : Connexions P2P réelles avec négociation ICE
- **Messagerie persistante** : Queue avec garanties, retry automatique et Dead Letter Queue
- **DHT Directory** : Annuaire distribué avec K-buckets et XOR distance metric
- **NAT Traversal MVP** : Support de base (STUN/TURN complet en v0.3.0)

### 🔐 **Cryptographie robuste**
- **ChaCha20-Poly1305** : Chiffrement authentifié (AEAD) avec validation stricte
- **Ed25519** : Signatures numériques haute performance avec verification
- **BLAKE3** : Hachage cryptographique ultra-rapide (implémentation pure Rust)
- **Interfaces abstraites** : Traits object-safe pour extensibilité future

### 🏗️ **Architecture workspace moderne**
- **miaou-core** : Types communs, gestion d'erreurs, données sensibles avec zeroization
- **miaou-crypto** : Primitives cryptographiques avec implémentations de référence
- **miaou-keyring** : Gestion de clés en mémoire avec sérialisation sécurisée
- **miaou-network** : Infrastructure réseau P2P complète (nouveau crate v0.2.0)
- **miaou-cli** : Interface ligne de commande avec 14 commandes réseau et crypto

### 🧪 **Qualité de code exceptionnelle**
- **369 tests complets** : Tests unitaires, d'intégration, E2E et edge cases (+305% vs v0.1.0)
- **Couverture 95.5%** : Mesurée avec cargo-llvm-cov et validation automatique
- **Clippy pedantic/nursery** : Compliance stricte avec tous les lints
- **Documentation complète** : `# Errors` et `# Panics` pour toutes les fonctions
- **Tests de mutation** : Robustesse validée avec cargo-mutants
- **Scripts E2E** : test_mdns_demo.sh, test_e2e_messaging.sh, test_e2e_dht.sh

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

#### 🌐 **Commandes réseau P2P (nouveau v0.2.0)**

```bash
# Démarrer le service réseau P2P
./target/release/miaou-cli net-start --duration 60

# Lister les pairs découverts
./target/release/miaou-cli net-list-peers

# Se connecter à un pair via WebRTC
./target/release/miaou-cli net-connect <peer-id>

# Envoyer un message chiffré
./target/release/miaou-cli send <to> "Hello P2P world!"

# Recevoir les messages en attente
./target/release/miaou-cli recv

# Publier une clé dans le DHT
./target/release/miaou-cli dht-put signing <key-hex>

# Rechercher une clé DHT
./target/release/miaou-cli dht-get <peer-id> signing
```

#### 🔐 **Commandes cryptographiques**

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

### 🧪 Tests E2E réseau

```bash
# Test découverte mDNS mutuelle
./test_mdns_demo.sh

# Test messaging complet avec persistance
./test_e2e_messaging.sh

# Test DHT put/get distribué
./test_e2e_dht.sh

# Test parcours complet mDNS → WebRTC
./test_e2e_net_connect.sh
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
│   ├── network/               # Infrastructure P2P (nouveau v0.2.0)
│   │   ├── Cargo.toml
│   │   └── src/               # Discovery, Transport, Messaging, DHT
│   │       ├── lib.rs         # API publique réseau
│   │       ├── mdns_discovery.rs    # Découverte mDNS/Bonjour
│   │       ├── webrtc_transport.rs  # Transport WebRTC
│   │       ├── messaging.rs   # Queue messages persistante
│   │       ├── dht.rs         # Directory DHT Kademlia
│   │       └── peer.rs        # Gestion identités pairs
│   └── cli/                   # Interface ligne de commande
│       ├── Cargo.toml
│       └── src/main.rs        # CLI avec 14 commandes P2P + crypto
├── docs/                      # Documentation détaillée
├── scripts/                   # Scripts d'automatisation E2E
│   ├── test_mdns_demo.sh      # Test découverte mutuelle
│   ├── test_e2e_messaging.sh  # Test messaging persistant
│   ├── test_e2e_dht.sh        # Test DHT distribué
│   └── test_e2e_net_connect.sh # Test WebRTC complet
└── .github/workflows/         # CI/CD pipeline unifié
    └── ci-cd.yml              # Pipeline complet (validation, build, test, release)
```

### Traits et abstractions

#### 🔐 **Cryptographie** (miaou-crypto)
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

#### 🌐 **Réseau P2P** (miaou-network v0.2.0)
```rust
// Découverte de pairs abstraite
pub trait Discovery {
    async fn start(&mut self) -> Result<(), NetworkError>;
    async fn discovered_peers(&self) -> Vec<PeerInfo>;
    async fn collect_peers(&mut self) -> Result<(), NetworkError>;
}

// Transport de connexion abstrait
pub trait Transport {
    async fn create_outbound(&self, peer: &PeerInfo) -> Result<Connection, NetworkError>;
    async fn accept_inbound(&self) -> Result<Connection, NetworkError>;
}

// Queue de messages production
pub trait MessageQueue {
    async fn send(&mut self, msg: Message) -> Result<MessageId, NetworkError>;
    async fn receive(&mut self) -> Result<Option<Message>, NetworkError>;
    fn get_stats(&self) -> QueueStats;
}

// Annuaire distribué
pub trait Directory {
    async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), NetworkError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, NetworkError>;
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

## 📊 Métriques de qualité v0.2.0

### Tests et couverture
- **369 tests** tous types confondus (+305% vs v0.1.0)
- **95.5% de couverture** validée avec cargo-llvm-cov (maintenue excellente)
- **Seuil minimum 90%** appliqué automatiquement en CI

### Distribution des tests par crate
- **miaou-cli** : Tests workflow complet P2P + crypto
- **miaou-core** : Tests types sensibles, gestion erreurs, traits
- **miaou-crypto** : Tests primitives crypto, validations, security  
- **miaou-keyring** : Tests gestion clés, sérialisation, lifecycle
- **miaou-network** : Tests découverte, transport, messaging, DHT (nouveau)

### Tests End-to-End
- **test_mdns_demo.sh** : Découverte mutuelle mDNS (2 instances)
- **test_e2e_messaging.sh** : Messaging avec persistance FileMessageStore
- **test_e2e_dht.sh** : DHT put/get avec K-buckets distribués
- **test_e2e_net_connect.sh** : Parcours complet mDNS → WebRTC

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

### 🎯 v0.3.0 "Chat Quantique" (prochaine version)
- **STUN/TURN réel** : NAT traversal production avec serveurs externes
- **Handshake E2E** : Double Ratchet intégré pour Perfect Forward Secrecy
- **Web of Trust** : Signatures croisées et réputation distribuée
- **Persistance réseau** : Cache découverte inter-processus
- **GUI Desktop** : Interface Tauri/Electron native
- **Mobile natif** : Applications iOS/Android avec build automatisé

### 🌟 Roadmap long terme
La v0.2.0 établit l'**infrastructure P2P production-ready** pour :

- **Messageries fédérées** : Ponts vers Signal, Matrix, XMPP
- **Blockchain intégrée** : Système d'incitations économiques décentralisé  
- **Applications tierces** : SDK pour développeurs externes
- **Résilience réseau** : Routing mesh auto-réparant

La qualité de code exceptionnelle (369 tests, 95.5% couverture) et l'architecture SOLID garantissent une extensibilité future sans dette technique.

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

**Miaou v0.2.0 "Radar Moustaches"** - Infrastructure P2P production-ready avec 369 tests et découverte réseau complète 🌐🔐