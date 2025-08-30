# 🐱 Miaou v0.2.0 "Radar Moustaches"

**Plateforme P2P décentralisée avec base technique solide et cryptographie production**

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-300%2B%20passing-green.svg)](#tests)
[![Coverage](https://img.shields.io/badge/coverage-90%2B%25-brightgreen.svg)](#coverage)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-passing-green.svg)](/.github/workflows/ci.yml)

Miaou v0.2.0 établit une **base technique solide** pour P2P sécurisé : découverte mDNS réelle, cryptographie production-ready, CLI complète, et infrastructure de tests E2E. Architecture modulaire préparée pour WebRTC et DHT complets en v0.3.0.

## 🎯 État v0.2.0 "Radar & Moustaches"

### ✅ **Production Ready**

#### 🔐 **Cryptographie sécurisée**
- **ChaCha20-Poly1305** : AEAD avec API trait-based, tests exhaustifs
- **Ed25519** : Signatures numériques rapides, génération de clés sécurisée  
- **BLAKE3** : Hachage cryptographique, implémentation pure Rust
- **SensitiveBytes** : Zeroization automatique des données sensibles
- **KeyStore** : Gestion de clés modulaire avec persistance JSON

#### 🌐 **Découverte réseau réelle**
- **mDNS Discovery** : Découverte LAN avec `mdns-sd`, annonce automatique
- **CLI net-list-peers** : Commande avec retry logic, codes de sortie corrects
- **Format JSON** : Sortie structurée avec peer_id, endpoints, latence

#### 🖥️ **CLI complète et testée**
- **14 commandes** : key, net, send/recv, dht, crypto, avec `--json` global
- **243 tests** : Couverture complète des commandes et edge cases  
- **Codes de sortie** : Standards Unix (0/1/2) avec retry automatique
- **Intégration tests** : `assert_cmd` pour validation bout-en-bout

#### 🧪 **Tests E2E et infrastructure**
- **4 scénarios E2E** : 2-node, bidirectionnel, multi-peer, gestion d'erreurs
- **Orchestration** : `E2eTestNode` pour tests complexes automatisés
- **Collecte de traces** : Validation intelligente des logs et métriques

### 🚧 **MVP/Architecture (v0.3.0)**

#### 🔗 **WebRTC Transport**
- **Structure définie** : `WebRtcTransport`, intégration `webrtc-rs` 
- **État actuel** : Architecture + mocks pour développement
- **v0.3.0** : DataChannels complets, ICE réel, STUN/TURN

#### 🌍 **DHT Kademlia**  
- **MVP local** : Table de routage, messages PING/STORE/FIND
- **État actuel** : Tests multi-nœuds en mémoire
- **v0.3.0** : Communication UDP réseau, bootstrap automatique

#### 📨 **Messaging robuste**
- **Base stable** : `FileMessageStore`, déduplication, retry
- **État actuel** : API stable, tests unitaires
- **v0.3.0** : Tests de charge, ACK end-to-end fiables

## 🏗️ Architecture Workspace

```
miaou/
├── crates/
│   ├── core/         ✅ Types communs, erreurs, SensitiveBytes
│   ├── crypto/       ✅ ChaCha20Poly1305, Ed25519, traits AEAD/Signer  
│   ├── keyring/      ✅ KeyStore trait, MemoryKeyStore, persistance
│   ├── network/      🚧 mDNS réel + WebRTC/DHT MVP (extension v0.3.0)
│   └── cli/          ✅ 14 commandes, 243 tests, formats JSON
├── .github/          ✅ CI/CD complet (4 workflows, quality gates)
└── docs/             ✅ Documentation synchronisée code/specs
```

## 🚀 Démarrage Rapide

### Installation et Build
```bash
git clone https://github.com/yrbane/miaou.git
cd miaou
cargo build --workspace --release
```

### Démo Découverte LAN
```bash
# Terminal 1 - Alice
./target/release/miaou-cli net unified list-peers --json

# Terminal 2 - Bob (autre machine LAN)
./target/release/miaou-cli net unified list-peers --timeout 10

# Résultat : Découverte mutuelle via mDNS en <8s ✅
```

### Tests et Validation
```bash
# Tests complets (300+ tests)
cargo test --workspace

# Tests E2E spécifiques
cargo test --package miaou-network e2e_

# Linting strict (pedantic + nursery)
cargo clippy --workspace --all-targets -- -D warnings
```

## 📊 Métriques v0.2.0

| Composant | Tests | Couverture | Statut |
|-----------|-------|------------|--------|
| **miaou-core** | 11 tests | 100% | ✅ Production |
| **miaou-crypto** | 45+ tests | 95%+ | ✅ Production |  
| **miaou-keyring** | 20+ tests | 90%+ | ✅ Production |
| **miaou-network** | 25+ tests | 85%+ | 🚧 mDNS réel + MVP |
| **miaou-cli** | 243 tests | 90%+ | ✅ Production |
| **Total** | **300+ tests** | **>90%** | **Base solide** |

## 🔧 Commandes CLI Disponibles

```bash
# Gestion de clés
miaou key generate --name alice
miaou key export alice

# Réseau et découverte  
miaou net unified list-peers --json --timeout 10
miaou net status

# Cryptographie (utilitaires)
miaou aead encrypt --key $(miaou key export alice --field encryption)
miaou sign --data "hello" --key alice

# DHT basique (MVP)
miaou dht-put signing $(miaou key export alice --field signing)
miaou dht-get signing alice

# Format JSON global
miaou --json net status | jq '.peers_count'
```

## 🧪 Infrastructure de Qualité

### CI/CD Pipeline
- **Format/Linting** : `cargo fmt`, `clippy pedantic + nursery`
- **Tests multi-OS** : Ubuntu, Windows, macOS
- **Security audit** : `cargo-audit` + dependency review  
- **Coverage** : >90% maintenue avec `cargo-tarpaulin`

### Standards de Code
- **Zero unsafe** : `#![forbid(unsafe_code)]` sur tout le workspace
- **Documentation** : APIs publiques avec `# Errors` et `# Panics`
- **TDD rigoureux** : Interfaces découvertes par tests
- **Gestion d'erreurs** : `MiaouError` typé avec conversions automatiques

## 🔮 Roadmap v0.3.0 "DHT & WebRTC Réel"

Les fonctionnalités MVP seront finalisées :
- 🎯 **WebRTC complet** : DataChannels réels, ICE avec STUN/TURN
- 🎯 **DHT réseau** : Communication UDP, bootstrap, réplication
- 🎯 **Messaging robuste** : Tests de charge, ACK fiables
- 🎯 **API de signaling** : Échange SDP/candidats standardisé

## 📚 Documentation

- **[Architecture](docs/ARCHITECTURE.md)** : Design patterns et composants
- **[État du workspace](docs/WORKSPACE_STATUS.md)** : Implémentation détaillée  
- **[Réconciliation code/doc](docs/CODE_DOC_RECONCILIATION.md)** : Alignement réel
- **[Guide CLI](docs/CLI_GUIDE.md)** : Toutes les commandes expliquées
- **[Tests E2E](crates/network/tests/README_E2E.md)** : Scénarios et orchestration

## 🤝 Contribution

Le projet suit des standards stricts :
- TDD obligatoire pour nouvelles fonctionnalités
- Clippy pedantic + nursery compliance
- Tests d'intégration pour toute API publique  
- Documentation complète des interfaces

Voir [CONTRIBUTING.md](docs/CONTRIBUTING.md) pour les détails.

## 📄 Licence

Dual licensed MIT OR Apache-2.0 - voir [LICENSE](LICENSE) pour détails.

---

**Miaou v0.2.0 "Radar Moustaches" - Base technique solide pour P2P sécurisé 🐾**