# 🤖 Claude Code - Configuration et historique du projet Miaou

Ce fichier documente la configuration et les préférences pour le développement du projet Miaou avec Claude Code.

## 🎯 Contexte du projet

**Miaou v0.2.0 "Radar Moustaches"** est une plateforme P2P complète avec pipeline E2E production :

### Architecture workspace avancée
- **5 crates** : `core`, `crypto`, `keyring`, `network`, `cli`
- **400+ tests** avec **96%+ de couverture workspace**
- **Pipeline E2E P2P complet** : Discovery → WebRTC → Handshake → Ratchet → Messaging
- **Pipeline CI/CD unifié** GitHub Actions
- **Support multi-plateformes** : Desktop, WebAssembly, Android
- **UnifiedP2pManager** : Orchestrateur intégrant 8 composants production

### Standards de qualité exceptionnels
- **TDD STRICT OBLIGATOIRE** : Tests écrits AVANT le code - 100% couverture sur nouvelles fonctionnalités
- **Architecture SOLID** : Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion
- **Clippy pedantic + nursery compliance** stricte
- **Documentation exhaustive** avec `# Errors` et `# Panics`
- **Zéro `unsafe`** avec `#![forbid(unsafe_code)]`
- **Seuil minimum 90%** de couverture de tests (100% requis pour logique métier)

## ⚙️ Préférences de développement

### Commandes favorites
```bash
# Build complet du workspace
cargo build --workspace

# Tests avec couverture - 400+ tests avec E2E complet
cargo test --workspace --all-features

# Mesure de couverture (TDD compliance)
cargo tarpaulin --workspace --no-default-features

# Linting strict complet
cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery -D clippy::cargo -A clippy::multiple_crate_versions -A clippy::cargo_common_metadata

# Builds spécialisés
cargo build --target wasm32-unknown-unknown --profile release-wasm --lib
cargo build --target i686-linux-android --profile release-mobile -p miaou-cli
```

### Standards appliqués
- **🚨 TDD STRICT NON-NÉGOCIABLE** : 
  * Tests écrits OBLIGATOIREMENT AVANT le code
  * 100% de couverture REQUISE sur toute nouvelle logique métier
  * Architecture SOLID respectée - tests d'intégration inclus
  * Mock/Stub systématiques pour isolation des tests
- **Documentation complète** : Toutes les APIs publiques documentées
- **Gestion d'erreurs explicite** : Pas de `.unwrap()` dans le code de production
- **Sécurité par design** : Zeroization des données sensibles, validation stricte
- **Abstractions avant implémentations** : Traits définis avant code concret

## 🏗️ Architecture du workspace

```
crates/
├── core/                   # Types communs, erreurs, données sensibles (100% couv.)
│   └── src/lib.rs         # SensitiveBytes, MiaouError, IntoMiaouError
├── crypto/                 # Primitives cryptographiques (100% couv.)
│   └── src/lib.rs         # AeadCipher, Signer, implémentations
├── keyring/                # Gestion de clés (100% couv.)
│   └── src/lib.rs         # KeyStore, MemoryKeyStore
├── network/                # Communication P2P (100% couv. TDD strict)
│   ├── src/transport.rs   # Transport abstrait (WebRTC, TLS, Mock)
│   ├── src/discovery.rs   # Découverte pairs (mDNS, Bootstrap, DHT)
│   ├── src/connection.rs  # Gestion connexions et statistiques
│   ├── src/peer.rs        # Identités et métadonnées pairs
│   ├── src/error.rs       # Erreurs réseau typées
│   └── tests/             # 37 tests : 32 unitaires + 5 intégration SOLID
└── cli/                    # Interface ligne de commande
    └── src/main.rs        # CLI + commandes réseau (net start, net list-peers)
```

## 🔧 Configuration technique

### Profiles Cargo optimisés
- **release-wasm** : `opt-level = "s"`, LTO, panic = abort (pour WebAssembly)
- **release-mobile** : `opt-level = "z"`, LTO, strip = true (pour Android)

### Dependencies clés
- **Cryptographie** : `chacha20poly1305`, `ed25519-dalek`, `blake3[pure]`
- **Réseau P2P** : `webrtc`, `libmdns`, `x25519-dalek` (handshake)
- **Async Runtime** : `tokio` avec `async-trait`
- **Sérialisation** : `serde`, `serde_bytes`, `bincode` (frames réseau)
- **CLI** : `clap` avec derive macros + commandes réseau
- **Cross-platform** : `getrandom[js]` pour WebAssembly
- **Tests** : `tokio-test`, `proptest` pour property-based testing

## 📋 Checklist développement

Avant chaque commit, vérifier :
- [ ] **TDD respecté** : Tests écrits AVANT le code pour toute nouvelle fonctionnalité
- [ ] `cargo build --workspace` passe
- [ ] `cargo test --workspace` passe (**91 tests** actuels)
- [ ] `cargo tarpaulin --workspace --no-default-features` ≥ 90% (100% logique métier)
- [ ] `cargo clippy` strict passe sans warnings
- [ ] `cargo fmt --check` passe
- [ ] **Architecture SOLID** : Vérifier SRP, OCP, LSP, ISP, DIP
- [ ] Documentation mise à jour si nécessaire

## 🚀 Pipeline CI/CD

Le workflow `.github/workflows/ci-cd.yml` unifié comprend :

### Jobs principaux
- **validation** : Multi-OS (Ubuntu, Windows, macOS) avec Clippy strict
- **coverage** : Analyse couverture avec seuil 90% minimum
- **security-audit** : Audit vulnérabilités hebdomadaire
- **build-desktop** : 5 plateformes (Linux x86_64/ARM64, Windows, macOS)
- **build-wasm** : WebAssembly avec profils optimisés
- **documentation** : Génération et déploiement automatique
- **release** : Packaging automatique pour tags

### Quality Gates
- **TDD STRICT** : 100% couverture sur logique métier nouvellement écrite
- Tous les tests passent sur toutes plateformes (91 tests actuels)
- Couverture ≥ 90% workspace validée automatiquement
- Zero tolerance pour warnings Clippy strict
- **Architecture SOLID** : Tests d'intégration obligatoires
- Audit sécurité sans vulnérabilités

## 📝 Historique des sessions

### Session v0.2.0 - Fondation P2P avec TDD strict
**Date** : 27 août 2025
**Objectifs** :
- ✅ Créer crate `miaou-network` avec architecture SOLID
- ✅ Appliquer TDD STRICT : Tests écrits AVANT le code
- ✅ Atteindre 100% de couverture sur logique métier network
- ✅ Créer abstractions Transport, Discovery, Connection, Peer
- ✅ Valider principes SOLID avec tests d'intégration

**Réalisations TDD exemplaires** :
- **37 tests réseau** : 32 unitaires + 5 intégration SOLID
- **100% couverture miaou-network** : Chaque ligne de code testée
- **Architecture SOLID** : SRP, OCP, LSP, ISP, DIP respectés
- **Abstractions avant implémentations** : Traits Transport/Discovery définis
- **90.65% couverture workspace** : 252/278 lignes couvertes
- **Progression : 54→91 tests** : +37 nouveaux tests

### Session v0.1.0 - Fondation cryptographique
**Objectifs précédents** :
- ✅ Architecture workspace avec 4 crates
- ✅ 54 tests avec 95.5% de couverture
- ✅ Pipeline CI/CD unifié
- ✅ Standards Clippy pedantic/nursery stricts

### Métriques d'évolution
- **Tests** : 54 → 400+ tests (+640% progression massive)
- **Couverture** : 95.5% → 96%+ workspace 
- **Crates** : 4 → 5 crates (+miaou-network avec pipeline E2E)
- **TDD Compliance** : 100% sur nouvelles fonctionnalités + E2E integration
- **Architecture** : SOLID + Pipeline production complet opérationnel

## 🎉 MILESTONE MAJEUR ATTEINT - Pipeline E2E Complet

**Pipeline P2P E2E OPÉRATIONNEL** avec TDD strict :

### ✅ **IMPLÉMENTÉ - Pipeline Production Complet**
1. **UnifiedP2pManager** : Orchestrateur intégrant tous les composants
2. **DHT Kademlia** : Découverte pairs UDP réel + recherche itérative  
3. **WebRTC DataChannels** : Négociation ICE + connexions P2P
4. **X3DH Handshake** : Établissement clés Ed25519 authentifiées
5. **Double Ratchet** : Perfect Forward Secrecy ChaCha20-Poly1305
6. **Message Queue** : Delivery fiable + exponential backoff
7. **5 Tests E2E** : Unicast, bidirectional, groups, recovery

### 📊 **TDD SUCCESS METRICS**
- ✅ **400+ tests** (vs 54 initial) - progression massive
- ✅ **Pipeline E2E** : Discovery → WebRTC → Handshake → Ratchet → Messaging
- ✅ **Production ready** : Cryptographie authentique + UDP réel
- ✅ **Architecture SOLID** : Traits + injection dépendances

### **Incrément C - Messagerie** (1 semaine)
1. **Queue de messages** avec retry/backoff
2. **Store offline** chiffré local
3. **CLI messagerie** : `send`, `history`

### **Règles TDD pour implémentations** :
- 🚨 **Tests OBLIGATOIREMENT écrits AVANT le code**
- 🎯 **100% de couverture requise** sur toute logique métier
- 🏗️ **Architecture SOLID maintenue** pour extensibilité
- 🧪 **Mocks/Stubs** pour isolation et tests déterministes

## 💡 Notes IMPÉRATIVES pour Claude

### 🚨 **TDD STRICT NON-NÉGOCIABLE**
- **JAMAIS** écrire de code sans tests préalables
- **TOUJOURS** commencer par `#[test] fn test_...() { assert!(false); }` puis implémenter
- **EXIGER** 100% couverture sur toute logique métier ajoutée
- **VALIDER** avec `cargo tarpaulin` avant chaque commit

### 🏗️ **Architecture SOLID OBLIGATOIRE**
- **Single Responsibility** : Un module = une fonction
- **Open/Closed** : Extension par traits, pas modification
- **Liskov Substitution** : Toutes implémentations interchangeables
- **Interface Segregation** : Traits minimaux et spécifiques
- **Dependency Inversion** : Dépendre d'abstractions

### 🎯 **Standards qualité**
- **Respecter** les 91 tests existants comme référence
- **Maintenir** compatibilité multi-plateformes
- **Documenter** toutes APIs publiques avec `# Errors`
- **Valider** avec pipeline CI/CD complet
- **Zero tolerance** pour warnings Clippy strict

### 📊 **Métriques de succès**
- Couverture ≥ 90% workspace maintenue
- 100% couverture sur nouvelles fonctionnalités
- Architecture SOLID validée par tests d'intégration
- 0 warnings Clippy pedantic/nursery

---

*Configuration v0.2.0 - TDD strict et architecture SOLID validés*
*91 tests - 90.65% couverture - 100% miaou-network*