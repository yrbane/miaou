# Workflow Git et Stratégie de Branches

## Vue d'ensemble

Le projet Miaou utilise une stratégie de branches basée sur les versions pour structurer le développement selon la roadmap définie. Chaque version majeure dispose de sa propre branche de développement avec des règles strictes de validation.

## Structure des branches

### Branches principales

```
main (production)
├── v0.1.0-premiere-griffe (développement Phase 1)
├── v0.2.0-radar-moustaches (développement Phase 2)  
├── v0.3.0-ronron-bonheur (développement Phase 3)
├── v0.4.0-toilettage-royal (développement Phase 4)
├── v0.5.0-chat-gouttiere (développement Phase 5)
├── v0.6.0-neuf-vies (développement Phase 6)
└── v1.0.0-matou-majestueux (développement Phase 7)
```

### Branches de fonctionnalités

```
v0.1.0-premiere-griffe
├── feature/crypto-primitives
├── feature/keyring-management
├── feature/encryption-layer
├── feature/signature-system
└── feature/hashing-wrappers
```

## Règles de développement par version

### Phase 1 - v0.1.0-premiere-griffe
**Objectif :** Fondations cryptographiques et architecture modulaire

**Critères de validation avant commit :**
- [ ] Tests unitaires >= 90% de couverture
- [ ] Tests cryptographiques KAT validés
- [ ] Fuzzing sans erreurs sur 1M+ inputs
- [ ] Documentation rustdoc complète
- [ ] Linting clippy::pedantic sans warnings
- [ ] Benchmarks de performance < baselines
- [ ] Architecture SOLID respectée

**Commandes de validation :**
```bash
# Tests complets
cargo test --all-features
cargo test --doc

# Couverture de code
cargo tarpaulin --verbose --all-features --timeout 120

# Tests cryptographiques 
cargo test crypto::tests::known_answer_tests
cargo test crypto::tests::property_tests

# Fuzzing (minimum 1M iterations)
cargo fuzz run crypto_primitives -- -runs=1000000

# Documentation
cargo doc --all-features --no-deps --document-private-items

# Linting
cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic

# Benchmarks
cargo bench
```

### Phase 2 - v0.2.0-radar-moustaches
**Objectif :** Réseau P2P et communication décentralisée

**Critères additionnels :**
- [ ] Tests d'intégration réseau
- [ ] Tests de latence < 100ms P2P direct
- [ ] Tests de connectivité NAT traversal
- [ ] Simulation de pannes réseau
- [ ] Validation protocoles WebRTC/STUN/TURN

### Phase 3 - v0.3.0-ronron-bonheur
**Objectif :** Économie et gamification

**Critères additionnels :**
- [ ] Tests économiques avec simulations
- [ ] Validation anti-spam mechanisms
- [ ] Tests de charge blockchain locale
- [ ] Audit de sécurité économique

### Phase 4 - v0.4.0-toilettage-royal
**Objectif :** Interfaces utilisateur multi-plateforme

**Critères additionnels :**
- [ ] Tests d'accessibilité WCAG 2.1 AA
- [ ] Tests cross-platform (desktop/mobile/web)
- [ ] Tests de performance UI/UX
- [ ] Validation synchronisation cross-device
- [ ] Tests compilation mobile (Android/iOS)

### Phases 5-7
**Critères similaires avec spécificités par phase**

## Processus de développement

### 1. Création d'une branche de version

```bash
# Créer et passer sur la branche de version
git checkout -b v0.1.0-premiere-griffe main
git push -u origin v0.1.0-premiere-griffe

# Mettre à jour Cargo.toml pour la version
# Exemple: version = "0.1.0-dev"
```

### 2. Développement de fonctionnalités

```bash
# Créer une branche de fonctionnalité
git checkout -b feature/crypto-primitives v0.1.0-premiere-griffe

# Développement avec commits fréquents
git add .
git commit -m "feat(crypto): implement ChaCha20-Poly1305 wrapper

- Add ChaCha20-Poly1305 encryption interface
- Integrate with ring crate for performance
- Add comprehensive tests with NIST vectors
- Document security properties and usage"

# Push de la fonctionnalité
git push -u origin feature/crypto-primitives
```

### 3. Validation pré-commit obligatoire

Avant chaque commit, exécuter automatiquement :

```bash
#!/bin/bash
# .git/hooks/pre-commit (sera automatisé)

echo "🧪 Validation des tests..."
cargo test --all-features || exit 1

echo "📊 Vérification de la couverture..."
COVERAGE=$(cargo tarpaulin --output Stdout | grep -oP '\d+\.\d+(?=%)')
if (( $(echo "$COVERAGE < 90" | bc -l) )); then
    echo "❌ Couverture insuffisante: $COVERAGE% (minimum 90%)"
    exit 1
fi

echo "🔍 Linting du code..."
cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic || exit 1

echo "📚 Génération de la documentation..."
cargo doc --all-features --no-deps --document-private-items || exit 1

echo "🏃 Tests de performance..."
cargo bench --bench crypto_benchmarks || exit 1

echo "✅ Validation réussie !"
```

### 4. Pull Request et revue

```bash
# Créer une PR vers la branche de version
gh pr create \
  --base v0.1.0-premiere-griffe \
  --title "feat(crypto): implement ChaCha20-Poly1305 wrapper" \
  --body "$(cat <<EOF
## Résumé
Implementation of ChaCha20-Poly1305 encryption wrapper with ring integration.

## Changements
- [x] ChaCha20-Poly1305 interface implementation
- [x] Integration with audited ring crate
- [x] Comprehensive test suite with NIST vectors
- [x] Performance benchmarks
- [x] Complete rustdoc documentation

## Validation
- [x] Tests: 94.2% coverage (> 90% required)
- [x] Fuzzing: 1M+ iterations without errors
- [x] Benchmarks: Encryption 1.2GB/s (baseline: 1GB/s)
- [x] Documentation: 100% public APIs documented
- [x] Linting: No warnings with clippy::pedantic

## Breaking changes
None - New functionality only.
EOF
)"
```

### 5. Merge et release

```bash
# Après validation PR, merge dans la branche de version
git checkout v0.1.0-premiere-griffe
git merge feature/crypto-primitives
git tag v0.1.0-alpha.1
git push origin v0.1.0-premiere-griffe --tags

# Quand la version est complète, merge vers main
git checkout main
git merge v0.1.0-premiere-griffe
git tag v0.1.0
git push origin main --tags
```

## Templates de documentation

### Template README.md de version
```markdown
# Miaou v0.1.0 "Première Griffe"

## Status: [EN DÉVELOPPEMENT | ALPHA | BETA | STABLE]

## Fonctionnalités implémentées
- [x] Crypto primitives (ChaCha20-Poly1305, Ed25519)
- [x] Keyring management
- [ ] Signature system (en cours)
- [ ] Hashing wrappers

## Installation et usage
\`\`\`bash
git checkout v0.1.0-premiere-griffe
cargo build --release --all-features
./target/release/miaou-cli --help
\`\`\`

## Documentation technique
- [Rustdoc](./target/doc/miaou/index.html)
- [Spécifications](../versions/v0.1.0-premiere-griffe.md)
- [Benchmarks](./benchmarks/v0.1.0-results.md)

## Métriques qualité
- **Tests:** 94.2% coverage
- **Performance:** Encryption 1.2GB/s  
- **Sécurité:** Fuzzing 10M+ iterations
- **Documentation:** 100% APIs publiques
```

### Template rustdoc

```rust
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/yrbane/miaou/main/assets/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/yrbane/miaou/main/assets/favicon.ico"
)]

//! # Miaou v0.1.0 "Première Griffe"
//! 
//! ## Vue d'ensemble
//! 
//! Cette version établit les fondations cryptographiques et l'architecture modulaire
//! de Miaou, une messagerie décentralisée sécurisée.
//! 
//! ## Modules principaux
//! 
//! - [`crypto`] - Primitives cryptographiques auditées
//! - [`keyring`] - Gestion sécurisée des clés
//! - [`network`] - Communication P2P (Phase 2)
//! - [`storage`] - Stockage local chiffré
//! 
//! ## Exemples d'usage
//! 
//! ```rust
//! use miaou::crypto::ChaCha20Poly1305;
//! 
//! let key = ChaCha20Poly1305::generate_key()?;
//! let ciphertext = key.encrypt(b"Hello, Miaou!", b"unique_nonce")?;
//! let plaintext = key.decrypt(&ciphertext, b"unique_nonce")?;
//! ```
//! 
//! ## Sécurité
//! 
//! - **Chiffrement:** ChaCha20-Poly1305 (authenticated encryption)
//! - **Signatures:** Ed25519 (high-performance elliptic curves)
//! - **Hashing:** BLAKE3, SHA-3, Argon2 (password hashing)
//! - **Audit:** Utilise exclusivement des crates auditées (ring, RustCrypto)
```

## Configuration CI/CD

### GitHub Actions workflow

```yaml
# .github/workflows/version-validation.yml
name: Version Validation

on:
  push:
    branches: [ 'v*.*.*-*' ]  # Branches de version
  pull_request:
    branches: [ 'v*.*.*-*' ]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust toolchain
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        components: clippy, rustfmt
        
    - name: Run comprehensive tests
      run: |
        cargo test --all-features --verbose
        cargo test --doc
        
    - name: Check code coverage
      run: |
        cargo tarpaulin --all-features --out Xml
        if [ "$(grep -oP 'line-rate="\K[^"]*' cobertura.xml | head -1 | awk '{print $1*100}')" -lt 90 ]; then
          echo "Coverage below 90%"
          exit 1
        fi
        
    - name: Lint code
      run: cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic
      
    - name: Generate documentation
      run: cargo doc --all-features --no-deps --document-private-items
      
    - name: Run benchmarks
      run: cargo bench
      
    - name: Security audit
      run: |
        cargo install cargo-audit
        cargo audit
```

Cette stratégie garantit un développement structuré, une qualité constante et une traçabilité complète pour chaque version de Miaou.