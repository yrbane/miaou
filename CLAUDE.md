# 🤖 Claude Code - Configuration et historique du projet Miaou

Ce fichier documente la configuration et les préférences pour le développement du projet Miaou avec Claude Code.

## 🎯 Contexte du projet

**Miaou v0.1.0 "Première Griffe"** est une bibliothèque cryptographique Rust avec les caractéristiques suivantes :

### Architecture workspace moderne
- **4 crates** : `core`, `crypto`, `keyring`, `cli`
- **54 tests** avec **95.5% de couverture**
- **Pipeline CI/CD unifié** GitHub Actions
- **Support multi-plateformes** : Desktop, WebAssembly, Android

### Standards de qualité exceptionnels
- **Clippy pedantic + nursery compliance** stricte
- **Documentation exhaustive** avec `# Errors` et `# Panics`
- **Zéro `unsafe`** avec `#![forbid(unsafe_code)]`
- **Seuil minimum 90%** de couverture de tests

## ⚙️ Préférences de développement

### Commandes favorites
```bash
# Build complet du workspace
cargo build --workspace

# Tests avec couverture
cargo test --workspace --all-features

# Linting strict complet
cargo clippy --all-features --all-targets -- -D warnings -D clippy::pedantic -D clippy::nursery -D clippy::cargo -A clippy::multiple_crate_versions -A clippy::cargo_common_metadata

# Builds spécialisés
cargo build --target wasm32-unknown-unknown --profile release-wasm --lib
cargo build --target i686-linux-android --profile release-mobile -p miaou-cli
```

### Standards appliqués
- **TDD obligatoire** : Tous les nouveaux features doivent avoir des tests
- **Documentation complète** : Toutes les APIs publiques documentées
- **Gestion d'erreurs explicite** : Pas de `.unwrap()` dans le code de production
- **Sécurité par design** : Zeroization des données sensibles, validation stricte

## 🏗️ Architecture du workspace

```
crates/
├── core/                   # Types communs, erreurs, données sensibles
│   └── src/lib.rs         # SensitiveBytes, MiaouError, IntoMiaouError
├── crypto/                 # Primitives cryptographiques
│   └── src/lib.rs         # AeadCipher, Signer, implémentations
├── keyring/                # Gestion de clés
│   └── src/lib.rs         # KeyStore, MemoryKeyStore  
└── cli/                    # Interface ligne de commande
    └── src/main.rs        # CLI complète avec toutes les commandes
```

## 🔧 Configuration technique

### Profiles Cargo optimisés
- **release-wasm** : `opt-level = "s"`, LTO, panic = abort (pour WebAssembly)
- **release-mobile** : `opt-level = "z"`, LTO, strip = true (pour Android)

### Dependencies clés
- **Cryptographie** : `chacha20poly1305`, `ed25519-dalek`, `blake3[pure]`
- **Sérialisation** : `serde`, `serde_bytes` pour KeyEntry
- **CLI** : `clap` avec derive macros
- **Cross-platform** : `getrandom[js]` pour WebAssembly

## 📋 Checklist développement

Avant chaque commit, vérifier :
- [ ] `cargo build --workspace` passe
- [ ] `cargo test --workspace` passe (54 tests)
- [ ] `cargo clippy` strict passe sans warnings
- [ ] `cargo fmt --check` passe
- [ ] Couverture ≥ 90% maintenue
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
- Tous les tests passent sur toutes plateformes
- Couverture ≥ 90% validée automatiquement
- Zero tolerance pour warnings Clippy strict
- Audit sécurité sans vulnérabilités

## 📝 Historique des sessions

### Session finale - Refactoring et nettoyage
**Date** : Session courante
**Objectifs** :
- ✅ Résoudre problème linker Android NDK dans CI/CD
- ✅ Fusionner tous les workflows GitHub Actions en pipeline unifié
- ✅ Nettoyer architecture : supprimer fichiers `src/` obsolètes
- ✅ Refactoring complet et mise à jour documentation

**Réalisations** :
- Pipeline CI/CD unifié et optimisé dans `ci-cd.yml`
- Suppression de l'ancienne architecture (`src/`, `miaou-*/` racine)
- README complètement réécrit et précis
- Architecture workspace pure et moderne

### Sessions précédentes
- **Couverture de tests** : 95.5% atteinte avec TDD systématique
- **Compliance Clippy** : Pedantic + nursery + cargo stricte
- **Support multi-plateformes** : WebAssembly et Android
- **Qualité code** : 54 tests, documentation exhaustive

## 🎯 Prochaines étapes possibles

Pour les futures sessions de développement :

1. **Communication P2P** : Ajout de primitives réseau
2. **Persistence** : Backend de stockage chiffré
3. **Interfaces graphiques** : Applications desktop/mobile
4. **Performance** : Optimisations et benchmarks avancés

## 💡 Notes pour Claude

- **Toujours respecter** les standards de qualité établis
- **Privilégier** l'architecture modulaire et les tests
- **Maintenir** la compatibilité multi-plateformes
- **Documenter** toutes les APIs publiques
- **Valider** avec le pipeline CI/CD complet

---

*Généré automatiquement par Claude Code - Configuration mise à jour lors du refactoring final*