# GitHub Configuration

Ce dossier contient la configuration GitHub pour le projet Miaou, incluant les workflows CI/CD, les templates d'issues et de pull requests, et la configuration Dependabot.

## 🔧 Workflows CI/CD

### `ci.yml` - Pipeline principal
**Statut**: ✅ Implémenté et optimisé pour issue #12

Le workflow principal exécute :
- **Format Check** : Vérification du formatage avec `cargo fmt`
- **Clippy Lints** : Analyse statique avec `cargo clippy` (zéro warning toléré)
- **Tests** : Tests multi-plateformes (Ubuntu, Windows, macOS) avec Rust stable, beta et nightly
- **Build Check** : Compilation dev et release pour validation
- **Coverage** : Analyse de couverture avec `cargo-tarpaulin` (Linux uniquement)

**Triggers** :
- Push sur `main` et branches `v0.*` (ignore fichiers `.md`)
- Pull requests vers `main` et branches `v0.*` (ignore fichiers `.md`)

**Optimisations** :
- Concurrency avec cancel-in-progress pour éviter les runs dupliqués
- Permissions minimales (contents: read)
- Cache Rust pour accélérer les builds
- Timeouts configurés (30min tests, 20min coverage)
- Échec non-critique pour Rust nightly
- Garde-fou `hashFiles('**/Cargo.toml')` pour repos non-Rust

### `security-audit.yml` - Audit de sécurité
**Statut**: ✅ Implémenté et sécurisé pour issue #12

Audit de sécurité automatique :
- Exécution hebdomadaire (dimanche 02:00 UTC)
- Déclenchement sur changements `Cargo.toml`/`Cargo.lock`
- Utilise `cargo-audit` pour scanner les vulnérabilités
- Rapport JSON détaillé des problèmes trouvés
- Permissions minimales (contents: read, security-events: write)

### `dependency-review.yml` - Review des dépendances
**Statut**: ✅ Nouveau workflow ajouté

Review automatique des dépendances sur les PR :
- Analyse les changements de dépendances
- Commente directement dans la PR
- Mode warning pour ne pas bloquer le développement

### `cargo-deny.yml` - Analyse approfondie des dépendances
**Statut**: ✅ Nouveau workflow ajouté

Analyse complète avec cargo-deny :
- Vérification des licences acceptées
- Détection des dépendances dupliquées
- Scan des vulnérabilités connues
- Exécution hebdomadaire et sur changements

## 🤖 Dependabot

### `dependabot.yml` - Mise à jour des dépendances
**Statut**: ✅ Implémenté pour issue #12

Configuration automatisée :
- **Cargo** : Mise à jour hebdomadaire des dépendances Rust (dimanche 04:00)
- **GitHub Actions** : Mise à jour des actions utilisées (dimanche 04:30)
- Limite de 10 PR Cargo + 5 PR Actions ouvertes simultanément
- Auto-assignation et labeling des PR

## 📝 Templates

### Issues Templates
- **Bug Report** (`bug_report.yml`) : Formulaire structuré pour signaler des bugs
- **Feature Request** (`feature_request.yml`) : Formulaire pour proposer des fonctionnalités

**Champs obligatoires** :
- Description détaillée
- Étapes de reproduction (bugs)
- Environnement (OS, versions Rust/Cargo/Miaou)
- Priorité et domaine concerné

### Pull Request Template
- **`pull_request_template.md`** : Template complet avec checklist
- Catégorisation des changements (bug fix, feature, breaking change)
- Checklist qualité (tests, documentation, performances)
- Référencement automatique des issues

## 🚦 Critères d'acceptation

Pour que le CI passe, une PR doit :
1. ✅ **Format** : `cargo fmt --check` sans erreurs
2. ✅ **Lints** : `cargo clippy` sans warnings (`-D warnings`)
3. ✅ **Tests** : Tous les tests passent sur 3 OS
4. ✅ **Build** : Compilation réussie en dev et release
5. ✅ **Documentation** : Doctests passent
6. ✅ **Sécurité** : Pas de vulnérabilités détectées

## 📊 Métriques et monitoring

### Couverture de code
- **Outil** : `cargo-tarpaulin`
- **Cible** : Maintenir > 90% de couverture
- **Upload** : Codecov pour tracking historique
- **Exclusions** : Tests, benches, target/

### Badges de statut
À ajouter dans le README principal :
```markdown
[![CI](https://github.com/yrbane/miaou/workflows/CI/badge.svg)](https://github.com/yrbane/miaou/actions/workflows/ci.yml)
[![Security Audit](https://github.com/yrbane/miaou/workflows/Security%20Audit/badge.svg)](https://github.com/yrbane/miaou/actions/workflows/security-audit.yml)
[![codecov](https://codecov.io/gh/yrbane/miaou/branch/main/graph/badge.svg)](https://codecov.io/gh/yrbane/miaou)
```

## 🔄 Workflow de développement recommandé

1. **Créer une branche** : `feature/issue-XX-description`
2. **Développer** : Implémenter en suivant TDD
3. **Tester localement** : `cargo fmt && cargo clippy && cargo test`
4. **Push** : Le CI validera automatiquement
5. **Pull Request** : Utiliser le template, référencer l'issue
6. **Review** : Attendre validation CI + review humaine
7. **Merge** : Squash and merge recommandé

## 🛠️ Développement local

### Commandes rapides
```bash
# Validation complète locale (simule CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings  
cargo test --workspace --all-features
cargo build --workspace --all-features --release

# Audit de sécurité
cargo install cargo-audit
cargo audit

# Couverture de code
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --all-features --timeout 300
```

### Pre-commit hooks
_Note : Le script `scripts/pre-commit.sh` n'est pas inclus dans ce dépôt. Pour reproduire les validations CI localement, utilisez les commandes listées ci-dessus dans la section "Commandes rapides"._

---
*Configuration CI créée pour résoudre l'issue #12 - GitHub Actions pipeline standard*