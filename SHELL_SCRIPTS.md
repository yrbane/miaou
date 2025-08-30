# 🐚 Scripts Shell Miaou v0.2.0

Ce document référence tous les scripts shell utiles du projet Miaou, leur utilité et leur statut pour la version v0.2.0 "Radar Moustaches".

## 📊 Vue d'ensemble

Le projet contient **11 scripts shell** répartis dans différentes catégories :
- **Production/Qualité** : Scripts de refactoring et hardening
- **Tests E2E** : Scripts de validation fonctionnelle 
- **Build/Déploiement** : Scripts de compilation multi-plateforme
- **Git/Workflow** : Configuration des hooks et pre-commit

## 🎯 Scripts utiles à conserver

### Production et Qualité

#### 1. `refactor.sh` (racine) ⭐
**Utilité** : Script de refactoring et hardening complet pour la phase v0.2.0
**Statut** : **ESSENTIEL - À CONSERVER**
- **167 lignes** de pipeline qualité complete
- Toolchain validation, formatting (rustfmt, taplo, cargo-sort)
- Security audits (cargo-audit, cargo-deny)
- Tests complets (unit, integration, doctests)
- Coverage avec tarpaulin (HTML/XML)
- Mutation testing avec mutants
- Release build sanity check
- Installation automatique pre-commit hook
**Usage** : `./refactor.sh` avant chaque milestone

#### 2. `scripts/refactor.sh` 
**Utilité** : Version dans /scripts/ (quasi-identique à la version racine)
**Statut** : **DOUBLON - CANDIDAT À SUPPRESSION**
- **140 lignes** similaires à la version racine
- Moins de commentaires et documentation
**Recommandation** : Garder seulement la version racine plus complète

#### 3. `scripts/hardening.sh` ⭐
**Utilité** : Script avancé de hardening avec gestion workspace
**Statut** : **TRÈS UTILE - À CONSERVER**
- **323 lignes** de hardening approfondi
- Gestion `[workspace.package]` automatique
- Héritage des métadonnées entre crates
- Lints forts automatiques dans lib.rs
- Installation optionnelle d'outils (`--install-tools`)
**Usage** : `./scripts/hardening.sh --install-tools`

### Tests End-to-End

#### 4. `test_e2e_dht.sh` ⭐
**Utilité** : Tests production DHT avec put/get d'annuaire distribué
**Statut** : **ESSENTIEL - À CONSERVER**
- **139 lignes** de validation DHT complète
- Tests commandes `dht-put` et `dht-get` réelles
- Validation format hex des clés (8 bytes)
- Statistiques publications/recherches
- Vérifications sans crash WebRTC
**Usage** : `./test_e2e_dht.sh`

#### 5. `test_e2e_messaging.sh` ⭐
**Utilité** : Tests messaging avec 2 instances CLI réelles
**Statut** : **ESSENTIEL - À CONSERVER**
- **125 lignes** de validation messaging complète
- Instances séparées Alice/Bob avec persistance
- Validation stores JSON independants
- Tests commandes `send`/`recv` production
- Isolation `MIAOU_STORAGE` par instance
**Usage** : `./test_e2e_messaging.sh`

#### 6. `test_e2e_net_connect.sh` ⭐
**Utilité** : Tests parcours complet mDNS → WebRTC
**Statut** : **ESSENTIEL - À CONSERVER**
- **209 lignes** de validation réseau complète
- Parcours `net-start` → `net-list-peers` → `net-connect`
- Découverte mDNS fonctionnelle
- Tentatives connexion WebRTC avec timeouts
- Gestion adresses IP LAN (non-loopback)
- Retry automatique et performance metrics
**Usage** : `./test_e2e_net_connect.sh`

#### 7. `test_mdns_demo.sh` ⭐
**Utilité** : Démonstration découverte mDNS mutuelle
**Statut** : **UTILE - À CONSERVER**
- **78 lignes** de démo simple mDNS
- 2 instances simultanées avec découverte mutuelle
- Intégration avec `avahi-browse` système
- Tests `net-list-peers` en conditions réelles
**Usage** : `./test_mdns_demo.sh`

### Build et Déploiement

#### 8. `scripts/build-targets.sh` ⭐
**Utilité** : Build multi-plateforme automatisé
**Statut** : **TRÈS UTILE - À CONSERVER**
- **267 lignes** de build système complet
- Support 3 catégories : desktop, mobile, WASM
- **11 targets** : Linux, Windows, macOS, Android, iOS, WebAssembly
- Gestion profils spécialisés (`release-mobile`, `release-wasm`)
- Packaging automatique (tar.gz, zip)
- Tests optionnels par target
**Usage** : `./scripts/build-targets.sh all --test`

### Git et Workflow

#### 9. `scripts/pre-commit.sh` ⭐
**Utilité** : Hook pre-commit avancé avec validations complètes
**Statut** : **EXCELLENT - À CONSERVER**
- **318 lignes** de validation pre-commit exhaustive
- Formatage automatique (rustfmt)
- Clippy strict avec configuration Miaou
- Tests unitaires + documentation
- Coverage minimum 90% avec tarpaulin
- Tests cryptographiques spécialisés (KAT)
- Security audit automatique
- Vérifications par phase de développement
- Support compilation mobile (Android/iOS)
**Usage** : Installé automatiquement comme hook git

#### 10. `scripts/setup-git-hooks.sh` 
**Utilité** : Configuration automatique des hooks git
**Statut** : **UTILE - À CONSERVER**
- **91 lignes** de setup hooks
- Installation pre-commit hook
- Configuration git recommandée
- Tests de fonctionnement des hooks
**Usage** : `./scripts/setup-git-hooks.sh`

## 🗑️ Scripts obsolètes à supprimer

### Doublons identifiés

#### `scripts/refactor.sh.bak`
**Statut** : **FICHIER BACKUP - SUPPRESSION RECOMMANDÉE**
- Sauvegarde automatique générée par le script hardening.sh
- Contenu identique à l'ancienne version de refactor.sh

## 📋 Scripts utilitaires mineurs

### Dans /scripts/

#### `fix_regex_dups.sh`
**Utilité** : Script de correction des doublons regex (spécifique)
**Statut** : **CONTEXTE SPÉCIFIQUE - ÉVALUATION REQUISE**
- Probablement utilisé lors du développement
- Peut être supprimé si plus d'usage

#### `generate_glossary_html.py` (Python)
**Utilité** : Génération HTML du glossaire depuis Markdown
**Statut** : **UTILE - À CONSERVER**
- Génère `glossaire.html` depuis `GLOSSAIRE.md`
- Utile pour documentation web

## 🏆 Classement par priorité

### Priorité 1 - ESSENTIELS (garder absolument)
1. **`refactor.sh`** - Pipeline qualité complet v0.2.0
2. **`test_e2e_dht.sh`** - Validation DHT production
3. **`test_e2e_messaging.sh`** - Validation messaging production  
4. **`test_e2e_net_connect.sh`** - Validation réseau mDNS+WebRTC
5. **`scripts/pre-commit.sh`** - Hook validation exhaustif
6. **`scripts/build-targets.sh`** - Build multi-plateforme
7. **`scripts/hardening.sh`** - Hardening workspace avancé

### Priorité 2 - UTILES (garder)
8. **`test_mdns_demo.sh`** - Démo mDNS simple
9. **`scripts/setup-git-hooks.sh`** - Setup hooks git
10. **`generate_glossary_html.py`** - Documentation web

### Priorité 3 - À SUPPRIMER
11. **`scripts/refactor.sh`** - Doublon de la version racine
12. **`scripts/refactor.sh.bak`** - Fichier backup
13. **`scripts/fix_regex_dups.sh`** - Usage spécifique fini

## 💡 Recommandations finales

### Actions immédiates
- ✅ **Conserver 8 scripts essentiels/utiles**
- 🗑️ **Supprimer 3 scripts obsolètes/doublons**
- 📝 **Documenter usage dans README si nécessaire**

### Optimisations futures
- Considérer fusion des scripts E2E en un seul script avec paramètres
- Ajouter script de CI/CD unifié pour GitHub Actions
- Documenter intégration avec `CLAUDE.md` pour commandes favorites

---

*Documentation générée pour Miaou v0.2.0 "Radar Moustaches" - Scripts shell analysés et classifiés*