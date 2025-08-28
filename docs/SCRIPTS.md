# 📜 Scripts Miaou v0.2.0

Documentation complète des scripts shell et d'automatisation du projet Miaou.

## 🎯 Scripts de test End-to-End (E2E) - **CONSERVÉS**

### **test_e2e_dht.sh** ✅ UTILE
Test complet du système d'annuaire DHT distribué avec commandes CLI réelles.

**Fonctionnalités validées :**
- Publication de clés via `dht-put signing|encryption <key>`
- Recherche dans l'annuaire via `dht-get <peer_id> <key_type>`
- Validation formats clés hexadécimales
- Gestion multi-types (signing/encryption)
- Tests de persistance locale DHT

**Usage :** `./test_e2e_dht.sh`

### **test_e2e_messaging.sh** ✅ UTILE
Test production du système de messaging avec instances CLI multiples.

**Fonctionnalités validées :**
- Messages inter-instances avec `send <recipient> <message>`
- Persistance JSON atomique (`messages.json`)
- Isolation des stores par instance
- Commande `recv` pour récupération de messages
- Variables d'environnement `MIAOU_STORAGE`

**Usage :** `./test_e2e_messaging.sh`

### **test_e2e_net_connect.sh** ✅ UTILE
Test complet du parcours mDNS → WebRTC pour connexions P2P.

**Fonctionnalités validées :**
- Découverte pairs via `net-list-peers`
- Connexion WebRTC via `net-connect <peer_id>`
- Négociation ICE et Data Channels
- Gestion adresses IP LAN (non-loopback)
- Retry automatique avec timeout

**Usage :** `./test_e2e_net_connect.sh`

### **test_mdns_demo.sh** ✅ UTILE
Démonstration découverte mutuelle mDNS entre instances.

**Fonctionnalités validées :**
- Services mDNS `_miaou._tcp`
- Communication inter-instances 
- Intégration avec `avahi-browse`
- Logs détaillés de découverte

**Usage :** `./test_mdns_demo.sh`

### **test_cli_mdns_integration.sh** ✅ UTILE
Test d'intégration CLI complet validant UnifiedDiscovery.

**Fonctionnalités validées :**
- Architecture de câblage mDNS dans CLI
- Commandes `net-start`, `net-list-peers`, `net-connect`
- Persistance des logs de test
- Score de réussite avec métriques

**Usage :** `./test_cli_mdns_integration.sh`

## 🔧 Scripts d'automatisation - Répertoire `/scripts/`

### **build-targets.sh** ✅ UTILE
Build multi-plateforme automatisé avec support des profils Cargo.

**Plateformes supportées :**
- **Desktop :** Linux (x86_64), Windows (x86_64), macOS (x86_64, ARM64)
- **Mobile :** Android (ARM64, ARMv7, i686, x86_64), iOS (ARM64, x86_64)
- **WebAssembly :** `wasm32-unknown-unknown`, `wasm32-wasi`

**Usage :**
```bash
./scripts/build-targets.sh                    # Desktop seulement
./scripts/build-targets.sh mobile             # Mobile seulement  
./scripts/build-targets.sh all --test         # Tout avec tests
./scripts/build-targets.sh wasm32-unknown-unknown  # Target spécifique
```

### **hardening.sh** ✅ UTILE
Script de durcissement et configuration workspace Cargo.

**Fonctionnalités :**
- Ajout `[workspace.package]` avec métadonnées
- Héritage automatique dans tous les crates
- Génération `scripts/refactor.sh` compatible stable
- Lints stricts dans `lib.rs` (`#![forbid(unsafe_code)]`)
- Installation optionnelle des outils de développement

**Usage :** `./scripts/hardening.sh [--install-tools]`

### **pre-commit.sh** ✅ UTILE
Hook de validation pre-commit avec standards Miaou stricts.

**Validations automatiques :**
- Formatage (`rustfmt`)
- Linting (`clippy` pedantic + nursery + cargo)
- Tests unitaires et documentation
- Couverture de code ≥90% (avec `cargo-tarpaulin`)
- Audit de sécurité (`cargo-audit`)
- Tests cryptographiques spécialisés
- Vérifications par phase de développement

**Installation :** `cp scripts/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`

### **setup-git-hooks.sh** ✅ UTILE
Configuration automatique des git hooks dans le projet.

**Fonctionnalités :**
- Installation hook pre-commit depuis `.githooks/`
- Configuration git (autocrlf, fileMode, couleurs)
- Test automatique de fonctionnement des hooks
- Instructions d'usage (`--no-verify`, réinstallation)

**Usage :** `./scripts/setup-git-hooks.sh`

### **generate_glossary_html.py** ✅ UTILE
Générateur de glossaire HTML interactif depuis `GLOSSAIRE.md`.

**Fonctionnalités :**
- Recherche en temps réel (filtrage instantané)
- Liens automatiques entre termes
- Navigation par sections (24 catégories, 200+ termes)
- Interface responsive et design moderne
- URLs partageable avec ancres permanentes

**Usage :** `python3 scripts/generate_glossary_html.py`
**Sortie :** `scripts/glossaire.html`

## 📊 Scripts supprimés (obsolètes)

### ~~refactor.sh~~ ❌ SUPPRIMÉ
- **Raison :** Version obsolète en doublon avec `/scripts/refactor.sh`
- **Migration :** Utiliser `./scripts/hardening.sh` qui génère une version compatible stable

### ~~scripts/fix_regex_dups.sh~~ ❌ SUPPRIMÉ
- **Raison :** Script ponctuel pour fix spécifique déjà appliqué
- **Statut :** Correction intégrée, plus nécessaire

## 🎯 Recommandations d'usage v0.2.0

### Pour le développement quotidien :
1. **Installation des hooks :** `./scripts/setup-git-hooks.sh`
2. **Tests E2E réguliers :** `./test_cli_mdns_integration.sh`
3. **Build multi-plateforme :** `./scripts/build-targets.sh desktop --test`

### Pour la validation complète :
1. **Hardening complet :** `./scripts/hardening.sh --install-tools`
2. **Tous les tests E2E :** `./test_e2e_*.sh`
3. **Génération doc :** `python3 scripts/generate_glossary_html.py`

### Pour la release :
1. **Build toutes plateformes :** `./scripts/build-targets.sh all`
2. **Packaging :** Les archives sont créées dans `dist/`
3. **Vérification finale :** `./scripts/pre-commit.sh` (validation complète)

## 📈 Métriques des scripts

- **5 scripts E2E** conservés (validation production complète)
- **5 scripts d'automatisation** dans `/scripts/` (développement et release) 
- **2 scripts obsolètes** supprimés (cleaning)
- **Couverture complète** : tests, build, validation, documentation

---

*Tous les scripts respectent les standards Miaou : sécurité, robustesse et compatibilité multi-plateforme.* 🐱