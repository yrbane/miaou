# 📋 CHANGELOG

*Journal des modifications et versions de Miaou*

---

## Format

Ce changelog suit le format [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

---

## [Unreleased] - En développement

### Ajouté
- Structure initiale du projet avec micro-crates
- Documentation complète (README, ROADMAP, CONTRIBUTING, SECURITY, GLOSSAIRE)
- Architecture modulaire définie
- Spécifications cryptographiques
- Plan de test avec couverture 100%

### Modifié
- Remplacement "MiaouCoin" par "Croquettes"
- Intégration fonctions sociales avec isolation données
- Ajout pont Mastodon dans l'architecture

### Sécurité
- Définition des exigences de sécurité strictes
- Politique de dépendances externes clarifiée
- Standards cryptographiques spécifiés

---

## [0.1.0] - Première Griffe - 2025-08-20 - IMPLÉMENTÉ ✅

### Ajouté
- **Module cryptographique complet** avec primitives sécurisées auditées
  - ChaCha20-Poly1305 pour chiffrement AEAD avec AAD obligatoire
  - Ed25519 pour signatures numériques avec zeroization
  - Argon2id pour dérivation de clés (configurations fast/balanced/secure)
  - BLAKE3 et SHA3-256 pour fonctions de hachage
  - HKDF pour dérivation de sous-clés
- **Architecture object-safe** avec traits CryptoProvider modulaires
- **Support multi-plateformes** (CLI, desktop, mobile Android/iOS)
- **Tests exhaustifs** avec vecteurs IETF/NIST (34 tests, 100% de réussite)
- **Benchmarks de performance** pour toutes les primitives cryptographiques
- **Documentation complète** des APIs publiques avec rustdoc
- **Gestion sécurisée de la mémoire** avec zeroization automatique
- **Interfaces JNI/Objective-C** pour intégration mobile native

### Modifié
- Adoption des bibliothèques cryptographiques auditées (RustCrypto + Dalek)
- Abandon de l'approche "crypto from scratch" au profit de libs éprouvées
- Configuration balanced par défaut pour Argon2 (remplace default())
- Compilation clean sans warnings (cargo + clippy)

### Sécurité
- **AAD obligatoire** pour toutes les opérations AEAD
- **Object-safe traits** permettant le polymorphisme sécurisé
- **Zeroization automatique** des clés cryptographiques
- **Tests KAT** avec vecteurs officiels IETF/NIST
- **Gestion d'erreurs** robuste sans exposition d'informations sensibles

---

## [0.2.0] - Radar à Moustaches - FONDATIONS SOLIDES - Septembre 2025

### ✅ INFRASTRUCTURE P2P ÉTABLIE

#### 🌐 **Réseau LAN production**
- **mDNS discovery réelle** : via mdns-sd, service _miaou._tcp.local, TXT records
- **UnifiedDiscovery** : Gestionnaire multi-méthodes (mDNS/DHT/manuel) avec JSON stable  
- **CLI réseau fonctionnel** : net-list-peers, lan-mdns-*, collect_peers() automatique
- **Tests mDNS** : Annonce/browse locaux, intégration CLI, output JSON validé

#### 🔐 **Cryptographie robuste et sécurisée**
- **ChaCha20-Poly1305** : AEAD production, validation stricte, AAD obligatoire
- **Ed25519** : Signatures numériques, clés d'identité, vérification robuste
- **BLAKE3** : Hachage cryptographique ultra-rapide, implémentation pure Rust
- **SensitiveBytes** : Zeroization automatique, gestion mémoire sécurisée
- **KeyStore trait** : Architecture modulaire avec implémentation mémoire MVP

#### 📱 **Architecture SOLID mature**
- **Traits abstraits** : Discovery/Transport/Directory pour extensibilité
- **WebRTC MVP** : DataChannels derrière feature flag, connect() partiel
- **DHT préparé** : API traits complets, implémentation Kademlia en développement
- **CLI stable** : 14 commandes avec output JSON cohérent et testé

### Ajouté - Nouvelle architecture réseau
- **Nouveau crate miaou-network** : Infrastructure P2P complète
- **mDNS production** : Découverte LAN réelle remplaçant simulations
- **UnifiedDiscovery** : Agrégateur multi-sources avec priorité LAN
- **WebRTC foundation** : MVP avec PeerConnection/DataChannel (feature flag)

### Modifié - Maturité technique
- **Architecture SOLID** : Dependency injection, traits object-safe
- **Qualité de code** : forbid(unsafe_code), Clippy pedantic compliance
- **Documentation** : APIs publiques complètes, `# Errors` et `# Panics`
- **CI/CD** : Pipeline multi-OS avec validation stricte

### État v0.2.0 - Fondations pour v0.3.0
- **✅ PRODUCTION** : mDNS discovery, crypto robuste, CLI stable
- **🚧 MVP** : WebRTC transport (feature flag), DHT traits (sans implem)
- **🎯 v0.3.0** : WebRTC production complet, DHT Kademlia réel
- **📊 QUALITÉ** : Architecture SOLID, tests complets, zéro unsafe

---

## [0.3.0] - Ronron du Bonheur - Gamification

### Sera ajouté
- Blockchain Croquettes
- Mining par contributions
- Portefeuille intégré
- Système de parrainage
- Anti-spam économique

---

## [0.4.0] - Toilettage Royal - Interfaces

### Sera ajouté
- Application desktop (Tauri)
- Interface web (WebAssembly)
- Site d'accueil intégré
- Support mobile
- Thèmes et accessibilité

---

## [0.5.0] - Chat de Gouttière - Interopérabilité

### Sera ajouté
- Ponts Matrix, XMPP, IRC
- Pont Mastodon bidirectionnel
- Ponts WhatsApp, Signal, Telegram
- Fonctions sociales
- Invitations cross-platform

---

## [0.6.0] - Neuf Vies - Fonctionnalités avancées

### Sera ajouté
- Audio/vidéo P2P (WebRTC)
- Partage de fichiers
- Groupes et channels
- Résistance à la censure
- Mobile iOS/Android

---

## [1.0.0] - Matou Majestueux - Release stable

### Sera ajouté
- Marketplace décentralisée
- IA intégrée
- Gouvernance DAO
- Audit de sécurité validé
- Documentation complète

---

## Types de changements

- **Ajouté** pour les nouvelles fonctionnalités
- **Modifié** pour les changements de fonctionnalités existantes
- **Déprécié** pour les fonctionnalités bientôt supprimées
- **Supprimé** pour les fonctionnalités supprimées
- **Corrigé** pour les corrections de bugs
- **Sécurité** pour les corrections de vulnérabilités

---

## Notes sur les versions

### Semantic Versioning
- **MAJOR** : Changements incompatibles de l'API
- **MINOR** : Nouvelles fonctionnalités compatibles
- **PATCH** : Corrections de bugs compatibles

### Versions de développement
- **alpha** : Fonctionnalités de base incomplètes
- **beta** : Fonctionnalités principales complètes, tests en cours  
- **rc** : Release candidate, prêt pour audit de sécurité

---

*Ce changelog sera mis à jour à chaque release et changement significatif.*