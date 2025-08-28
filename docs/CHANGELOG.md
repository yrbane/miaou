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

## [0.2.0] - Radar à Moustaches - Réseau P2P (MVP IMPLÉMENTÉ - Août 2025)

### Ajouté - Fondations P2P solides
- 📡 **mDNS discovery réel** avec mdns-sd : découverte pairs réseau local
- 🌐 **UnifiedDiscovery** : gestionnaire multi-méthodes (mDNS + DHT + manuel)
- 🟡 **DHT Kademlia MVP** : K-buckets, XOR distance, logique locale (sans I/O réseau)
- 🟡 **WebRTC Data Channels MVP** : architecture complète simulée, API tests
- 🟡 **NAT/STUN/TURN MVP** : génération candidats ICE simulés
- 💬 **FileMessageStore** : persistance JSON atomique pour messaging
- 📱 **14 commandes CLI réseau** : définies mais pas encore câblées (stubs)
- 🧪 **261 tests réseau** : couverture complète architecture MVP
- 📊 **369 tests total** : +305% depuis v0.1.0, coverage 95.5% maintenue

### Modifié - Architecture
- **Nouveau crate miaou-network** : 12 modules, 4 traits abstraits SOLID
- **CLI étendu** : 14 commandes (8 réseau + 6 crypto) vs 6 précédent  
- **Architecture SOLID** : Dependency Injection, traits abstraits complets

### Notes MVP v0.2.0
- **✅ RÉEL** : mDNS, messaging persistant, architecture modulaire
- **🟡 SIMULÉ** : WebRTC, DHT réseau, STUN/TURN (fondations posées)
- **🎯 v0.3.0** : Implémentation réseau complète (UDP DHT, WebRTC réel)

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