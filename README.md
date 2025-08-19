# Miaou 🐱

> *La messagerie qui fait ronronner les cryptographes et qui vous récompense à chaque miaou* 

**Miaou** est l'application de messagerie décentralisée qui transforme chaque conversation en aventure : indépendante comme un chat de gouttière, sécurisée comme un coffre-fort suisse, et généreuse comme une grand-mère qui distribue des croquettes à chaque contribution. Parce qu'au final, vos conversations méritent mieux qu'un simple serveur quelque part dans un datacenter.

## 📖 Description détaillée

**Miaou** représente une approche révolutionnaire de la messagerie moderne, conçue selon les principes de souveraineté numérique et de confidentialité absolue. Cette application décentralisée exploite une architecture peer-to-peer sophistiquée où chaque utilisateur devient un acteur autonome du réseau, éliminant ainsi les points de défaillance centralisés et les risques de surveillance de masse.

L'application s'appuie sur une cryptographie de bout-en-bout basée sur des bibliothèques auditées (ring, RustCrypto), garantissant que seuls les destinataires légitimes peuvent accéder au contenu des communications. Son système d'annuaires distribués permet une redondance géographique naturelle, assurant la continuité de service même en cas de tentatives de censure ou de conflits régionaux.

L'innovation majeure de Miaou réside dans son système d'incitations économiques basé sur une blockchain intégrée. Les utilisateurs sont récompensés en croquettes pour leur participation au réseau, créant un écosystème auto-entretenu et encourageant l'adoption virale. Le système de parrainage cross-platform permet d'inviter des utilisateurs depuis toutes les messageries populaires, transformant chaque utilisateur en ambassadeur du réseau décentralisé.

Développée entièrement en Rust selon les plus hauts standards de l'industrie (SOLID, TDD, couverture 100%), Miaou privilégie la performance, la sécurité mémoire et la fiabilité. Son architecture micro-modulaire garantit une maintenabilité optimale et une extensibilité future, while son interface multi-plateforme (CLI, desktop, web) s'adapte à tous les environnements d'usage.

## 🏴‍☠️ Philosophie et vision

**Miaou incarne un esprit de liberté numérique et de résistance technologique.** Nous refusons l'idée que les communications humaines doivent être contrôlées, monétisées ou surveillées par des corporations ou des États. Inspirés par l'héritage de cypherpunks, les créateurs du Web décentralisé et les pionniers du logiciel libre, nous construisons un outil d'émancipation numérique.

**Notre conviction :** La technologie doit servir l'humain, pas le contraire. Chaque ligne de code est écrite avec l'intention de redonner le pouvoir aux utilisateurs sur leurs données, leurs conversations et leur vie privée. Nous ne cherchons pas à "disruptr" un marché, mais à libérer les gens de l'aliénation aux plateformes propriétaires.

**Notre approche :** Pragmatique mais intransigeante sur les principes. Nous utilisons les meilleures technologies disponibles (pas de réinvention dangereuse), nous construisons sur des standards ouverts, mais nous n'acceptons aucun compromis sur la décentralisation et la confidentialité. Comme les premiers développeurs du Web, nous créons d'abord l'infrastructure technique solide, puis l'adoption suivra naturellement.

**L'esprit pirate :** Nous contournons les limitations imposées, nous connectons les îlots isolés, nous redistribuons le pouvoir. Mais toujours avec la rigueur technique qui garantit que notre rébellion soit durable et sécurisée.

## 📋 Vue d'ensemble

**Miaou** est une application de messagerie décentralisée conçue selon les principes de sécurité et de confidentialité. L'application utilise un chiffrement côté client et une architecture P2P pour garantir la protection des données personnelles.

### ✨ Domaines fonctionnels

#### 🔐 **Sécurité & Cryptographie**
- Chiffrement côté client bout-en-bout
- Authentification par clés publiques/privées
- Forward secrecy et perfect forward secrecy
- Authentification à deux facteurs (2FA)
- Audit trail et journalisation sécurisée

#### 🌐 **Réseau décentralisé**
- Communication P2P directe entre clients
- Annuaires distribués auto-hébergés
- Redondance géographique et failover
- Résistance à la censure et aux conflits
- Mode dégradé sans infrastructure centralisée

#### 🎮 **Économie & Gamification**
- Blockchain croquettes intégrée
- Mining par contributions qualitatives
- Système de parrainage récompensé
- Portefeuille et échanges P2P
- Marketplace décentralisée

#### 🌉 **Interopérabilité**
- Ponts vers messageries populaires (WhatsApp, Signal, Telegram...)
- Liaison Mastodon et réseaux sociaux décentralisés
- Invitations cross-platform automatisées
- Protocoles ouverts (Matrix, XMPP, IRC)
- Migration depuis autres plateformes

#### 📱 **Fonctions sociales respectueuses de la vie privée**
- Agrégation de publications Facebook, Instagram, Twitter
- Pont Mastodon bidirectionnel sécurisé
- Publication sociale optionnelle et anonymisable
- Serveur de contenu web intégré (WebAssembly)
- Isolation des données sociales et messagerie privée

#### 💬 **Communications**
- Messagerie texte chiffrée
- Partage de fichiers sécurisé
- Audio/vidéo P2P (WebRTC)
- Groupes et channels avec modération
- Messages persistants hors-ligne

#### 🖥️ **Interfaces utilisateur**
- CLI pour administration et automation
- Application desktop native (Tauri)
- Applications mobiles natives (Android/iOS)
- Interface web progressive (WebAssembly)
- Mini-site d'accueil pour invités avec documentation
- Thèmes adaptatifs et personnalisables

## 🏗️ Architecture technique

### 📦 **Structure modulaire (Crates Rust)**
```
miaou/
├── core/           # Noyau applicatif
│   ├── crypto/     # Cryptographie et clés
│   ├── network/    # Communication P2P
│   ├── storage/    # Stockage local
│   └── protocol/   # Protocole Miaou
├── blockchain/     # MiaouCoin et consensus
├── bridges/        # Ponts vers autres messageries
├── directory/      # Annuaires distribués
├── media/          # Audio/vidéo WebRTC
├── interfaces/     # Couches d'interface
│   ├── cli/        # Interface ligne de commande
│   ├── desktop/    # Application native
│   ├── mobile/     # Applications Android/iOS
│   └── web/        # Interface WebAssembly
└── tools/          # Outils et utilitaires
```

### 🌐 **Architecture réseau distribuée**
- **Clients P2P** : Communication directe chiffrée
- **Annuaires distribués** : Réseau de serveurs d'annuaires
- **Blockchain MiaouCoin** : Consensus et incitations économiques
- **Ponts messageries** : Passerelles vers écosystèmes existants
- **Redondance géographique** : Résistance aux pannes et censure

## 🔐 Sécurité

### Chiffrement et confidentialité
- Chiffrement côté client exclusivement
- Les clés privées ne quittent jamais l'appareil
- Échange direct des profils et identités entre clients
- Aucune donnée personnelle stockée sur le serveur

### Gestion des contacts
- Ajout de contacts via clé publique uniquement
- Confirmation requise des deux parties
- Pas d'annuaire public des utilisateurs

## 🛠️ Développement

Miaou suit des standards de développement stricts pour garantir sécurité, performance et maintenabilité.

**📋 Exigences principales :**
- **Architecture SOLID** et **TDD** obligatoires
- **Couverture de tests >= 90%** avec fuzzing et tests KAT crypto
- **Allowlist de dépendances auditées** pour la sécurité (voir [DEPENDENCIES.md](docs/DEPENDENCIES.md))
- **Documentation exhaustive** auto-générée avec rustdoc
- **Support i18n et accessibilité** dès le départ

Pour les détails complets, voir [CONTRIBUTING.md](docs/CONTRIBUTING.md).

### 🏗️ **Architecture micro-modulaire**

```
miaou/
├── 🔐 security/       # Cryptographie et sécurité (6 crates)
├── 🌐 network/        # Communication P2P et transport (5 crates)  
├── 📇 directory/      # Annuaires distribués (4 crates)
├── ⛏️ blockchain/     # Croquettes et consensus (5 crates)
├── 💬 messaging/      # Messages et conversations (5 crates)
├── 🌉 bridges/        # Ponts vers autres messageries (8 crates)
├── 📱 social/         # Fonctions sociales décentralisées (4 crates)
├── 🎯 invitations/    # Système de parrainage (4 crates)
├── 🏪 marketplace/    # Place de marché plugins (4 crates)
├── 🖥️ interfaces/    # Interfaces utilisateur (7 crates)
├── 🌍 i18n/          # Internationalisation (3 crates)
├── 📊 analytics/      # Métriques et monitoring (3 crates)
├── 🌐 web-server/     # Serveur web intégré (5 crates)
├── 🔧 utils/          # Utilitaires transversaux (5 crates)
└── 🧪 testing/       # Framework de tests (4 crates)
```

**Total : ~70 micro-crates** pour une modularité maximale et une réutilisabilité optimale.

Voir l'architecture détaillée dans [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## 🔐 Sécurité

Miaou implémente une sécurité de niveau militaire avec chiffrement bout-en-bout par défaut.

**🔒 Propriétés garanties :**
- Confidentialité des messages (ChaCha20-Poly1305)
- Perfect Forward Secrecy (Double Ratchet)
- Authentification des correspondants (Ed25519)
- Résistance à la censure et surveillance

**📋 Standards utilisés :**
- TLS 1.3, WebRTC, Signal Protocol
- Bibliothèques auditées : ring, RustCrypto, libsignal
- Tests cryptographiques avec vecteurs officiels NIST/IETF

Pour les détails complets, voir [SECURITY.md](docs/SECURITY.md).

## 🚀 Roadmap par progression logique

### 🏗️ **Phase 1 : Fondations techniques**
#### Objectif : Établir l'infrastructure de base sécurisée et modulaire

- [ ] **🔐 Core cryptographique (wrappers vers libs auditées)**
  - [ ] crypto-primitives : Wrappers vers ring, RustCrypto (AES, ChaCha20, Ed25519)
  - [ ] crypto-keyring : Génération et gestion sécurisée via ed25519-dalek
  - [ ] crypto-encryption : Chiffrement hybride avec libsignal-protocol
  - [ ] crypto-signature : Signatures Ed25519 via ed25519-dalek
  - [ ] crypto-hashing : Wrappers SHA-3, BLAKE3, Argon2 (RustCrypto)

- [ ] **📦 Architecture modulaire**
  - [ ] Structure des crates Rust (core, crypto, network, storage)
  - [ ] Interfaces et traits entre modules
  - [ ] Système de plugins extensible
  - [ ] Configuration et gestion des profils utilisateur

- [ ] **🧪 Qualité et tests**
  - [ ] Framework de tests personnalisé avec mocks
  - [ ] Pipeline CI/CD avec hooks pre-commit stricts
  - [ ] Couverture 100% obligatoire (cargo-tarpaulin)
  - [ ] Tests de mutation (cargo-mutagen)
  - [ ] Benchmarks automatisés (criterion)
  - [ ] Tests de propriétés (proptest)
  - [ ] Documentation rustdoc avec exemples exécutables
  - [ ] Linting exhaustif (clippy pedantic + custom rules)

---

### 🌐 **Phase 2 : Réseau P2P et communication**
#### Objectif : Communication décentralisée directe entre clients

- [ ] **🔗 Communication P2P (standards éprouvés)**
  - [ ] network-discovery : WebRTC + ICE pour découverte automatique
  - [ ] network-protocol : Protocole Miaou sur WebRTC Data Channels
  - [ ] network-transport : TLS 1.3 + DTLS pour WebRTC
  - [ ] network-nat : ICE + STUN/TURN standards (pas de custom NAT traversal)

- [ ] **📇 Annuaires distribués**
  - [ ] API REST pour clés publiques et métadonnées
  - [ ] Mode serveur auto-hébergé pour annuaires
  - [ ] Synchronisation P2P entre annuaires
  - [ ] Système de réputation et web of trust

- [ ] **💬 Messagerie de base**
  - [ ] Messages texte chiffrés bout-en-bout
  - [ ] Gestion des conversations et contacts
  - [ ] Messages hors-ligne avec stockage temporaire
  - [ ] Interface CLI fonctionnelle

---

### 🎮 **Phase 3 : Blockchain et économie**
#### Objectif : Système d'incitations et gamification

- [ ] **⛏️ Blockchain MiaouCoin**
  - [ ] Consensus Proof-of-Stake adapté aux messageries
  - [ ] Mining par micro-interactions (messages, ajouts contacts, uptime)
  - [ ] Portefeuille intégré et gestion des transactions
  - [ ] Mécanismes anti-spam économiques

- [ ] **🎯 Système de parrainage**
  - [ ] Génération de codes d'invitation uniques
  - [ ] Récompenses crypto pour parrains et filleuls
  - [ ] Tracking des conversions et croissance du réseau
  - [ ] Mécanismes d'incitation pour participation

---

### 🖥️ **Phase 4 : Interfaces utilisateur**
#### Objectif : Expérience utilisateur moderne et accessible

- [ ] **🖥️ Application desktop**
  - [ ] Interface Tauri avec frontend moderne
  - [ ] Gestion complète des conversations et contacts
  - [ ] Intégration portefeuille et stats blockchain
  - [ ] Notifications système et thèmes adaptatifs

- [ ] **🌐 Interface web progressive**
  - [ ] Compilation WebAssembly pour performance
  - [ ] PWA avec support offline
  - [ ] Interface responsive et accessible
  - [ ] Synchronisation avec versions desktop/mobile

- [ ] **🌐 Mini-site d'accueil et contenu social intégré**
  - [ ] web-server : Serveur HTTP léger intégré (from scratch)
  - [ ] Site d'accueil pour invités avec design moderne
  - [ ] Documentation auto-générée hébergée (rustdoc + custom)
  - [ ] Templates responsive avec thèmes adaptatifs
  - [ ] Assets statiques optimisés (CSS/JS minimal)
  - [ ] web-wasm : Modules WebAssembly pour contenu riche
  - [ ] web-social : Serveur de contenu social décentralisé

- [ ] **👤 Expérience utilisateur**
  - [ ] Assistant d'onboarding et configuration initiale
  - [ ] Cache intelligent et optimisations performance
  - [ ] Support multilingue et accessibilité

---

### 🌍 **Phase 5 : Interopérabilité et ponts**
#### Objectif : Connexion avec l'écosystème existant

- [ ] **🌉 Ponts vers protocoles ouverts**
  - [ ] Matrix, XMPP, IRC avec chiffrement préservé
  - [ ] Discord via API officielle
  - [ ] Interface unifiée multi-protocoles

- [ ] **📱 Ponts messageries populaires**
  - [ ] WhatsApp (Business API + reverse engineering)
  - [ ] Signal (libsignal-client), Telegram (MTProto)
  - [ ] Facebook Messenger (Graph API)
  - [ ] Mastodon (API ActivityPub bidirectionnelle)

- [ ] **📧 Système d'invitations cross-platform**
  - [ ] Génération de liens personnalisés
  - [ ] Envoi automatique via ponts existants
  - [ ] Tracking et récompenses pour croissance virale

- [ ] **📱 Fonctions sociales intégrées**
  - [ ] social-aggregator : Agrégation Facebook, Instagram, Twitter
  - [ ] social-publisher : Publication optionnelle et anonymisable
  - [ ] social-privacy : Isolation totale données sociales/messagerie
  - [ ] web-social : Serveur contenu web avec modules WASM

---

### 🚀 **Phase 6 : Fonctionnalités avancées**
#### Objectif : Écosystème complet et résilient

- [ ] **📁 Multimédia et fichiers**
  - [ ] Partage de fichiers P2P avec chunking
  - [ ] Communications audio/vidéo WebRTC chiffrées
  - [ ] Appels de groupe et partage d'écran

- [ ] **👥 Collaboration avancée**
  - [ ] Groupes et channels avec modération
  - [ ] Permissions granulaires et rôles
  - [ ] Intégration outils de travail collaboratif

- [ ] **🛡️ Résistance et résilience**
  - [ ] Mécanismes anti-censure (DPI, obfuscation)
  - [ ] Mode dégradé sans infrastructure
  - [ ] Routage adaptatif en cas de conflit

---

### 🌟 **Phase 7 : Écosystème et gouvernance**
#### Objectif : Plateforme autonome et communautaire

- [ ] **🏪 Marketplace décentralisée**
  - [ ] Plugins et extensions communautaires
  - [ ] Économie MiaouCoin intégrée
  - [ ] API publique et SDK développeurs

- [ ] **🤖 Intelligence artificielle**
  - [ ] Assistant IA contextuel
  - [ ] Détection contenu malveillant
  - [ ] Traduction temps réel

- [ ] **🏛️ Gouvernance décentralisée**
  - [ ] DAO pour évolutions du protocole
  - [ ] Système de vote communautaire
  - [ ] Mécanismes de résolution de conflits

## 🚀 Démarrage rapide

```bash
# Clone du repository
git clone https://github.com/username/miaou.git
cd miaou

# Build et tests
cargo build --release
cargo test

# Lancement interface CLI
./target/release/miaou-cli --help
```

*Documentation complète à venir avec les premières releases.*

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](docs/CONTRIBUTING.md) pour :
- Guidelines de développement strict (TDD, SOLID, sécurité)
- Processus de review et de merge
- Standards de code et de documentation
- Système de récompenses en croquettes

## 📋 Documentation

- **[ROADMAP.md](docs/ROADMAP.md)** - Feuille de route détaillée
- **[CHANGELOG.md](docs/CHANGELOG.md)** - Historique des versions
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** - Guide de contribution
- **[SECURITY.md](docs/SECURITY.md)** - Politique de sécurité
- **[GLOSSAIRE.md](docs/GLOSSAIRE.md)** - Définitions techniques
- **[CRITIQUE_CLAUDE.md](docs/CRITIQUE_CLAUDE.md)** - Analyse critique du projet
- **[CRITIQUE_COMPILEE.md](docs/CRITIQUE_COMPILEE.md)** - Compilation des critiques techniques
- **[DEPENDENCIES.md](docs/DEPENDENCIES.md)** - Politique des dépendances auditées
- **[IDEA.md](docs/IDEA.md)** - Vision initiale et évolution du concept
- **[WEBSITE_STACK.md](docs/WEBSITE_STACK.md)** - Stack technique pour le site web
- **[MOBILE.md](docs/MOBILE.md)** - Support Android et iOS

## 📄 Licence

*Licence open source à définir (probablement MIT ou Apache 2.0)*

---

*Miaou est actuellement en phase de conception. Rejoignez-nous pour construire l'avenir de la messagerie décentralisée !* 🏴‍☠️