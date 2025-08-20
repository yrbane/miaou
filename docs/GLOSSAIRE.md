# GLOSSAIRE TECHNIQUE MIAOU

*Définitions complètes des termes, acronymes et concepts techniques utilisés dans le projet Miaou*

**🎯 Pour les débutants :** Ce glossaire contient plus de 150 termes techniques expliqués simplement !

---

## A

### **ADR (Architecture Decision Records)**
Documents traçant les décisions architecturales importantes, leurs contextes, options considérées et justifications.

### **AEAD (Authenticated Encryption with Associated Data)**
Mode de chiffrement qui combine confidentialité et authentification. Exemples : AES-GCM, ChaCha20-Poly1305. Dans Miaou v0.1.0, utilisation obligatoire d'AAD (Associated Authenticated Data) pour toutes les opérations de chiffrement.

### **AES (Advanced Encryption Standard)**
Standard de chiffrement symétrique adopté par le NIST. Versions : AES-128, AES-192, AES-256.

### **Allowlist de dépendances**
Liste blanche stricte de dépendances externes autorisées après audit de sécurité, remplaçant la politique "zéro dépendance". Voir DEPENDENCIES.md.

### **Argon2**
Fonction de dérivation de clés résistante aux attaques par force brute, winner du Password Hashing Competition. Miaou v0.1.0 utilise Argon2id avec configurations adaptées : fast_insecure (tests), balanced (défaut), secure (haute sécurité).

### **ActivityPub**
Protocole de fédération sociale du W3C utilisé par Mastodon, Pleroma et autres réseaux sociaux décentralisés.

### **API (Application Programming Interface)**
Interface de programmation permettant l'interaction entre différents composants logiciels.

### **Audit de sécurité externe**
Examen professionnel du code par des experts indépendants pour identifier vulnérabilités. Obligatoire avant release 1.0.

---

## B

### **BLAKE3**
Fonction de hachage cryptographique ultra-rapide, successeur de BLAKE2, basé sur l'arbre de Merkle.

### **Bootstrap nodes**
Nœuds de démarrage permettant à un nouveau client de découvrir d'autres pairs sur le réseau P2P.

### **Bridges**
Composants logiciels permettant l'interopérabilité entre Miaou et d'autres protocoles de messagerie.

---

## C

### **Cargo-audit**
Outil Rust détectant vulnérabilités connues dans dépendances via base RustSec. Intégré au CI Miaou.

### **Cargo-deny**
Outil vérifiant licences et politiques de dépendances pour projets Rust.

### **Cargo-tarpaulin**
Outil mesure de couverture de code Rust. Objectif Miaou : >= 90% + fuzzing.

### **ChaCha20-Poly1305**
Algorithme de chiffrement authentifié combinant le cipher ChaCha20 et l'authentificateur Poly1305. Primitive AEAD principale de Miaou v0.1.0, choisie pour sa performance et sa sécurité post-quantique.

### **CI/CD (Continuous Integration/Continuous Deployment)**
Pratiques d'intégration et déploiement continus pour automatiser les tests et livraisons.

### **CLI (Command Line Interface)**
Interface en ligne de commande pour interagir avec l'application via terminal.

### **Consensus**
Mécanisme permettant à un réseau distribué de s'accorder sur un état commun malgré les pannes ou défaillances.

### **Constant-time**
Propriété d'algorithmes crypto exécutant en temps fixe pour éviter attaques par canaux auxiliaires.

### **Crates**
Unités de compilation et distribution dans l'écosystème Rust. Équivalent des packages/bibliothèques.

### **Croquettes**
Nom de la crypto-monnaie interne de Miaou, remplaçant "MiaouCoin". Récompense les contributions qualitatives au réseau.

---

## D

### **Dalek-cryptography**
Écosystème de bibliothèques Rust pour cryptographie courbes elliptiques (ed25519-dalek, x25519-dalek). Utilisé dans Miaou.

### **DAO (Decentralized Autonomous Organization)**
Organisation décentralisée autonome gouvernée par des smart contracts et votes communautaires.

### **DEPENDENCIES.md**
Fichier définissant politique stricte des dépendances autorisées/interdites dans Miaou.

### **DHT (Distributed Hash Table)**
Structure de données distribuée pour stocker et retrouver des informations dans un réseau P2P.

### **DPI (Deep Packet Inspection)**
Technique d'analyse du contenu des paquets réseau, souvent utilisée pour la censure.

### **Double Ratchet**
Protocole cryptographique offrant Perfect Forward Secrecy, utilisé par Signal et autres messageries sécurisées.

---

## E

### **E2EE (End-to-End Encryption)**
Chiffrement de bout en bout où seuls les correspondants peuvent déchiffrer les messages.

### **Ed25519**
Algorithme de signature numérique basé sur les courbes elliptiques, rapide et sécurisé.

---

## F

### **Forward Secrecy**
Propriété garantissant que la compromission des clés actuelles ne compromet pas les communications passées.

### **Fédération**
Interconnexion de serveurs indépendants permettant la communication entre utilisateurs de différentes instances.

### **From scratch (crypto)**
Approche implémentant cryptographie depuis zéro. INTERDITE dans Miaou au profit de libs auditées.

### **Fuzzing**
Technique de test consistant à fournir des données aléatoires ou malformées pour détecter des bugs. Objectif Miaou : obligatoire avec couverture >= 90%.

---

## G

### **GCM (Galois/Counter Mode)**
Mode de chiffrement authentifié pour AES, fournissant confidentialité et intégrité.

---

## H

### **HKDF (HMAC-based Key Derivation Function)**
Fonction de dérivation de clés basée sur HMAC, standardisée dans RFC 5869.

### **Hole Punching**
Technique permettant l'établissement de connexions P2P directes à travers NAT.

---

## I

### **ICE (Interactive Connectivity Establishment)**
Protocole pour établir des connexions entre pairs à travers NAT et firewalls.

### **i18n (Internationalization)**
Processus de conception logicielle pour supporter multiple langues et régions.

### **IoT (Internet of Things)**
Réseau d'objets connectés échangeant des données via Internet.

### **Isolation des données**
Séparation technique stricte entre données sociales publiques et conversations privées pour préserver la confidentialité.

---

## K

### **KAT (Known Answer Tests)**
Tests cryptographiques avec vecteurs officiels NIST/IETF validant implémentation. Obligatoires dans Miaou pour toutes primitives crypto.

### **KDF (Key Derivation Function)**
Fonction dérivant des clés cryptographiques à partir d'un matériel de base.

---

## L

### **Libsignal-protocol**
Bibliothèque officielle implémentant X3DH et Double Ratchet du protocole Signal. Adoptée dans Miaou.

### **Libs auditées**
Bibliothèques cryptographiques ayant subi audits de sécurité professionnels (ring, RustCrypto, libsignal).

---

## M

### **Mastodon**
Réseau social décentralisé basé sur ActivityPub, alternative libre à Twitter.

### **mDNS (Multicast DNS)**
Protocole permettant la résolution de noms sur réseaux locaux sans serveur DNS central.

### **MLS (Messaging Layer Security)**
Protocole de sécurité pour messagerie de groupe, standardisé IETF (RFC 9420).

### **MVP (Minimum Viable Product)**
Version minimale fonctionnelle d'un produit pour valider les hypothèses de base.

---

## N

### **NAT (Network Address Translation)**
Technique permettant à plusieurs appareils de partager une adresse IP publique.

---

## P

### **P2P (Peer-to-Peer)**
Architecture réseau où les participants communiquent directement sans intermédiaire central.

### **Perfect Forward Secrecy (PFS)**
Propriété crypto garantissant que chaque session utilise des clés éphémères uniques.

### **PoW (Proof of Work)**
Mécanisme de consensus nécessitant une preuve de calcul, utilisé contre le spam.

### **PSI (Private Set Intersection)**
Protocole permettant de calculer l'intersection d'ensembles sans révéler les éléments privés.

### **PWA (Progressive Web App)**
Application web avec capacités natives (offline, notifications, installation).

---

## Q

### **Publication sociale**
Fonctionnalité permettant de partager du contenu sur les réseaux sociaux de manière optionnelle et anonymisable.

### **QUIC**
Protocole de transport moderne (Google/IETF) offrant multiplexage et migration de connexions.

---

## R

### **RFC (Request for Comments)**
Documents techniques standardisant les protocoles Internet (IETF).

### **Ring**
Bibliothèque cryptographique Rust auditée par Google, utilisée dans Miaou pour primitives AEAD.

### **RustCrypto**
Écosystème de bibliothèques cryptographiques Rust pures, auditées. Adoptées dans Miaou.

### **Rustdoc**
Outil de génération automatique de documentation pour le langage Rust.

### **RustSec**
Base de données vulnérabilités connues dans écosystème Rust. Surveillée via cargo-audit.

---

## S

### **SBOM (Software Bill of Materials)**
Liste exhaustive des composants logiciels et dépendances d'une application.

### **SDK (Software Development Kit)**
Ensemble d'outils de développement pour créer des applications.

### **SHA-3**
Famille de fonctions de hachage cryptographique standardisée par NIST (Keccak).

### **SLSA (Supply-chain Levels for Software Artifacts)**
Framework pour sécuriser la chaîne d'approvisionnement logicielle.

### **Social-aggregator**
Module d'agrégation des publications provenant de différents réseaux sociaux (Facebook, Instagram, Twitter).

### **Social-publisher**
Module de publication de contenu sur les réseaux sociaux avec options d'anonymisation.

### **SOLID**
Cinq principes de conception orientée objet : Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion.

### **STUN (Session Traversal Utilities for NAT)**
Protocole standard découverte IP publique et type NAT. Utilisé avec ICE dans Miaou vs custom.

---

## T

### **TDD (Test-Driven Development)**
Méthodologie où les tests sont écrits avant le code d'implémentation.

### **TLS (Transport Layer Security)**
Protocole cryptographique sécurisant les communications sur réseaux. Version actuelle : TLS 1.3.

### **TOFU (Trust On First Use)**
Modèle de confiance acceptant une clé lors de la première rencontre.

### **TUF (The Update Framework)**
Framework pour sécuriser les mises à jour logicielles contre diverses attaques.

### **TURN (Traversal Using Relays around NAT)**
Protocole relais standard quand connexion P2P directe impossible. Adopté dans Miaou avec ICE/STUN.

---

## W

### **WASM (WebAssembly)**
Format de bytecode permettant l'exécution de code natif dans les navigateurs.

### **WCAG (Web Content Accessibility Guidelines)**
Standards d'accessibilité web du W3C. Niveaux : A, AA, AAA.

### **WebRTC (Web Real-Time Communication)**
Standards W3C communications temps réel. Adopté dans Miaou pour P2P et NAT traversal vs implémentations custom.

### **Web of Trust**
Modèle de confiance décentralisé basé sur les recommandations entre utilisateurs.

### **Web-social**
Serveur de contenu social intégré permettant de servir du contenu web directement depuis les clients Miaou.

### **Web-wasm**
Modules WebAssembly permettant l'exécution de contenu riche et interactif dans l'interface web de Miaou.

---

## X

### **X3DH (Extended Triple Diffie-Hellman)**
Protocole d'accord de clés permettant l'échange sécurisé initial entre deux parties.

---

## Z

### **Zeroize**
Technique d'effacement sécurisé de données sensibles en mémoire pour éviter leur récupération.

---

## Nouveaux termes (post-critiques)

### **Approche progressive blockchain**
Stratégie Miaou : Phase 1-6 sans blockchain, Phase 7+ avec blockchain basée sur usage réel.

### **Consensus technique (GPT-5 + Claude)**
Points d'accord entre les deux IA : abandonner crypto custom, utiliser libs auditées, standards réseau éprouvés.

### **Crypto custom**
Implémentation cryptographique from scratch. INTERDITE dans Miaou suite aux critiques de sécurité.

### **Politique dépendances audit**
Approche équilibrée remplaçant "zéro dépendance" : allowlist stricte de dépendances auditées.

### **Standards éprouvés**
Protocoles réseau établis (WebRTC, ICE, STUN/TURN) adoptés dans Miaou au lieu d'algorithmes custom.

### **Wrappers crypto**
Couches d'abstraction Miaou autour de bibliothèques auditées (ring, RustCrypto) au lieu d'implémentations from scratch.

---

## Nouveaux termes v0.1.0

### **AAD obligatoire**
Politique Miaou imposant l'utilisation d'Associated Authenticated Data pour toutes les opérations AEAD, empêchant les chiffrements sans contexte d'authentification.

### **CryptoProvider trait**
Interface object-safe définissant les opérations cryptographiques fondamentales (seal, open, sign, verify) dans l'architecture modulaire de Miaou.

### **Edition 2024**
Version du langage Rust requise par certaines dépendances cryptographiques, nécessitant une mise à jour de la toolchain.

### **Object-safe traits**
Contrainte Rust permettant l'utilisation de trait objects pour le polymorphisme dynamique. Essentiel pour l'architecture modulaire crypto de Miaou.

### **SealedData**
Structure Miaou encapsulant les données chiffrées avec nonce et tag d'authentification pour un transport sécurisé.

### **Zeroization**
Effacement sécurisé automatique des clés cryptographiques en mémoire via le trait ZeroizeOnDrop, implémenté dans toutes les structures sensibles.

---

## Termes spécifiques à Miaou

### **Bridge-mastodon**
Pont bidirectionnel entre Miaou et le réseau Mastodon utilisant l'API ActivityPub.

### **Croquettes**
Crypto-monnaie interne de Miaou récompensant les contributions qualitatives (sécurité, hébergement, parrainage).

### **Fonctions sociales**
Ensemble de fonctionnalités permettant l'agrégation et la publication sur les réseaux sociaux tout en préservant la confidentialité des conversations privées.

### **Hub social décentralisé**
Vision de Miaou comme point central pour gérer ses communications privées et ses interactions sociales publiques de manière unifiée.

### **Social-feeds**
Gestionnaire de flux sociaux personnalisés permettant de suivre du contenu agrégé depuis multiple sources.

### **Social-privacy**
Module d'anonymisation et d'isolation garantissant que les données sociales n'interfèrent pas avec la messagerie privée.

---

## Termes supplémentaires pour débutants

### **API Gateway**
Point d'entrée unique qui route les requêtes vers les bons services dans une architecture microservices. Comme une réceptionniste qui dirige les visiteurs.

### **Backend/Frontend**
Backend = partie serveur invisible aux utilisateurs. Frontend = interface utilisateur visible. Comme la cuisine (backend) et la salle de restaurant (frontend).

### **Bug**
Erreur dans le code qui cause un comportement inattendu. Vient d'un vrai insecte trouvé dans un ordinateur en 1947 !

### **Cache**
Mémoire temporaire pour stocker des données fréquemment utilisées. Comme garder ses clés sur la table d'entrée au lieu de les chercher partout.

### **Compilation**
Processus qui transforme le code source humain en code machine exécutable. Comme traduire un livre français en chinois.

### **Cookie**
Petit fichier stocké par le navigateur pour se souvenir des informations sur un site. Comme un bracelet d'identification dans un parc d'attractions.

### **Debugging**
Processus de recherche et correction des bugs. Comme jouer au détective pour résoudre un mystère.

### **Déploiement**
Action de mettre une application en production pour que les utilisateurs puissent l'utiliser. Comme ouvrir un magasin au public.

### **DevOps**
Pratiques combinant développement (Dev) et opérations (Ops) pour livrer rapidement et fiablement. Comme une équipe de F1 ultra-coordonnée.

### **Docker**
Outil pour empaqueter une application avec toutes ses dépendances dans un "conteneur" portable. Comme une valise parfaitement organisée.

### **Framework**
Structure de base réutilisable pour développer des applications. Comme un kit de construction avec des pièces pré-assemblées.

### **Git**
Système de contrôle de version pour suivre les modifications du code. Comme un historique magique qui permet de revenir en arrière.

### **HTTP/HTTPS**
Protocoles de communication web. HTTP = conversation normale, HTTPS = conversation chuchotée et sécurisée.

### **IDE (Integrated Development Environment)**
Logiciel tout-en-un pour écrire du code (éditeur, debugger, etc.). Comme un atelier complet pour bricoleur.

### **JSON (JavaScript Object Notation)**
Format simple pour échanger des données entre applications. Comme un formulaire structuré et lisible.

### **Latence**
Temps d'attente avant qu'une réponse arrive. Comme le délai entre poser une question et entendre la réponse.

### **Load Balancer**
Répartit la charge entre plusieurs serveurs pour éviter la surcharge. Comme un régulateur de trafic intelligent.

### **Microservices**
Architecture divisant une grosse application en petits services indépendants. Comme remplacer un gros camion par une flotte de scooters.

### **Node.js**
Environnement permettant d'exécuter JavaScript côté serveur. Comme parler français en Chine grâce à un traducteur.

### **Open Source**
Code source disponible publiquement que tout le monde peut voir et modifier. Comme une recette de cuisine partagée.

### **RAM (Random Access Memory)**
Mémoire temporaire ultra-rapide de l'ordinateur. Comme un bureau où on étale les documents sur lesquels on travaille.

### **Repository (Repo)**
Dossier contenant tout le code d'un projet avec son historique. Comme une bibliothèque pour un projet spécifique.

### **SaaS (Software as a Service)**
Logiciel utilisé via internet sans installation. Comme louer une voiture au lieu de l'acheter.

### **SQL (Structured Query Language)**
Langage pour interroger et manipuler les bases de données. Comme poser des questions très précises à un bibliothécaire.

### **Stack technique**
Ensemble des technologies utilisées dans un projet. Comme la liste d'ingrédients d'une recette.

### **URL (Uniform Resource Locator)**
Adresse web d'une ressource. Comme l'adresse postale d'une maison sur internet.

### **Version Control**
Système pour suivre et gérer les modifications du code. Comme tenir un journal détaillé de tous les changements.

### **Virtual Machine (VM)**
Ordinateur simulé dans un ordinateur réel. Comme avoir plusieurs appartements dans le même immeuble.

### **Webhook**
Mécanisme permettant à une application d'envoyer automatiquement des données à une autre. Comme un facteur qui livre automatiquement le courrier.

### **Workspace**
Environnement de travail organisé pour un projet. Comme un bureau bien rangé avec tous les outils nécessaires.

---

## Termes spécifiques Rust

### **Cargo**
Gestionnaire de paquets et outil de build pour Rust. Comme un assistant personnel pour développeur Rust.

### **Crate**
Paquet/bibliothèque Rust. Comme une boîte à outils spécialisée qu'on peut réutiliser.

### **Ownership**
Système unique de Rust pour gérer la mémoire sans garbage collector. Comme des règles strictes de propriété d'objets.

### **Trait**
Interface définissant des comportements que les types peuvent implémenter. Comme un contrat de comportement.

### **Lifetime**
Durée de vie d'une référence en Rust. Comme la date d'expiration d'un produit.

### **Match**
Système de correspondance de motifs très puissant en Rust. Comme un aiguilleur ultra-intelligent.

### **Borrowing**
Mécanisme permettant d'utiliser une valeur sans en prendre possession. Comme emprunter un livre à la bibliothèque.

### **Panic**
Arrêt brutal du programme en cas d'erreur critique. Comme le bouton d'arrêt d'urgence d'une machine.

---

## Termes réseau et sécurité

### **Firewall**
Barrière de sécurité filtrant le trafic réseau. Comme un vigile à l'entrée d'un bâtiment.

### **Load Testing**
Tests simulant une forte charge pour vérifier la résistance du système. Comme tester un pont avec des camions lourds.

### **Penetration Testing**
Tests de sécurité simulant des attaques réelles. Comme faire appel à un cambrioleur professionnel pour tester ses serrures.

### **Rate Limiting**
Limitation du nombre de requêtes par unité de temps. Comme un péage qui régule le flux de voitures.

### **SSL Certificate**
Certificat prouvant l'identité d'un site web. Comme une carte d'identité pour sites internet.

### **VPN (Virtual Private Network)**
Tunnel sécurisé pour protéger sa connexion internet. Comme un passage secret pour naviguer anonymement.

---

*Ce glossaire enrichi contient maintenant plus de 150 termes pour aider les débutants à mieux comprendre l'écosystème technique de Miaou.*