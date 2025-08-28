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

## Nouveaux termes v0.2.0 "Radar Moustaches" 

### **Adresse IP non-loopback**
Adresse réseau réelle (192.168.x.x, 10.x.x.x, 172.x.x.x) permettant la communication entre machines différentes, contrairement à l'adresse loopback (127.0.0.1) qui ne fonctionne qu'en local.

### **Backoff exponentiel**
Algorithme qui augmente progressivement le délai entre les tentatives de reconnexion (1s, 2s, 4s, 8s...). Comme faire des pauses de plus en plus longues après chaque échec.

### **Bootstrap DHT**
Processus d'initialisation d'un nœud DHT en se connectant à des nœuds de démarrage connus pour découvrir le réseau distribué.

### **Candidate ICE**
Information de connectivité (adresse IP + port) découverte par le protocole ICE pour établir une connexion P2P. Comme une option de chemin possible pour joindre quelqu'un.

### **collect_peers()**
Méthode critique qui synchronise la découverte de pairs avant de les lister, résolvant les problèmes de timing inter-processus.

### **Connection state**
État d'une connexion réseau : Connecting (en cours), Connected (établie), Closed (fermée). Comme le statut d'un appel téléphonique.

### **Data Channel**
Canal de communication bidirectionnel dans WebRTC permettant l'échange de données entre pairs. Comme un tuyau digital pour faire passer des informations.

### **Dead Letter Queue (DLQ)**
Queue spéciale stockant les messages qui ont échoué après tous les essais de livraison. Comme une boîte de retour pour courrier non-distribué.

### **DHT K-buckets**
Listes ordonnées de pairs connues dans une DHT Kademlia, organisées par distance XOR. Comme un carnet d'adresses très intelligent.

### **Discovery trait**
Interface abstraite définissant les méthodes pour découvrir des pairs sur le réseau (start, discovered_peers, collect_peers).

### **Directory trait**  
Interface abstraite pour les annuaires distribués définissant put/get pour stocker et récupérer des clés publiques.

### **FileMessageStore**
Implémentation persistante de stockage des messages utilisant des fichiers JSON atomiques pour garantir la durabilité.

### **FIND_NODE (DHT)**
Requête DHT Kademlia pour trouver les K pairs les plus proches d'un identifiant donné. Comme demander les voisins les plus proches d'une adresse.

### **FQDN (Fully Qualified Domain Name)**
Nom de domaine complet incluant tous les niveaux hiérarchiques. Comme une adresse postale complète avec rue, ville, pays.

### **get_local_ip()**
Fonction utilitaire qui détecte l'adresse IP locale non-loopback de la machine, cruciale pour l'annonce mDNS correcte.

### **Hex matching**
Algorithme de correspondance des identifiants de pairs supportant les formats courts (8...8) et complets hexadécimaux.

### **ICE negotiation**
Processus WebRTC d'échange et de test des candidats de connectivité pour établir la meilleure connexion P2P possible.

### **mDNS multicast**
Diffusion de découverte de services sur le réseau local utilisant l'adresse multicast 224.0.0.251. Comme crier son nom dans une foule.

### **mDNS service resolution**
Processus automatique (mdns-sd) qui traduit un ServiceFound en adresses IP concrètes via ServiceResolved.

### **MessageId**
Identifiant unique généré pour chaque message envoyé, permettant le suivi et la confirmation de livraison.

### **MessageQueue trait**
Interface abstraite définissant send/receive/get_stats pour les systèmes de messagerie avec garanties de livraison.

### **Mock ICE**
Simulation simplifiée de la négociation ICE pour le MVP v0.2.0, avant l'implémentation complète STUN/TURN en v0.3.0.

### **Network crate**
Nouveau crate v0.2.0 contenant toute l'infrastructure P2P : discovery, transport, messaging, DHT, peer management.

### **Peer discovery timing**
Problématique de synchronisation entre processus CLI où les pairs peuvent ne pas être immédiatement visibles après démarrage.

### **PeerInfo struct**
Structure complète contenant id, clé publique, adresses, protocoles et métadonnées d'un pair réseau.

### **PeerMetadata**
Informations additionnelles d'un pair : version protocole, nom d'affichage, capacités, score de réputation.

### **Priority queuing**
Système de priorisation des messages (High/Normal/Low) dans la queue pour traiter les urgents en premier.

### **QueueStats**
Métriques temps réel d'une queue de messages : messages en attente, traités, échecs, latence moyenne.

### **Retry automatique**
Mécanisme qui retente automatiquement les opérations échouées avec des délais croissants (1s, 2s, 3s).

### **ServiceFound event**
Événement mDNS indiquant qu'un service a été découvert, suivi automatiquement par la résolution d'adresse.

### **ServiceResolved event**  
Événement mDNS fournissant les adresses IP concrètes d'un service précédemment découvert.

### **STORE (DHT)**
Commande DHT Kademlia pour publier une paire clé-valeur dans le réseau distribué, répliquée sur plusieurs nœuds.

### **Transport trait**
Interface abstraite définissant create_outbound/accept_inbound pour les connexions réseau P2P.

### **UnifiedDiscovery**
Gestionnaire combinant plusieurs méthodes de découverte (mDNS, DHT, Bootstrap) dans une interface unique.

### **WebRtcConnection**
Wrapper Miaou autour des connexions WebRTC natives, gérant l'état et les data channels de manière simplifiée.

### **WebRtcTransport**
Implémentation du trait Transport utilisant WebRTC pour les connexions P2P réelles avec data channels.

### **XOR distance metric**
Métrique de distance utilisée dans Kademlia DHT, calculée par XOR bit-à-bit des identifiants. Plus la distance est petite, plus les nœuds sont "proches".

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

## Commandes CLI v0.2.0

### **net-start**
Commande CLI qui démarre le service réseau P2P complet : discovery mDNS + transport WebRTC + messaging. Comme allumer sa radio pour pouvoir communiquer.

### **net-list-peers**
Commande CLI qui liste tous les pairs découverts sur le réseau local avec leurs identifiants et adresses IP. Comme regarder qui est connecté au WiFi.

### **net-connect**
Commande CLI qui établit une connexion WebRTC vers un pair spécifique via son identifiant. Comme composer un numéro de téléphone.

### **send <to> <message>**
Commande CLI qui envoie un message chiffré à un destinataire via la queue persistante. Le message est automatiquement chiffré avec la clé publique du destinataire.

### **recv**
Commande CLI qui récupère et déchiffre tous les messages en attente dans la queue locale. Comme relever sa boîte aux lettres.

### **dht-put <type> <key-hex>**
Commande CLI qui publie une clé cryptographique dans l'annuaire DHT distribué. Types supportés : signing, encryption.

### **dht-get <peer-id> <type>**
Commande CLI qui recherche une clé cryptographique d'un pair dans l'annuaire DHT distribué. Comme chercher le numéro de quelqu'un dans l'annuaire.

---

## Termes simples ajoutés v0.2.0

### **Adresse IP**
Numéro unique identifiant une machine sur un réseau, comme 192.168.1.100. Similaire à une adresse postale pour les ordinateurs.

### **ANSI color codes**
Codes spéciaux ajoutés au texte pour les couleurs dans le terminal. Souvent nettoyés avec `sed 's/\\x1b\\[[0-9;]*m//g'` pour l'analyse.

### **Atomique (opération)**
Opération qui s'exécute complètement ou pas du tout, sans état intermédiaire. Comme un interrupteur : allumé ou éteint, jamais entre les deux.

### **Background process**
Processus qui s'exécute en arrière-plan sans interface utilisateur. Comme un service qui travaille discrètement.

### **Bidirectionnel**
Communication qui fonctionne dans les deux sens simultanément. Comme une conversation téléphonique normale.

### **Bonjour (Apple)**
Implémentation Apple du protocole mDNS pour la découverte de services réseau. Comme mDNS mais avec la marque Apple.

### **Candidat de connectivité**
Option de chemin réseau testée pour établir une connexion P2P. Comme essayer différentes routes pour aller quelque part.

### **Chiffrement automatique**
Processus où les messages sont chiffrés transparentement sans intervention utilisateur. Comme une enveloppe qui se ferme automatiquement.

### **Code ANSI**
Séquences de caractères contrôlant l'affichage du texte (couleurs, position) dans les terminaux. Souvent invisibles mais présentes.

### **Daemon mode**
Mode où une application s'exécute en permanence en arrière-plan comme un service système. Comme un gardien de nuit qui surveille toujours.

### **Délai de timeout**
Durée maximale d'attente avant d'abandonner une opération. Comme raccrocher après 30 secondes si personne ne répond.

### **Durée (option CLI)**
Paramètre `--duration` spécifiant combien de temps un service doit fonctionner avant de s'arrêter automatiquement.

### **E2E testing**
Tests qui vérifient le fonctionnement complet d'un système de bout en bout. Comme tester tout le parcours d'un colis de l'expéditeur au destinataire.

### **Fallback**
Solution de repli utilisée quand la méthode principale échoue. Comme prendre le bus quand sa voiture tombe en panne.

### **GREEN phase (TDD)**
Phase du TDD où on écrit le code minimal pour faire passer les tests. Après RED (tests qui échouent) et avant REFACTOR (nettoyage).

### **Handshake**
Échange initial entre deux parties pour établir une communication sécurisée. Comme se serrer la main avant de parler affaires.

### **Inter-processus**
Communication ou coordination entre différents programmes qui s'exécutent simultanément. Comme la coordination entre plusieurs équipes.

### **JSON atomique**
Écriture de fichiers JSON de manière indivisible pour éviter la corruption des données. Tout s'écrit ou rien ne s'écrit.

### **Loopback address**
Adresse IP spéciale (127.0.0.1) qui renvoie vers la même machine, utilisée pour les tests locaux. Comme parler dans un miroir.

### **Matching (correspondance)**
Processus de comparaison pour trouver des éléments qui se correspondent. Comme apparier des chaussettes de la même couleur.

### **MVP (version)**
Minimum Viable Product - version basique mais fonctionnelle d'un logiciel. Comme une voiture de base qui roule mais sans options.

### **Multicast**
Envoi simultané d'un message à plusieurs destinataires sur le réseau. Comme faire une annonce avec un porte-voix dans une cour d'école.

### **Non-loopback**
Adresse IP "vraie" permettant la communication entre différentes machines, contrairement aux adresses locales (127.0.0.1).

### **Pair ID court**
Version raccourcie d'un identifiant de pair au format "debut...fin" (ex: "a1b2c3d4...e5f6g7h8"). Plus facile à lire et taper.

### **Perfect Forward Secrecy**
Garantie qu'une compromission des clés actuelles ne permet pas de déchiffrer les communications passées. Chaque session a ses propres clés éphémères.

### **Port réseau**
Numéro identifiant un service spécifique sur une machine (ex: port 80 pour HTTP). Comme un numéro d'appartement dans un immeuble.

### **Production-ready**
Logiciel suffisamment robuste et testé pour être utilisé en environnement de production réel. Prêt pour les vrais utilisateurs.

### **Radar (métaphore)**
Référence au nom "Radar Moustaches" - capacité de découvrir les autres machines sur le réseau comme un radar détecte les objets.

### **Réseau local (LAN)**
Réseau limité géographiquement comme celui d'une maison ou bureau. Toutes les machines peuvent se "voir" directement.

### **Script de validation**
Programme automatique qui vérifie le bon fonctionnement d'un système. Comme une checklist automatique.

### **Service réseau**
Programme qui fournit des fonctionnalités accessibles via le réseau. Comme un magasin qui sert les clients.

### **SocketAddr**
Structure technique combinant une adresse IP et un port réseau. Adresse complète pour joindre un service spécifique.

### **TDD systématique**
Application rigoureuse du Test-Driven Development pour chaque nouvelle fonctionnalité. Pas d'exceptions, toujours des tests d'abord.

### **Timing issue**
Problème de synchronisation où différentes parties du système ne sont pas coordonnées dans le temps. Comme arriver en retard à un rendez-vous.

### **Versioning (clés DHT)**
Système de numérotation des clés publiques dans l'annuaire distribué permettant les mises à jour. Comme un numéro de version sur un document.

---

*Ce glossaire enrichi contient maintenant plus de 200 termes pour aider les débutants à mieux comprendre l'écosystème technique de Miaou v0.2.0.*