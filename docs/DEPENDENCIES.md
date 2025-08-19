# 📦 POLITIQUE DES DÉPENDANCES

*Gestion stricte des dépendances externes pour Miaou*

---

## 🎯 Philosophie

**Miaou privilégie la sécurité et l'auditabilité** par rapport à la commodité de développement. Chaque dépendance externe représente une surface d'attaque potentielle et doit être justifiée par un bénéfice sécuritaire ou technique majeur.

**Principe directeur :** *Faire confiance mais vérifier* - Utiliser les meilleures bibliothèques auditées plutôt que de réinventer des primitives critiques.

---

## ✅ DÉPENDANCES AUTORISÉES

### **🔐 Cryptographie (OBLIGATOIRES)**
*Primitives audit´ees par des experts - ne JAMAIS réimplémenter*

```toml
# Cryptographie symétrique et authentifiée
ring = "0.17"                    # ✅ Audit Google, primitives AEAD
chacha20poly1305 = "0.10"        # ✅ RustCrypto, RFC 8439

# Cryptographie asymétrique  
ed25519-dalek = "2.0"            # ✅ dalek-cryptography, Ed25519
x25519-dalek = "2.0"             # ✅ dalek-cryptography, X25519

# Fonctions de hachage
blake3 = "1.5"                   # ✅ Audit officiel BLAKE3
sha3 = "0.10"                    # ✅ RustCrypto, FIPS 202
argon2 = "0.5"                   # ✅ RustCrypto, RFC 9106

# Protocoles éprouvés
libsignal-protocol = "0.1"       # ✅ Signal Foundation, X3DH + Double Ratchet
rustls = "0.21"                  # ✅ TLS 1.3 pur Rust, audité
```

**Justification :** Ces bibliothèques ont subi des audits de sécurité professionnels et implémentent des standards cryptographiques éprouvés. Les réimplémenter serait dangereux.

### **🌐 Réseau et Communication**
*Standards ouverts pour interopérabilité*

```toml
# WebRTC et ICE 
webrtc = "0.7"                   # ✅ Standard W3C, NAT traversal
tokio = "1.35"                   # ✅ Runtime async mature, largement audité
quinn = "0.10"                   # ✅ QUIC/HTTP3 pour transport moderne

# Sérialisation sécurisée
serde = { version = "1.0", default-features = false }  # ✅ Pas de dérive non contrôlée
bincode = "1.3"                  # ✅ Sérialisation binaire déterministe
```

**Justification :** WebRTC évite la réimplémentation complexe de NAT traversal. Tokio est le standard de facto pour async Rust.

### **🧪 Outils de développement**
*Amélioration qualité et productivité*

```toml
# Tests et qualité
proptest = "1.4"                 # ✅ Tests de propriétés
criterion = "0.5"                # ✅ Benchmarking précis
cargo-tarpaulin = "0.27"         # ✅ Couverture de code
cargo-audit = "0.18"             # ✅ Audit vulnérabilités

# Sécurité mémoire
zeroize = "1.7"                  # ✅ Nettoyage sécurisé des secrets
subtle = "2.5"                   # ✅ Opérations constant-time
```

**Justification :** Outils essentiels pour maintenir la qualité et la sécurité du code.

---

## 🚫 DÉPENDANCES INTERDITES

### **❌ Catégories absolument bannies**

```toml
# Cryptographie custom ou non-auditée
crypto = "*"                     # ❌ Trop générique, pas d'audit spécifique  
openssl = "*"                    # ❌ Binding C/C++, surface d'attaque
sodiumoxide = "*"                # ❌ Bindings libsodium, préférer pur Rust

# Frameworks lourds
actix-web = "*"                  # ❌ Trop lourd pour serveur intégré minimal
rocket = "*"                     # ❌ Framework web complet non nécessaire
diesel = "*"                     # ❌ ORM complexe, pas de BDD relationnelle

# Sérialisation non-déterministe  
serde_json = "*"                 # ❌ JSON non-déterministe pour crypto
yaml-rust = "*"                  # ❌ Parsing complexe, surface d'attaque
toml = "*"                       # ❌ Seulement pour config, pas pour protocole

# Networking custom
libp2p = "*"                     # ❌ Complexité excessive, préférer WebRTC
```

### **⚠️ Justifications des interdictions**

- **Cryptographie non-auditée** : Risque de vulnérabilités subtiles
- **Bindings C/C++** : Surface d'attaque memory-unsafe  
- **Frameworks lourds** : Complexité non-nécessaire, plus de bugs
- **Sérialisation non-déterministe** : Incompatible avec signatures crypto

---

## 🔍 PROCESSUS D'ÉVALUATION

### **Critères d'acceptation d'une nouvelle dépendance**

1. **✅ Sécurité**
   - [ ] Audit de sécurité professionnel récent (< 2 ans)
   - [ ] Historique de fixes rapides des CVE
   - [ ] Mainteneurs reconnus dans la communauté
   - [ ] Code source disponible et auditable

2. **✅ Qualité technique**
   - [ ] Tests exhaustifs (couverture > 80%)
   - [ ] Documentation complète
   - [ ] API stable (pas de breaking changes fréquents)
   - [ ] Performance acceptable

3. **✅ Justification métier**
   - [ ] Complexité technique trop élevée pour réimplémentation sûre
   - [ ] Standard de l'industrie (RFC, ISO, NIST)
   - [ ] Bénéfice sécuritaire mesurable
   - [ ] Pas d'alternative plus légère

### **Processus de review**

```bash
# 1. Analyse automatique
cargo audit                      # Vulnérabilités connues
cargo deny check                 # Politique de licences

# 2. Review manuelle obligatoire
- Examen du code source des fonctions critiques
- Vérification des audits de sécurité
- Test d'intégration dans l'architecture Miaou
- Validation par le comité sécurité
```

---

## 📊 MONITORING CONTINU

### **Surveillance des dépendances**

```toml
# Cargo.toml - Versions exactes
[dependencies]
ring = "=0.17.7"                 # Pin exact pour reproductibilité
ed25519-dalek = "=2.0.0"         # Pas de mise à jour automatique
```

### **Outils de monitoring**

```bash
# CI/CD automatique
cargo audit                      # Nouvelles CVE
cargo outdated                   # Mises à jour disponibles  
cargo tree                       # Dépendances transitives

# Review mensuelle
- Analyse des nouvelles versions
- Évaluation des CVE patches
- Mise à jour contrôlée avec tests
```

---

## 🏗️ STRATÉGIE LONG TERME

### **Réduction progressive des dépendances**

**Phase 1** : Utiliser les meilleures bibliothèques auditées
```
- ring, RustCrypto : Primitives crypto
- libsignal : Protocoles éprouvés  
- webrtc : Communication P2P
```

**Phase 2** : Optimisations spécialisées
```
- Wrappers légers autour des primitives
- Réimplémentation de couches non-critiques
- Maintien des primitives crypto externes
```

**Phase 3** : Écosystème mature
```
- Bibliothèques Miaou réutilisables
- Contributions upstream aux projets utilisés
- Standards Miaou pour l'industrie
```

### **Principe d'évolution**

> **"Commencer conservateur, optimiser progressivement"**
> 
> Utiliser les meilleurs outils existants pour livrer un MVP sécurisé, puis optimiser quand l'expertise interne le permet.

---

## 🛡️ GESTION DES INCIDENTS

### **En cas de CVE critique**

1. **⚡ Action immédiate (< 24h)**
   ```bash
   # Évaluation de l'impact
   cargo audit
   grep -r "vulnerable_function" src/
   
   # Patch temporaire si disponible
   cargo update --package vulnerable_crate
   ```

2. **🔧 Solution permanente (< 7 jours)**
   - Migration vers alternative sécurisée
   - Ou réimplémentation minimale si nécessaire
   - Tests exhaustifs de non-régression

3. **📢 Communication transparente**
   - Security advisory sur GitHub
   - Notification utilisateurs actifs
   - Post-mortem public

---

## 📞 CONTACTS ET RESSOURCES

### **Équipe dependencies**
- **Lead** : Responsable politique dépendances
- **Security** : Validation audits et CVE
- **Legal** : Vérification licences

### **Ressources externes**
- **RustSec** : https://rustsec.org/ (CVE database Rust)
- **Crates.io Security** : https://blog.rust-lang.org/category/security.html
- **NIST NVD** : https://nvd.nist.gov/ (CVE générales)

---

*La sécurité commence par de bonnes fondations. Choisissons nos dépendances avec la rigueur d'un cryptographe.* 🔐