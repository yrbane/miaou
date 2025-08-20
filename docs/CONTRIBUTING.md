# 🤝 GUIDE DE CONTRIBUTION

*Guidelines pour contribuer au projet Miaou*

---

## 🏴‍☠️ Philosophie de contribution

**Miaou incarne un esprit de liberté numérique et de résistance technologique.** Contribuer à Miaou, c'est participer à la construction d'un outil d'émancipation numérique.

**Nos valeurs :**
- **Pragmatisme technique** : Code robuste et auditable
- **Intransigeance sur les principes** : Décentralisation et confidentialité
- **Qualité non négociable** : Standards professionnels stricts
- **Esprit pirate** : Contourner les limitations, connecter les îlots

---

## ⚡ Exigences techniques NON NÉGOCIABLES

### **📋 Qualité du code**
- **🏗️ Architecture SOLID** : Respect strict des 5 principes
- **🧪 TDD obligatoire** : Tests écrits AVANT le code
- **📊 Couverture >= 90%** : Mesurée avec cargo-tarpaulin + fuzzing obligatoire
- **🧪 Tests KAT crypto** : Vecteurs officiels pour primitives cryptographiques
- **🚫 Zéro commit** si tests critiques échouent
- **📝 Commentaires exhaustifs** en français
- **📚 Documentation stricte obligatoire** : `#![warn(missing_docs)]` dans TOUS les crates
- **🔐 Sécurité by design** : Validation et sanitization systématiques

### **🧩 Architecture modulaire**
- **🔬 Micro-responsabilités** : Un crate = une fonction précise
- **📋 Allowlist de dépendances** : Seules les dépendances auditées autorisées (voir DEPENDENCIES.md)
- **🔗 Dépendances internes autorisées** entre crates Miaou
- **🔌 Hiérarchie claire** : Pas de dépendances circulaires
- **🔍 Audit continu** : cargo-audit en CI pour vulnérabilités

### **🌍 Standards internationaux**
- **🌐 i18n dès le départ** : Pas de strings hardcodées
- **♿ Accessibilité WCAG 2.1 AA** minimum
- **📱 Responsive** : Adaptation tous écrans
- **🎨 Templates externes** : Séparation logique/présentation

---

## 🛠️ Processus de développement

### **1. 🍴 Fork et setup**
```bash
# Fork du repo sur GitHub
git clone https://github.com/VOTRE_USERNAME/miaou.git
cd miaou

# Configuration des hooks pre-commit
cargo install cargo-tarpaulin cargo-mutagen
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### **2. 🌿 Workflow Git par versions**

Le projet utilise une stratégie de branches dédiées par version majeure :

```
main (production)
├── v0.1.0-premiere-griffe (Phase 1 - Fondations crypto)
├── v0.2.0-radar-moustaches (Phase 2 - Réseau P2P)  
├── v0.3.0-ronron-bonheur (Phase 3 - Économie gamification)
├── v0.4.0-toilettage-royal (Phase 4 - UI/UX multi-plateforme)
├── v0.5.0-chat-gouttiere (Phase 5 - Interopérabilité)
├── v0.6.0-neuf-vies (Phase 6 - Fonctionnalités avancées)
└── v1.0.0-matou-majestueux (Phase 7 - Production complète)
```

**📖 Documentation complète :** [GIT_WORKFLOW.md](GIT_WORKFLOW.md)

```bash
# Développement sur une version spécifique
git checkout v0.1.0-premiere-griffe  # Exemple pour Phase 1

# Créer une branche de fonctionnalité depuis la version
git checkout -b feature/crypto-primitives v0.1.0-premiere-griffe

# OU pour un bugfix
git checkout -b fix/description-bug

# OU pour de la documentation
git checkout -b docs/sujet-modifie
```

### **3. 🧪 Développement TDD strict**
```bash
# 1. Écrire les tests d'abord
cargo test nom_du_test -- --ignored

# 2. Lancer les tests (qui doivent échouer)
cargo test

# 3. Écrire le minimum de code pour passer
# 4. Refactorer en gardant les tests verts
# 5. Répéter
```

### **4. ✅ Checklist avant commit**
- [ ] **Tests écrits AVANT le code**
- [ ] **Tous les tests passent** : `cargo test`
- [ ] **Couverture >= 95%** : `cargo tarpaulin --verbose`
- [ ] **Linting clean** : `cargo clippy -- -D warnings`
- [ ] **Format Rust** : `cargo fmt`
- [ ] **Documentation stricte** : `cargo doc --no-deps` + pas d'avertissements missing_docs
- [ ] **Commentaires en français** pour la logique métier
- [ ] **Pas de `println!` ou `dbg!`** dans le code final

### **5. 📝 Messages de commit**
```bash
# Format : type(scope): description courte

# Types autorisés :
feat(crypto): ajoute chiffrement ChaCha20-Poly1305
fix(network): corrige timeout connexion P2P  
docs(readme): met à jour installation
test(messaging): ajoute tests unitaires envoi
refactor(ui): simplifie gestion des thèmes
perf(blockchain): optimise validation des blocs
security(auth): durcit vérification signatures

# Le message doit être en français
# Ligne 1 : < 50 caractères
# Ligne 3+ : détails si nécessaire
```

---

## 🏗️ Architecture et conventions

### **📦 Structure des crates**
```
nom-du-domaine/
├── Cargo.toml          # Métadonnées et dépendances
├── src/
│   ├── lib.rs          # Point d'entrée avec documentation
│   ├── error.rs        # Types d'erreur spécifiques
│   ├── config.rs       # Configuration (si applicable)
│   └── modules/        # Modules fonctionnels
├── tests/              # Tests d'intégration
├── benches/            # Benchmarks
└── examples/           # Exemples d'usage
```

### **🔐 Conventions de sécurité**
```rust
// ✅ BON : Types sécurisés
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; 32]);

// ❌ INTERDIT : Debug sur secrets
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

// ✅ BON : Validation des entrées
pub fn decrypt_message(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidInput);
    }
    // ...
}
```

### **📝 Documentation stricte obligatoire**

**🚫 RÈGLES NON NÉGOCIABLES :**
- **TOUS les crates** doivent avoir `#![warn(missing_docs)]` en début de `lib.rs` ou `main.rs`
- **TOUS les items publics** doivent être documentés (modules, fonctions, structs, enums, champs)
- **TOUS les paramètres** et valeurs de retour doivent être expliqués
- **TOUS les types d'erreur** possibles doivent être documentés

```rust
//! Documentation du crate obligatoire
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

/// Chiffre un message avec l'algorithme ChaCha20-Poly1305.
/// 
/// Cette fonction implémente le chiffrement authentifié AEAD en utilisant
/// une clé dérivée via HKDF et un nonce aléatoire généré de manière sécurisée.
///
/// # Arguments
/// 
/// * `plaintext` - Le message en clair à chiffrer
/// * `key` - La clé de chiffrement (32 bytes)
/// * `associated_data` - Données authentifiées non chiffrées
///
/// # Exemples
///
/// ```rust
/// use crypto_encryption::encrypt_message;
/// 
/// let message = b"Message secret";
/// let key = generate_key();
/// let result = encrypt_message(message, &key, b"headers")?;
/// ```
///
/// # Erreurs
///
/// Retourne `CryptoError::InvalidKey` si la clé n'a pas la bonne taille.
pub fn encrypt_message(
    plaintext: &[u8], 
    key: &Key, 
    associated_data: &[u8]
) -> Result<EncryptedMessage, CryptoError> {
    // Implémentation...
}

/// Structure représentant un profil utilisateur
pub struct ProfileInfo {
    /// Nom du profil choisi par l'utilisateur
    pub name: String,
    /// Identifiant unique généré automatiquement
    pub id: ProfileId,
}
```

---

## 🧪 Tests et qualité

### **Types de tests obligatoires**
```rust
// 1. Tests unitaires
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"test message";
        let key = generate_test_key();
        
        let encrypted = encrypt_message(plaintext, &key, b"").unwrap();
        let decrypted = decrypt_message(&encrypted, &key, b"").unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    // 2. Tests de propriétés
    proptest! {
        #[test]
        fn encryption_is_deterministic_with_same_nonce(
            plaintext in any::<Vec<u8>>(),
        ) {
            let key = generate_test_key();
            let nonce = [0u8; 12];
            
            let result1 = encrypt_with_nonce(plaintext, &key, nonce);
            let result2 = encrypt_with_nonce(plaintext, &key, nonce);
            
            prop_assert_eq!(result1, result2);
        }
    }
}

// 3. Tests d'intégration (dans tests/)
#[test]
fn integration_full_protocol_handshake() {
    // Test bout-en-bout
}

// 4. Benchmarks (dans benches/)
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_encryption(c: &mut Criterion) {
    c.bench_function("encrypt_1kb", |b| {
        let data = vec![0u8; 1024];
        let key = generate_test_key();
        
        b.iter(|| encrypt_message(&data, &key, b""))
    });
}
```

### **🔍 Outils de qualité**
```bash
# Tests avec couverture
cargo tarpaulin --verbose --timeout 120

# Tests de mutation (détecte les tests faibles)
cargo mutagen

# Linting strict
cargo clippy -- -D warnings -D clippy::pedantic

# Audit des dépendances
cargo audit

# Fuzzing (pour les parseurs)
cargo install cargo-fuzz
cargo fuzz run parser_target
```

---

## 🔐 Sécurité et cryptographie

### **❌ INTERDICTIONS ABSOLUES**
- **Pas de crypto from scratch** : OBLIGATOIRE d'utiliser ring, RustCrypto, libsignal
- **Pas de `unsafe` injustifié** autour des secrets
- **Pas de logs de secrets** : Jamais de clés en logs
- **Pas de timing attacks** : Comparaisons constant-time
- **Pas de dépendances non-auditées** : Vérifier DEPENDENCIES.md

### **✅ BONNES PRATIQUES**
```rust
// Comparaison constant-time
use subtle::ConstantTimeEq;

fn verify_signature(signature: &[u8], expected: &[u8]) -> bool {
    signature.ct_eq(expected).into()
}

// Zeroization automatique
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret {
    data: [u8; 32],
}

// Validation stricte
fn parse_message(data: &[u8]) -> Result<Message, ParseError> {
    if data.len() < HEADER_SIZE {
        return Err(ParseError::TooShort);
    }
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(ParseError::TooLong);
    }
    // ...
}
```

---

## 📋 Pull Request Process

### **1. ✅ Checklist PR**
- [ ] **Branche à jour** avec main
- [ ] **Tests passent** en local
- [ ] **Description claire** du changement
- [ ] **Screenshots** si changement UI
- [ ] **Documentation** mise à jour
- [ ] **CHANGELOG.md** mis à jour
- [ ] **Pas de breaking changes** sans discussion

### **2. 📝 Template de PR**
```markdown
## 🎯 Objectif
Brève description du problème résolu ou de la fonctionnalité ajoutée.

## 🔧 Changements
- [ ] Changement 1
- [ ] Changement 2

## 🧪 Tests
- [ ] Tests unitaires ajoutés
- [ ] Tests d'intégration mis à jour
- [ ] Benchmarks si pertinent

## 📸 Screenshots
(Si applicable)

## ⚠️ Notes pour les reviewers
Points d'attention particuliers.
```

### **3. 👀 Processus de review**
1. **Review automatique** : CI/CD doit passer
2. **Review manuelle** : Au moins 1 approbation
3. **Merge** : Squash and merge preferred
4. **Deploy** : Automatique sur branche main

---

## 🏆 Reconnaissance des contributions

### **🌟 Types de contributions valorisées**
- **Code** : Fonctionnalités, corrections, optimisations
- **Tests** : Amélioration de la couverture et qualité
- **Documentation** : Guides, exemples, traductions
- **Sécurité** : Audits, corrections de vulnérabilités
- **Design** : UI/UX, assets, thèmes
- **Infrastructure** : CI/CD, tooling, optimisations

### **🎁 Récompenses en Croquettes**
- **Première contribution** : 50 croquettes
- **Bug critique corrigé** : 100 croquettes
- **Nouvelle fonctionnalité majeure** : 200 croquettes
- **Audit de sécurité** : 500 croquettes
- **Documentation majeure** : 100 croquettes

### **🏅 Hall of Fame**
Les contributeurs exceptionnels seront mis en avant dans :
- README principal
- Site web du projet
- Crédits dans l'application

---

## 📞 Communication et support

### **💬 Canaux de communication**
- **Issues GitHub** : Bugs, demandes de fonctionnalités
- **Discussions GitHub** : Questions, idées, aide
- **Matrix/IRC** : Discussion temps réel (à venir)

### **🆘 Obtenir de l'aide**
1. **Documentation** : Lire README, CONTRIBUTING, SECURITY
2. **Glossaire** : Vérifier GLOSSAIRE.md pour les termes
3. **Issues** : Chercher les issues existantes
4. **Discussion** : Créer une discussion GitHub
5. **Direct** : Contacter les mainteneurs

---

## 🎯 Conclusion

Contribuer à Miaou, c'est participer à la construction d'un Internet plus libre et plus respectueux de la vie privée. Chaque ligne de code compte dans cette mission.

**Remember :** *Move fast and don't break cryptography* 🏴‍☠️

---

*Merci de contribuer à l'émancipation numérique !*