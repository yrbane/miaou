# Support Mobile - Android & iOS

## Vue d'ensemble

Miaou fournit un support natif pour les plateformes mobiles Android et iOS via des bindings Rust/JNI et Rust/Objective-C. Cette approche garantit des performances optimales tout en réutilisant la logique métier commune.

## Architecture mobile

### Structure des crates

```
src/
├── lib.rs          # Bibliothèque principale
├── core.rs         # Logique métier commune
├── mobile.rs       # Module mobile spécialisé
└── bin/
    └── cli.rs      # Point d'entrée CLI
```

### Features Cargo

Le projet utilise un système de features pour adapter la compilation aux différentes plateformes :

- `default = ["desktop"]` - Configuration par défaut
- `mobile` - Fonctionnalités communes mobile
- `android` - Support Android spécifique
- `ios` - Support iOS spécifique

## Support Android

### Configuration Cargo.toml

```toml
[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
android_logger = "0.13"

[package.metadata.android]
package = "net.nethttp.miaou"
build_targets = ["aarch64-linux-android", "armv7-linux-androideabi", "i686-linux-android", "x86_64-linux-android"]
```

### Interface JNI

Le module `src/mobile.rs` expose des fonctions via JNI pour l'intégration Android :

```rust
#[no_mangle]
pub extern "system" fn Java_net_nethttp_miaou_MiaouLib_hello(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // Retourne une string Java
}

#[no_mangle]
pub extern "system" fn Java_net_nethttp_miaou_MiaouLib_initialize(
    _env: JNIEnv,
    _class: JClass,
) {
    // Initialise la bibliothèque Miaou
}
```

### Compilation Android

```bash
# Ajouter les targets Android
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Compiler pour Android
cargo build --target aarch64-linux-android --features android
```

## Support iOS

### Configuration Cargo.toml

```toml
[target.'cfg(target_os = "ios")'.dependencies]
objc = "0.2"

[package.metadata.bundle]
name = "Miaou"
identifier = "net.nethttp.miaou"
category = "social-networking"
```

### Interface Objective-C

Le module expose des fonctions C compatibles avec Objective-C :

```rust
#[no_mangle]
pub extern "C" fn miaou_hello() -> *const c_char {
    // Retourne une string C
}

#[no_mangle]
pub extern "C" fn miaou_initialize() {
    // Initialise la bibliothèque Miaou
}

#[no_mangle]
pub extern "C" fn miaou_free_string(ptr: *mut c_char) {
    // Libère la mémoire allouée
}
```

### Compilation iOS

```bash
# Ajouter les targets iOS
rustup target add aarch64-apple-ios x86_64-apple-ios

# Compiler pour iOS
cargo build --target aarch64-apple-ios --features ios
```

## Fonctionnalités communes mobile

### Trait PlatformInterface

Toutes les plateformes implémentent un trait commun :

```rust
pub trait PlatformInterface {
    fn initialize(&mut self) -> Result<(), String>;
    fn get_platform_name(&self) -> &'static str;
}
```

### Gestion des ressources

- **Logging** : Configuration spécifique par plateforme
- **Stockage** : Adaptation aux répertoires système mobile
- **Réseau** : Gestion des changements de connectivité
- **Notifications** : Support des notifications push natives

## Roadmap mobile

### Phase 1 - Infrastructure (v0.1.0)
- [x] Configuration de base Android/iOS
- [x] Bindings JNI et Objective-C
- [x] Compilation multi-targets
- [ ] Tests sur émulateurs

### Phase 2 - Interface native (v0.4.0)
- [ ] Application Android native
- [ ] Application iOS native
- [ ] Interface utilisateur adaptative
- [ ] Notifications push

### Phase 3 - Fonctionnalités avancées (v0.6.0)
- [ ] Intégration carnet d'adresses
- [ ] Partage de fichiers mobile
- [ ] Mode background intelligent
- [ ] Synchronisation cross-device

## Outils de développement

### Android
- **Android Studio** - IDE principal
- **cargo-ndk** - Helper pour compilation Android
- **gradle** - Système de build Android

### iOS
- **Xcode** - IDE principal
- **cargo-lipo** - Helper pour compilation iOS universelle
- **cbindgen** - Génération des headers C

## Sécurité mobile

### Stockage sécurisé
- **Android** : Android Keystore pour les clés
- **iOS** : Keychain Services
- **Chiffrement** : Clés privées jamais en plain text

### Réseau
- **Certificate pinning** : Validation des certificats serveur
- **Tor support** : Routing via réseau Tor sur mobile
- **Network detection** : Adaptation au type de réseau

### Permissions
- **Principe minimal** : Seules les permissions nécessaires
- **Runtime permissions** : Demande explicite utilisateur
- **Audit trail** : Logging des accès sensibles

## Installation et déploiement

### Android
```bash
# Build APK de debug
cargo ndk -t arm64-v8a build --features android
# Publication Play Store via fastlane
```

### iOS
```bash
# Build pour simulateur
cargo build --target x86_64-apple-ios --features ios
# Publication App Store via Xcode
```

## Tests mobile

### Tests unitaires
```bash
# Tests Android
cargo test --target aarch64-linux-android --features android

# Tests iOS  
cargo test --target aarch64-apple-ios --features ios
```

### Tests d'intégration
- **Émulateurs** : Tests automatisés sur CI/CD
- **Devices physiques** : Tests manuels critiques
- **Performance** : Profiling mémoire et CPU

Cette architecture mobile garantit une base solide pour le développement d'applications Miaou natives performantes sur Android et iOS.