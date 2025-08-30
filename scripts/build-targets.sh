#!/bin/bash
# Script de build multi-plateforme pour Miaou v0.1.0
# Automatise la compilation pour différentes cibles

set -euo pipefail

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration des targets disponibles
DESKTOP_TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

MOBILE_TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi" 
    "i686-linux-android"
    "x86_64-linux-android"
    "aarch64-apple-ios"
    "x86_64-apple-ios"
)

WASM_TARGETS=(
    "wasm32-unknown-unknown"
    "wasm32-wasi"
)

# Fonction pour installer une target si nécessaire
ensure_target() {
    local target=$1
    if ! rustup target list --installed | grep -q "^$target$"; then
        log_info "Installation de la target $target..."
        rustup target add "$target"
    fi
}

# Fonction pour build une target spécifique
build_target() {
    local target=$1
    local profile=${2:-release}
    
    log_info "Build pour $target avec profil $profile..."
    
    # Sélection du profil approprié
    case $target in
        *android*|*ios*)
            profile="release-mobile"
            ;;
        wasm32*)
            profile="release-wasm"
            ;;
    esac
    
    if cargo build --target "$target" --profile "$profile" --workspace; then
        log_success "Build réussi pour $target"
        return 0
    else
        log_error "Échec du build pour $target"
        return 1
    fi
}

# Fonction pour build les tests pour une target
test_target() {
    local target=$1
    
    log_info "Tests pour $target..."
    
    if cargo test --target "$target" --workspace; then
        log_success "Tests réussis pour $target"
        return 0
    else
        log_error "Échec des tests pour $target"
        return 1
    fi
}

# Fonction pour créer les archives de distribution
package_release() {
    local target=$1
    local profile=${2:-release}
    
    log_info "Packaging pour $target..."
    
    local build_dir="target/$target/$profile"
    local package_dir="dist/$target"
    
    mkdir -p "$package_dir"
    
    # Copier les binaires
    if [[ -f "$build_dir/miaou-cli" ]]; then
        cp "$build_dir/miaou-cli" "$package_dir/"
    elif [[ -f "$build_dir/miaou-cli.exe" ]]; then
        cp "$build_dir/miaou-cli.exe" "$package_dir/"
    fi
    
    # Copier les libs pour WASM
    if [[ $target == wasm32* ]]; then
        find "$build_dir" -name "*.wasm" -exec cp {} "$package_dir/" \;
    fi
    
    # Créer l'archive
    cd dist
    case $target in
        *windows*)
            zip -r "${target}.zip" "$target"
            ;;
        *)
            tar -czf "${target}.tar.gz" "$target"
            ;;
    esac
    cd ..
    
    log_success "Package créé pour $target"
}

# Fonction principale
main() {
    local mode=${1:-"desktop"}
    local do_test=${2:-false}
    
    log_info "🐱 Build multi-plateforme Miaou v0.1.0"
    log_info "Mode: $mode, Tests: $do_test"
    
    # Vérifications préliminaires
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo non trouvé. Installez Rust d'abord."
        exit 1
    fi
    
    # Sélection des targets selon le mode
    local targets=()
    case $mode in
        "desktop")
            targets=("${DESKTOP_TARGETS[@]}")
            ;;
        "mobile") 
            targets=("${MOBILE_TARGETS[@]}")
            ;;
        "wasm")
            targets=("${WASM_TARGETS[@]}")
            ;;
        "all")
            targets=("${DESKTOP_TARGETS[@]}" "${MOBILE_TARGETS[@]}" "${WASM_TARGETS[@]}")
            ;;
        *)
            # Target spécifique
            targets=("$mode")
            ;;
    esac
    
    # Stats
    local success=0
    local total=${#targets[@]}
    local failed_targets=()
    
    # Clean des builds précédents
    log_info "Nettoyage des builds précédents..."
    cargo clean
    
    # Build pour chaque target
    for target in "${targets[@]}"; do
        log_info "=== Processing $target ===" 
        
        # Installation de la target si nécessaire
        ensure_target "$target"
        
        # Build
        if build_target "$target"; then
            ((success++))
            
            # Tests si demandés et pour les targets compatibles
            if [[ $do_test == "true" && $target != wasm32* ]]; then
                if ! test_target "$target"; then
                    log_warn "Tests échoués pour $target mais build OK"
                fi
            fi
            
            # Packaging pour release
            package_release "$target"
        else
            failed_targets+=("$target")
        fi
        
        echo ""
    done
    
    # Résumé final
    log_info "=== RÉSUMÉ ==="
    log_info "Targets réussies: $success/$total"
    
    if [[ ${#failed_targets[@]} -gt 0 ]]; then
        log_warn "Targets échouées:"
        for target in "${failed_targets[@]}"; do
            log_error "  - $target"
        done
    fi
    
    if [[ $success -eq $total ]]; then
        log_success "🎉 Tous les builds ont réussi!"
        exit 0
    else
        log_error "❌ Certains builds ont échoué."
        exit 1
    fi
}

# Aide
show_help() {
    cat << EOF
Usage: $0 [MODE] [--test]

MODES:
  desktop     Build pour les plateformes desktop (défaut)
  mobile      Build pour Android et iOS
  wasm        Build pour WebAssembly
  all         Build pour toutes les plateformes
  <target>    Build pour une target spécifique

OPTIONS:
  --test      Lance aussi les tests pour chaque target compatible

EXEMPLES:
  $0                                    # Desktop seulement
  $0 mobile                             # Mobile seulement
  $0 all --test                         # Tout avec tests
  $0 x86_64-unknown-linux-gnu          # Target spécifique
EOF
}

# Parse des arguments
if [[ $# -eq 0 ]]; then
    main "desktop" false
elif [[ $1 == "--help" || $1 == "-h" ]]; then
    show_help
elif [[ $# -eq 1 ]]; then
    main "$1" false
elif [[ $# -eq 2 && $2 == "--test" ]]; then
    main "$1" true
else
    log_error "Arguments invalides. Utilisez --help pour l'aide."
    exit 1
fi