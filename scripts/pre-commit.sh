#!/bin/bash
# Hook de validation pre-commit pour Miaou
# Garantit la qualité du code avant chaque commit

set -e

# Couleurs pour output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Vérification des outils requis
check_tools() {
    log_info "Vérification des outils requis..."
    
    local tools=("cargo" "rustc" "rustfmt" "clippy")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Outils manquants: ${missing_tools[*]}"
        log_info "Installez avec: rustup component add rustfmt clippy"
        exit 1
    fi
    
    log_success "Tous les outils requis sont disponibles"
}

# Formatage du code
format_code() {
    log_info "Formatage du code avec rustfmt..."
    
    if ! cargo fmt --check; then
        log_warning "Code non formaté détecté, application du formatage..."
        cargo fmt
        log_success "Code formaté automatiquement"
    else
        log_success "Code déjà correctement formaté"
    fi
}

# Linting avec clippy
lint_code() {
    log_info "Analyse statique avec clippy..."
    
    # Configuration stricte de clippy pour Miaou
    local clippy_args=(
        "--all-features"
        "--all-targets"
        "--"
        "-D" "warnings"
        "-D" "clippy::pedantic"
        "-D" "clippy::nursery" 
        "-D" "clippy::cargo"
        "-A" "clippy::multiple_crate_versions"  # Acceptable pour dépendances
        "-A" "clippy::cargo_common_metadata"    # Géré au niveau workspace
    )
    
    if ! cargo clippy "${clippy_args[@]}"; then
        log_error "Clippy a détecté des problèmes dans le code"
        log_info "Corrigez les warnings avant de commiter"
        exit 1
    fi
    
    log_success "Analyse statique réussie"
}

# Tests unitaires
run_tests() {
    log_info "Exécution des tests unitaires..."
    
    if ! cargo test --all-features --lib; then
        log_error "Tests unitaires échoués"
        exit 1
    fi
    
    log_success "Tests unitaires réussis"
}

# Tests de documentation
test_docs() {
    log_info "Tests de la documentation..."
    
    if ! cargo test --doc; then
        log_error "Tests de documentation échoués"
        exit 1
    fi
    
    log_success "Tests de documentation réussis"
}

# Vérification de la couverture de code
check_coverage() {
    log_info "Vérification de la couverture de code..."
    
    # Vérifier si cargo-tarpaulin est installé
    if ! command -v cargo-tarpaulin &> /dev/null; then
        log_warning "cargo-tarpaulin non installé, installation..."
        cargo install cargo-tarpaulin
    fi
    
    # Exécuter tarpaulin et capturer la couverture
    local coverage_output
    coverage_output=$(cargo tarpaulin --all-features --out Stdout --timeout 120 2>/dev/null | grep -oP '\d+\.\d+(?=%)' | head -1)
    
    if [ -z "$coverage_output" ]; then
        log_error "Impossible de mesurer la couverture de code"
        exit 1
    fi
    
    local coverage_percent=$(echo "$coverage_output" | cut -d'.' -f1)
    
    if [ "$coverage_percent" -lt 90 ]; then
        log_error "Couverture insuffisante: ${coverage_output}% (minimum 90%)"
        log_info "Ajoutez des tests pour atteindre le seuil requis"
        exit 1
    fi
    
    log_success "Couverture de code: ${coverage_output}% (≥90% ✓)"
}

# Tests cryptographiques (si module crypto présent)
test_crypto() {
    if [ -d "src/crypto" ] || grep -q "crypto" Cargo.toml; then
        log_info "Exécution des tests cryptographiques spécialisés..."
        
        # Tests avec vecteurs connus (KAT - Known Answer Tests)
        if ! cargo test crypto::tests::known_answer_tests --release; then
            log_error "Tests cryptographiques KAT échoués"
            exit 1
        fi
        
        # Tests de propriétés cryptographiques
        if ! cargo test crypto::tests::property_tests --release; then
            log_error "Tests de propriétés cryptographiques échoués"
            exit 1
        fi
        
        log_success "Tests cryptographiques réussis"
    fi
}

# Audit de sécurité des dépendances
security_audit() {
    log_info "Audit de sécurité des dépendances..."
    
    # Vérifier si cargo-audit est installé
    if ! command -v cargo-audit &> /dev/null; then
        log_warning "cargo-audit non installé, installation..."
        cargo install cargo-audit
    fi
    
    if ! cargo audit; then
        log_error "Vulnérabilités détectées dans les dépendances"
        log_info "Mettez à jour les dépendances ou ajoutez des exceptions justifiées"
        exit 1
    fi
    
    log_success "Audit de sécurité réussi"
}

# Génération de la documentation
generate_docs() {
    log_info "Génération de la documentation rustdoc..."
    
    local doc_args=(
        "--all-features"
        "--no-deps"
        "--document-private-items"
    )
    
    if ! cargo doc "${doc_args[@]}"; then
        log_error "Génération de documentation échouée"
        exit 1
    fi
    
    log_success "Documentation rustdoc générée"
}

# Vérification des benchmarks (si présents)
check_benchmarks() {
    if [ -d "benches" ] || find . -name "*.rs" -exec grep -l "#\[bench\]" {} \; | head -1 > /dev/null; then
        log_info "Vérification des benchmarks..."
        
        if ! cargo bench --no-run; then
            log_error "Compilation des benchmarks échouée"
            exit 1
        fi
        
        log_success "Benchmarks compilent correctement"
    fi
}

# Vérification spécifique par phase de développement
phase_specific_checks() {
    local current_branch=$(git branch --show-current)
    
    case "$current_branch" in
        *premiere-griffe*)
            log_info "Vérifications Phase 1 (Fondations cryptographiques)..."
            test_crypto
            ;;
        *radar-moustaches*)
            log_info "Vérifications Phase 2 (Réseau P2P)..."
            # Tests spécifiques réseau
            if ! cargo test network::tests::integration_tests --release; then
                log_error "Tests d'intégration réseau échoués"
                exit 1
            fi
            ;;
        *ronron-bonheur*)
            log_info "Vérifications Phase 3 (Économie)..."
            # Tests économiques spécifiques
            if ! cargo test blockchain::tests::economic_simulation --release; then
                log_error "Tests de simulation économique échoués"
                exit 1
            fi
            ;;
        *toilettage-royal*)
            log_info "Vérifications Phase 4 (UI/UX)..."
            # Tests multi-plateforme
            check_mobile_compilation
            ;;
        *)
            log_info "Branche générique, vérifications standards"
            ;;
    esac
}

# Vérification compilation mobile (Phase 4+)
check_mobile_compilation() {
    log_info "Vérification compilation mobile..."
    
    # Test compilation Android (si targets installés)
    if rustup target list --installed | grep -q "aarch64-linux-android"; then
        if ! cargo check --target aarch64-linux-android --features android; then
            log_error "Compilation Android échouée"
            exit 1
        fi
        log_success "Compilation Android réussie"
    fi
    
    # Test compilation iOS (si targets installés)
    if rustup target list --installed | grep -q "aarch64-apple-ios"; then
        if ! cargo check --target aarch64-apple-ios --features ios; then
            log_error "Compilation iOS échouée"
            exit 1
        fi
        log_success "Compilation iOS réussie"
    fi
}

# Résumé final
print_summary() {
    echo ""
    log_success "🎉 Toutes les validations sont réussies !"
    echo ""
    log_info "Résumé des vérifications :"
    echo "  ✅ Formatage du code"
    echo "  ✅ Analyse statique (clippy)"
    echo "  ✅ Tests unitaires"
    echo "  ✅ Tests documentation"
    echo "  ✅ Couverture de code ≥90%"
    echo "  ✅ Audit de sécurité"
    echo "  ✅ Documentation rustdoc"
    echo "  ✅ Vérifications spécifiques à la phase"
    echo ""
    log_success "Commit autorisé ! 🚀"
}

# Point d'entrée principal
main() {
    echo ""
    log_info "🔍 Validation pre-commit Miaou démarrée..."
    echo ""
    
    check_tools
    format_code
    lint_code
    run_tests
    test_docs
    check_coverage
    security_audit
    generate_docs
    check_benchmarks
    phase_specific_checks
    
    print_summary
}

# Exécution uniquement si appelé directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi