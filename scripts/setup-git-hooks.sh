#!/bin/bash
# Script de configuration des git hooks pour Miaou
# Installe les hooks dans .git/hooks/ et configure git

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Couleurs pour les logs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

main() {
    log_info "🔧 Configuration des git hooks pour Miaou"
    
    # Vérifier qu'on est dans un repo git
    if [ ! -d "$PROJECT_ROOT/.git" ]; then
        log_error "Pas dans un repository git"
        exit 1
    fi
    
    # Créer le répertoire des hooks s'il n'existe pas
    mkdir -p "$PROJECT_ROOT/.git/hooks"
    
    # Copier les hooks
    if [ -f "$PROJECT_ROOT/.githooks/pre-commit" ]; then
        cp "$PROJECT_ROOT/.githooks/pre-commit" "$PROJECT_ROOT/.git/hooks/"
        chmod +x "$PROJECT_ROOT/.git/hooks/pre-commit"
        log_success "Hook pre-commit installé"
    else
        log_warn "Hook pre-commit non trouvé dans .githooks/"
    fi
    
    # Configurer git pour utiliser les hooks
    cd "$PROJECT_ROOT"
    
    # S'assurer que les hooks sont exécutables
    if [ -f ".git/hooks/pre-commit" ]; then
        chmod +x ".git/hooks/pre-commit"
    fi
    
    # Configuration git recommandée
    log_info "📋 Configuration git recommandée..."
    
    # Configurer les fins de ligne (important pour les hooks shell)
    git config core.autocrlf false
    git config core.fileMode true
    
    # Activer les couleurs
    git config color.ui auto
    
    log_success "Git hooks configurés avec succès !"
    log_info "ℹ️  Les hooks suivants sont maintenant actifs :"
    
    if [ -f ".git/hooks/pre-commit" ]; then
        echo "  ✅ pre-commit : Formatage, linting et tests rapides"
    fi
    
    log_info "🧪 Test du hook pre-commit..."
    if ".git/hooks/pre-commit"; then
        log_success "Hook pre-commit fonctionne correctement !"
    else
        log_warn "Le hook pre-commit a échoué. Vérifiez manuellement."
    fi
    
    echo ""
    log_info "📝 Pour désactiver temporairement les hooks : git commit --no-verify"
    log_info "🔄 Pour réinstaller les hooks : ./scripts/setup-git-hooks.sh"
}

main "$@"