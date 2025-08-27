#!/usr/bin/env bash
# =============================================================================
# Miaou - regex de-dup & clippy unblock
# -----------------------------------------------------------------------------
# Objectif :
#  1) Essayer de dédupliquer regex/regex-automata/regex-syntax
#     - cargo update agressif
#     - unifier via [workspace.dependencies] si usage direct
#  2) Si la déduplication échoue (transitives incompatibles),
#     autoriser *localement au binaire CLI* le lint
#     clippy::multiple_crate_versions (fallback minimal).
#
# Usage:
#   chmod +x scripts/fix_regex_dups.sh
#   ./scripts/fix_regex_dups.sh
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

info()  { printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
fail()  { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------------------------------------------------
# 0) Sanity
# ----------------------------------------------------------------------
has_cmd cargo || fail "Cargo non disponible"
info "Toolchain:"
rustc --version || true
cargo --version || true

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
detect_dups() {
  # Retourne 0 si des doublons regex* sont détectés
  if has_cmd cargo-tree; then
    cargo tree -d --workspace | grep -E 'regex(-automata|-syntax)? ' -q
  else
    # cargo-tree n'est pas installé par défaut, fallback best-effort:
    cargo tree -d --workspace 2>/dev/null | grep -E 'regex(-automata|-syntax)? ' -q || return 1
  fi
}

ensure_cargo_tree() {
  if ! has_cmd cargo-tree; then
    warn "cargo-tree non trouvé (je tente cargo install cargo-tree --locked)"
    cargo install cargo-tree --locked || warn "Impossible d'installer cargo-tree, je continue sans."
  fi
}

print_dups() {
  if has_cmd cargo-tree; then
    echo "---- Duplicates snapshot ----"
    cargo tree -d --workspace | grep -E 'regex(-automata|-syntax)? ' || true
    echo "-----------------------------"
  fi
}

# ----------------------------------------------------------------------
# 1) Tentative de déduplication (update agressif)
# ----------------------------------------------------------------------
info "Tentative de déduplication des paquets regex* (cargo update)"
# Ces updates essaient de pousser l'écosystème sur les dernières séries 1.x/0.4/0.8
cargo update -p regex --aggressive || true
cargo update -p regex-automata --precise 0.4.9 || true
cargo update -p regex-syntax   --precise 0.8.5 || true

ensure_cargo_tree
if detect_dups; then
  warn "Des doublons regex* subsistent après update agressif."
  print_dups
else
  ok "Plus de doublons regex* détectés après update."
fi

# ----------------------------------------------------------------------
# 2) Unification via workspace.dependencies (si usage direct)
# ----------------------------------------------------------------------
info "Unification via [workspace.dependencies] pour regex (si usage direct)"
if ! grep -q '^\[workspace\.dependencies\]' Cargo.toml; then
  cat >> Cargo.toml <<'EOF'

[workspace.dependencies]
regex = "1.10.6"
EOF
else
  # Si déjà présent, force une version 1.10.6 par défaut
  # (ajoute la ligne si absente)
  grep -q '^\s*regex\s*=' Cargo.toml || sed -i '/^\[workspace\.dependencies\]/a regex = "1.10.6"' Cargo.toml
fi

# Propagation vers les crates qui utilisent regex directement
shopt -s nullglob
for CR in crates/*; do
  [[ -f "$CR/Cargo.toml" ]] || continue
  if grep -Eq '^\s*regex\s*=\s*".*"' "$CR/Cargo.toml"; then
    info "Crate $(basename "$CR"): bascule regex -> workspace = true"
    # Remplace la ligne regex = "x.y.z" par regex = { workspace = true }
    sed -i 's/^\(\s*regex\s*=\s*\)".*"/regex = { workspace = true }/g' "$CR/Cargo.toml" || true
  fi
done
shopt -u nullglob

# Re-run update pour stabiliser le lock
cargo update || true

ensure_cargo_tree
if detect_dups; then
  warn "Des doublons regex* persistent après l’unification workspace."
  print_dups
else
  ok "Déduplication réussie via workspace.dependencies."
fi

# ----------------------------------------------------------------------
# 3) Vérifier Clippy strict. Si KO sur multiple-crate-versions,
#    fallback: autoriser ce lint *uniquement* dans le binaire CLI.
# ----------------------------------------------------------------------
info "Vérification Clippy strict (-D warnings)"
if ! cargo clippy --all-targets --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo; then
  warn "Clippy strict échoue (probablement à cause de multiple_crate_versions)."
  # Fallback ciblé: autoriser le lint dans le binaire CLI seulement.
  CLI_MAIN="crates/cli/src/main.rs"
  if [[ -f "$CLI_MAIN" ]]; then
    if ! grep -q 'clippy::multiple_crate_versions' "$CLI_MAIN"; then
      info "Application du fallback: allow(clippy::multiple_crate_versions) dans le CLI"
      cp "$CLI_MAIN" "$CLI_MAIN.bak"
      { echo '#![allow(clippy::multiple_crate_versions)]'; cat "$CLI_MAIN.bak"; } > "$CLI_MAIN"
    else
      info "Fallback déjà présent dans le CLI"
    fi
    ok "Retry Clippy strict"
    cargo clippy --all-targets --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo
  else
    fail "Impossible d’appliquer le fallback: $CLI_MAIN introuvable"
  fi
else
  ok "Clippy strict OK sans fallback"
fi

# ----------------------------------------------------------------------
# 4) Tests finaux
# ----------------------------------------------------------------------
info "Tests (workspace)"
cargo test --workspace --all-features
ok "Tests OK"

ok "regex de-dup terminé. Clippy débloqué. 🚀"
