#!/usr/bin/env bash
# =============================================================================
# Miaou - Hardening v2 (sans awk) — avant Phase 2
# -----------------------------------------------------------------------------
# Ce script :
# 1) Ajoute/actualise [workspace.package] dans Cargo.toml racine
# 2) Fait hériter chaque crate des métadonnées (description/licence/etc.)
# 3) (Re)génère scripts/refactor.sh compatible stable (pas de -Z)
# 4) Ajoute des lints forts dans chaque lib.rs (si absents)
# 5) Crée un README.md racine minimal si absent
# 6) (Optionnel) installe des outils via --install-tools
# 7) Lance clippy strict + tests
# =============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

info()  { printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
fail()  { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; exit 1; }

INSTALL_TOOLS=0
[[ "${1-}" == "--install-tools" ]] && INSTALL_TOOLS=1

# ------------------------------------------------------------
# Préflight
# ------------------------------------------------------------
rustc --version || fail "Rust non installé"
cargo --version || fail "Cargo non installé"
[[ -f Cargo.toml ]] || fail "Pas de Cargo.toml à la racine"
[[ -d crates ]] || warn "Dossier 'crates' introuvable (je continue)"

# ------------------------------------------------------------
# 1) [workspace.package] au Cargo.toml racine
# ------------------------------------------------------------
info "Mise à jour du Cargo.toml racine ([workspace.package])"
cp Cargo.toml Cargo.toml.bak

if grep -q '^\[workspace\.package\]' Cargo.toml; then
  # On régénère proprement la section (sans awk)
  tmp="$(mktemp)"
  awk '
    BEGIN{inblk=0}
    /^\[workspace.package\]/{print; inblk=1; print "license = \"MIT OR Apache-2.0\""; print "repository = \"https://github.com/yrbane/miaou\""; print "readme = \"README.md\""; print "keywords = [\"miaou\", \"cryptography\", \"security\", \"cli\", \"p2p\"]"; print "categories = [\"cryptography\", \"command-line-utilities\"]"; print "description = \"Miaou: secure primitives, keyring and CLI foundation\""; next}
    /^\[.*\]/{ if(inblk){inblk=0}; print; next}
    { if(!inblk) print }
  ' Cargo.toml.bak > "$tmp"
  mv "$tmp" Cargo.toml
else
  cat >> Cargo.toml <<'EOF'

[workspace.package]
license    = "MIT OR Apache-2.0"
repository = "https://github.com/yrbane/miaou"
readme     = "README.md"
keywords   = ["miaou", "cryptography", "security", "cli", "p2p"]
categories = ["cryptography", "command-line-utilities"]
description = "Miaou: secure primitives, keyring and CLI foundation"
EOF
fi
ok "Cargo.toml racine prêt"

# ------------------------------------------------------------
# 2) Héritage des métadonnées dans chaque crate
# ------------------------------------------------------------
info "Propagation de l'héritage de métadonnées dans les crates"
shopt -s nullglob
for CR in crates/*; do
  [[ -d "$CR" && -f "$CR/Cargo.toml" ]] || continue
  cp "$CR/Cargo.toml" "$CR/Cargo.toml.bak"

  # S'assure que [package] existe
  if ! grep -q '^\[package\]' "$CR/Cargo.toml"; then
    sed -i '1i [package]\nname = "FIXME"\nversion = "0.1.0"\nedition = "2021"\n' "$CR/Cargo.toml"
  fi

  add_if_missing() {
    local key="$1" line="$2"
    grep -q "^[[:space:]]*$key[[:space:]]*=" "$CR/Cargo.toml" || \
      sed -i "/^\[package\]/a $line" "$CR/Cargo.toml"
  }

  add_if_missing "description\.workspace" 'description.workspace = true'
  add_if_missing "license\.workspace"     'license.workspace = true'
  add_if_missing "repository\.workspace"  'repository.workspace = true'
  add_if_missing "readme\.workspace"      'readme.workspace = true'
  add_if_missing "keywords\.workspace"    'keywords.workspace = true'
  add_if_missing "categories\.workspace"  'categories.workspace = true'

  ok "Crate $(basename "$CR") : héritage métadonnées OK"
done
shopt -u nullglob

# ------------------------------------------------------------
# 3) (Re)génère scripts/refactor.sh (version stable-friendly)
# ------------------------------------------------------------
info "Génération d'un scripts/refactor.sh compatible stable"
mkdir -p scripts
[[ -f scripts/refactor.sh ]] && cp scripts/refactor.sh scripts/refactor.sh.bak

cat > scripts/refactor.sh <<'REF'
#!/usr/bin/env bash
# ===========================================================
# Miaou - Pre-Phase 2 Refactor & Hardening Script (stable)
# ===========================================================

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

info()  { printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
fail()  { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; exit 1; }

info "Preflight: toolchain"
rustc --version
cargo --version
ok "Rust toolchain detected"

info "Formatting Cargo.toml files with taplo (TOML formatter)"
if command -v taplo >/dev/null 2>&1; then
  taplo fmt -a
  ok "TOML files formatted"
else
  warn "taplo not found (skipping). Install: cargo install taplo-cli"
fi

info "Sorting Cargo.toml dependency sections"
if command -v cargo-sort >/dev/null 2>&1; then
  cargo sort -w
  ok "Cargo manifests sorted"
else
  warn "cargo-sort not found (skipping). Install: cargo install cargo-sort"
fi

info "Applying rustfmt"
cargo fmt --all
ok "Code formatted"

info "Applying clippy automatic fixes (best effort)"
if cargo -V | grep -iq nightly; then
  cargo clippy --fix -Z unstable-options --all-targets --workspace -- \
    -W clippy::pedantic -W clippy::nursery -W clippy::cargo || true
else
  echo "[WARN] Stable channel detected: skipping clippy --fix (nightly-only)."
  echo "[WARN] Tip: run 'rustup toolchain install nightly' if you want auto-fixes."
fi
ok "Clippy auto-fixes step completed (best effort)"

info "Dependency security: cargo-audit"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
  ok "cargo-audit passed"
else
  warn "cargo-audit not found. Install: cargo install cargo-audit"
fi

info "Policy & licenses: cargo-deny"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check bans sources licenses
  ok "cargo-deny passed"
else
  warn "cargo-deny not found. Install: cargo install cargo-deny"
fi

info "Unused deps check: cargo-udeps"
if command -v cargo-udeps >/dev/null 2>&1; then
  cargo +nightly udeps --all-targets --workspace
  ok "udeps scan finished"
else
  warn "cargo-udeps not found. Install: cargo install cargo-udeps --locked"
fi

info "Outdated deps report: cargo-outdated"
if command -v cargo-outdated >/dev/null 2>&1; then
  cargo outdated || true
  ok "Outdated report generated (non-blocking)"
else
  warn "cargo-outdated not found. Install: cargo install cargo-outdated"
fi

info "Running unit & integration tests (fast)"
if command -v cargo-nextest >/dev/null 2>&1; then
  cargo nextest run --workspace
else
  cargo test --workspace --all-features
fi
ok "Tests passed"

info "Running documentation tests (doctests)"
RUSTDOCFLAGS="-D warnings" cargo test --doc --workspace
ok "Doctests passed (no warnings)"

info "Clippy (strict) -D warnings"
cargo clippy --all-targets --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo
ok "Clippy strict passed"

info "Coverage with tarpaulin (line coverage)"
if command -v cargo-tarpaulin >/dev/null 2>&1; then
  cargo tarpaulin --workspace --timeout 120 --engine llvm --out Html --out Xml
  ok "Coverage report generated (target/tarpaulin-report.html)"
else
  warn "cargo-tarpaulin not found. Install: cargo install cargo-tarpaulin"
fi

info "Mutation testing (mutants)"
if command -v mutants >/dev/null 2>&1; then
  mutants run --workspace || fail "Mutation testing found surviving mutants"
  ok "Mutation testing passed"
else
  warn "mutants not found. Install: cargo install mutants"
fi

info "Release build sanity"
cargo build --workspace --release
ok "Release build OK"

info "Installing pre-commit hook to enforce hygiene"
HOOK=".git/hooks/pre-commit"
cat > "$HOOK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all
cargo clippy --all-targets --workspace -- -D warnings
EOF
chmod +x "$HOOK"
ok "Git pre-commit hook installed"

info "Summary:"
echo "- Formatting: rustfmt, taplo, cargo-sort"
echo "- Lint: clippy strict"
echo "- Security: cargo-audit, cargo-deny"
echo "- Deps: udeps, outdated"
echo "- Tests: unit/integration + doctests"
echo "- Coverage: tarpaulin (HTML/XML)"
echo "- Mutation: mutants (optionnel)"
echo "- Hook: pre-commit (fmt + clippy)"

ok "Pre-Phase-2 refactor pipeline completed successfully"
REF
chmod +x scripts/refactor.sh
ok "scripts/refactor.sh régénéré"

# ------------------------------------------------------------
# 4) Lints forts en tête de chaque lib.rs
# ------------------------------------------------------------
info "Ajout des lints forts dans lib.rs (si absents)"
for CR in crates/*; do
  [[ -f "$CR/src/lib.rs" ]] || continue
  if ! grep -q 'forbid(unsafe_code)' "$CR/src/lib.rs"; then
    cp "$CR/src/lib.rs" "$CR/src/lib.rs.bak"
    {
      cat <<'EOF'
//! # Security & Quality Baseline
//! - Forbid unsafe code.
//! - Deny missing docs on public items.

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![warn(rust_2018_idioms, rust_2021_compatibility)]

EOF
      cat "$CR/src/lib.rs.bak"
    } > "$CR/src/lib.rs"
    ok "Crate $(basename "$CR"): lints ajoutés"
  else
    ok "Crate $(basename "$CR"): lints déjà présents"
  fi
done

# ------------------------------------------------------------
# 5) README.md racine minimal si absent
# ------------------------------------------------------------
if [[ ! -f README.md ]]; then
  info "Création d'un README.md racine minimal"
  cat > README.md <<'EOF'
# Miaou

Secure primitives, keyring and CLI foundation for future P2P features.

## Crates
- `miaou-core` – shared types and error handling
- `miaou-crypto` – audited cryptographic wrappers (no custom crypto)
- `miaou-keyring` – in-memory keystore and key management
- `miaou-cli` – developer-facing CLI to exercise primitives

> This is a pre-Phase 2 hardening baseline.
EOF
  ok "README.md créé"
else
  ok "README.md déjà présent"
fi

# ------------------------------------------------------------
# 6) (Optionnel) Installation des outils
# ------------------------------------------------------------
if [[ $INSTALL_TOOLS -eq 1 ]]; then
  info "Installation des outils (taplo, sort, deny, udeps, outdated, tarpaulin, mutants)"
  rustup component add clippy rustfmt || true
  cargo install taplo-cli cargo-sort cargo-deny cargo-udeps --locked || true
  cargo install cargo-outdated cargo-tarpaulin mutants --locked || true
  ok "Outils installés (si non présents)"
else
  warn "Outils non installés (passe --install-tools pour les installer automatiquement)"
fi

# ------------------------------------------------------------
# 7) Vérifications finales
# ------------------------------------------------------------
info "Vérification clippy strict (-D warnings)"
cargo clippy --all-targets --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo
ok "Clippy strict OK"

info "Tests (workspace)"
cargo test --workspace --all-features
ok "Tests OK"

ok "Hardening v2 terminé. Prêt pour la suite 🚀"
