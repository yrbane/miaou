#!/usr/bin/env bash
# ===========================================================
# Miaou - Pre-Phase 2 Refactor & Hardening Script
# -----------------------------------------------------------
# Objectif : appliquer des améliorations automatiques, valider
# la qualité (style, lint), la sécurité (audit deps), la
# robustesse (tests, doctests, mutation/coverage) et la santé
# des dépendances avant de passer en Phase 2 (réseau).
#
# NOTE : le code (noms de fonctions/variables) reste en anglais ;
#        la documentation/commentaires sont en français (cf. consignes).
# ===========================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# --------- Helpers (affichage) ---------------------------------------------
info()  { printf "\033[1;36m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[OK]\033[0m   %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
fail()  { printf "\033[1;31m[FAIL]\033[0m %s\n" "$*"; exit 1; }

# --------- Pré-requis outils -----------------------------------------------
# Conseillé : installer ces outils au préalable (Cargo):
# cargo-audit, cargo-deny, cargo-outdated, cargo-udeps, cargo-tarpaulin,
# cargo-nextest, cargo-sort, taplo-cli, mutants (mutation testing)
# rustup component add clippy rustfmt
# npm i -g license-checker (si tu as du JS/TS dans le monorepo)
# ---------------------------------------------------------------------------

# --------- 0) Préflight -----------------------------------------------------
info "Preflight: toolchain"
rustc --version
cargo --version
ok "Rust toolchain detected"

# --------- 1) Normalisation TOML & Cargo -----------------------------------
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

# --------- 2) Format & quick auto-fix --------------------------------------
info "Applying rustfmt"
cargo fmt --all
ok "Code formatted"

info "Applying clippy automatic fixes (non-breaking lints)"
rustup component add clippy >/dev/null 2>&1 || true
cargo clippy --fix -Z unstable-options --all-targets --workspace -- \
  -W clippy::pedantic -W clippy::nursery -W clippy::cargo || true
ok "Clippy auto-fixes applied (best effort)"

# --------- 3) Sécurité dépendances -----------------------------------------
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

# --------- 4) Tests & Doctests ---------------------------------------------
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

# --------- 5) Lint strict ---------------------------------------------------
info "Clippy (strict) -D warnings"
cargo clippy --all-targets --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo
ok "Clippy strict passed"

# --------- 6) Couverture ----------------------------------------------------
info "Coverage with tarpaulin (line coverage)"
if command -v cargo-tarpaulin >/dev/null 2>&1; then
  # Génère un rapport Cobertura + HTML si config tarpaulin présente
  cargo tarpaulin --workspace --timeout 120 --engine llvm --out Html --out Xml
  ok "Coverage report generated (target/tarpaulin-report.html)"
else
  warn "cargo-tarpaulin not found. Install: cargo install cargo-tarpaulin"
fi

# --------- 7) Mutation testing (si mutants dispo) --------------------------
info "Mutation testing (mutants)"
if command -v mutants >/dev/null 2>&1; then
  # Exécute les mutants sur les crates sensibles (crypto/core)
  mutants run --workspace || fail "Mutation testing found surviving mutants"
  ok "Mutation testing passed"
else
  warn "mutants not found. Install: cargo install mutants"
fi

# --------- 8) Build release sanity -----------------------------------------
info "Release build sanity"
cargo build --workspace --release
ok "Release build OK"

# --------- 9) Hooks & conventions ------------------------------------------
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

# --------- 10) Résumé -------------------------------------------------------
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
 