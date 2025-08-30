#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-yrbane/miaou}"
V020_TITLE="${V020_TITLE:-v0.2.0 - Radar & Moustaches}"
V030_TITLE="${V030_TITLE:-v0.3.0 - DHT & WebRTC réel}"
BRANCH="${BRANCH:-v0.2.0-radar-moustaches}"
DOC_V020_PATH="docs/versions/v0.2.0-radar-moustaches.md"

command -v gh >/dev/null 2>&1 || { echo "ERROR: gh requis (gh auth login)"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq requis"; exit 1; }

info(){ printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok(){   printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err(){  printf '\033[1;31m[ERR]\033[0m %s\n' "$*"; }

DOC_LINK="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${DOC_V020_PATH}"

# ---------- Helpers (robust, idempotent) ----------

milestone_number_by_title() {
  local title="$1"
  gh api "repos/$REPO/milestones?state=all" --paginate | jq -r --arg t "$title" 'map(select(.title==$t)) | .[0].number // empty'
}

ensure_milestone() {
  local title="$1"
  local number
  number="$(milestone_number_by_title "$title")"
  if [[ -z "$number" ]]; then
    number="$(gh api "repos/$REPO/milestones" --method POST -f "title=$title" | jq -r .number)"
    ok "Milestone créé: $title (#$number)"
  else
    ok "Milestone présent: $title (#$number)"
  fi
  echo "$number"
}

ensure_label() {
  local name="$1" desc="$2" color="$3"
  # Try edit first; if not exists, create; if still conflicts, force edit
  if gh label edit "$name" --repo "$REPO" --description "$desc" --color "$color" >/dev/null 2>&1; then
    : # edited
  else
    if gh label create "$name" --repo "$REPO" --description "$desc" --color "$color" >/dev/null 2>&1; then
      : # created
    else
      gh label edit "$name" --repo "$REPO" --description "$desc" --color "$color" >/dev/null || true
    fi
  fi
}

issue_number_by_title() {
  local title="$1"
  gh issue list --repo "$REPO" --state all --json number,title | jq -r --arg t "$title" '.[] | select(.title==$t) | .number' | head -n1
}

comment_with_file() {
  local num="$1"; shift
  local msg="$1"
  local tmp=$(mktemp)
  printf "%s" "$msg" > "$tmp"
  gh issue comment "$num" --repo "$REPO" -F "$tmp" >/dev/null
  rm -f "$tmp"
}

add_labels() {
  local num="$1"; shift
  for lb in "$@"; do
    gh issue edit "$num" --repo "$REPO" -l "$lb" >/dev/null
  done
}

set_milestone_title() {
  local num="$1" title="$2"
  gh issue edit "$num" --repo "$REPO" -m "$title" >/dev/null
}

close_issue() {
  local num="$1"
  gh issue close "$num" --repo "$REPO" -r "completed" >/dev/null
}

reopen_issue() {
  local num="$1"
  gh issue reopen "$num" --repo "$REPO" >/dev/null || true
}

edit_body_from_stdin() {
  local num="$1"
  local tmp=$(mktemp)
  cat > "$tmp"
  gh issue edit "$num" --repo "$REPO" -F "$tmp" >/dev/null
  rm -f "$tmp"
}

# ---------- Ensure milestones & labels ----------
info "Validation milestones…"
V020_NUM="$(ensure_milestone "$V020_TITLE")"
V030_NUM="$(ensure_milestone "$V030_TITLE")"

info "Validation labels…"
ensure_label "status:done" "Terminé (selon audit v0.2.0)" "0e8a16"
ensure_label "status:wip" "En cours / partiel" "fbca04"
ensure_label "moved:v0.3.0" "Déplacé vers v0.3.0" "1d76db"
ensure_label "needs:ci" "Nécessite pipeline CI" "5319e7"
ensure_label "needs:code" "Nécessite code concret dans repo" "b60205"
ensure_label "needs:clarification" "Contradiction doc à clarifier" "d4c5f9"
ensure_label "v0.2.0" "Version v0.2.0" "0e8a16"

# ---------- Decisions (titles only; bodies injected via heredocs to avoid backticks execution) ----------

# Close (considered done per doc)
CLOSE_OK_TITLES=(
  "[mDNS] Implémenter la découverte LAN réelle"
  "[Tests] TDD mDNS (mocks + intégration ignorée)"
  "[Discovery] `UnifiedDiscovery` : merge/TTL/dédup"
  "[Docs] Checklist d’acceptance + guide démo 2 nœuds"
)

# Move to v0.3.0
MOVE_TO_V030_TITLES=(
  "[NAT] STUN/TURN réels pour ICE"
  "[Signaling] API d’échange SDP/Candidats"
  "[Directory] Brancher sur la DHT (clé/valeur + TTL)"
)

# Titles to rewrite body
REWRITE_TITLES=(
  "[CLI] `net-list-peers` démarre mDNS et affiche les pairs (JSON)"
  "[WebRTC] Data Channels réels (offer/answer + ICE)"
  "[Messaging] File & Store robustes (dédup/retry/ack)"
  "[DHT] MVP réseau (Kademlia: ping/store/find)"
  "[CI] GitHub Actions (fmt, clippy, test)"
  "[CLI] Nettoyer incohérences handshake ou implémenter MVP"
)

# New issues to create if missing (handled with case below)
CREATE_TITLES=(
  "[Repo] Ajouter squelette code (Cargo.toml/crates) + synchro docs"
  "[Docs] Résoudre contradictions v0.2.0 (SIMULÉ vs RÉEL)"
  "[Release] Notes v0.2.0 et plan de transition v0.3.0"
)

# ---------- Apply ----------
info "Application des décisions d'audit…"

# Close set
for title in "${CLOSE_OK_TITLES[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    info "Close: #$num $title"
    comment_with_file "$num" "✅ Audit v0.2.0: considéré livré selon ${DOC_LINK}\nClôture automatique. Si désaccord, ré-ouvrez en commentant avec éléments concrets."
    add_labels "$num" "status:done" "v0.2.0"
    set_milestone_title "$num" "$V020_TITLE"
    close_issue "$num"
  else
    warn "Issue introuvable pour clôture: $title"
  fi
done

# Move set
for title in "${MOVE_TO_V030_TITLES[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    info "Move: #$num $title → $V030_TITLE"
    comment_with_file "$num" "↪️ Déplacé vers **${V030_TITLE}** suite à l'audit v0.2.0.\nVoir ${DOC_LINK} (section Transition v0.3.0)."
    add_labels "$num" "moved:v0.3.0"
    set_milestone_title "$num" "$V030_TITLE"
    reopen_issue "$num"
  else
    warn "Issue introuvable pour déplacement: $title"
  fi
done

# Rewrite bodies
for title in "${REWRITE_TITLES[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    info "Edit body: #$num $title"
    case "$title" in
      "[CLI] `net-list-peers` démarre mDNS et affiche les pairs (JSON)")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
La doc v0.2.0 indique mDNS réel mais un CLI encore partiellement câblé. Objectif : relier la commande au collecteur mDNS + sortie JSON propre.

Tâches
- [ ] Appeler collect_peers() avant discovered_peers() (fix timing).
- [ ] Implémenter --json (ID, adresses, proto, latence optionnelle).
- [ ] Codes retour: 0 (>=1 peer), 2 (aucun), 1 (erreur).
- [ ] Retries 1s/2s/3s (backoff) si 0 peer.

Critères d'acceptation
- [ ] Deux instances → >=1 peer listé sous 8s (LAN).
- [ ] Sortie JSON valide; tests CLI couvrant succès/aucun/erreur.

Référence
- Audit doc v0.2.0 (branche): ${DOC_LINK}
BODY
        ;;
      "[WebRTC] Data Channels réels (offer/answer + ICE)")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
La doc v0.2.0 présente des passages contradictoires (MVP simulé vs connexions réelles). Clarifier et livrer une implémentation réelle (webrtc-rs ou équivalent) avec DataChannels fiables.

Tâches
- [ ] Lib WebRTC réelle (offer/answer, DTLS/SCTP).
- [ ] ICE réel consommant candidats STUN/TURN (quand prêt).
- [ ] Test e2e: message fiable via DataChannel.
- [ ] Mesure latence <200ms en LAN.
- [ ] Documenter limites actuelles.

Critères d'acceptation
- [ ] Demo `net-connect` → `send` passe sur 2 nœuds.

Référence: ${DOC_LINK}
BODY
        ;;
      "[Messaging] File & Store robustes (dédup/retry/ack)")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
La doc v0.2.0 mentionne un FileMessageStore avec retries. Finaliser dédup/ack et tests de charge.

Tâches
- [ ] ID stable + dédup réception.
- [ ] Retries backoff (1s/2s/3s/… plafonné).
- [ ] Accusés de réception end-to-end.
- [ ] Tests charge: 100 messages avec pertes simulées.

Critères d'acceptation
- [ ] 100 envois → 100 acks ou erreurs claires < 60s.

Référence: ${DOC_LINK}
BODY
        ;;
      "[DHT] MVP réseau (Kademlia: ping/store/find)")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
La doc v0.2.0 parle d'un MVP Kademlia; préciser l'état (local vs réseau). Livrer I/O réseau réel + tests multi-nœuds.

Tâches
- [ ] Messages Kademlia (PING, STORE, FIND_NODE, FIND_VALUE).
- [ ] Table de routage + timeouts/evictions.
- [ ] Tests 3–5 nœuds (lookup, put/get).
- [ ] Intégration CLI (dht-put/dht-get) avec nodes de bootstrap.

Critères d'acceptation
- [ ] PUT/GET répliqués; latence <2s en LAN.

Référence: ${DOC_LINK}
BODY
        ;;
      "[CI] GitHub Actions (fmt, clippy, test)")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
Aucun workflow CI détecté. Ajouter pipeline standard Rust + linting + coverage (optionnel).

Tâches
- [ ] cargo fmt -- --check
- [ ] cargo clippy -- -D warnings
- [ ] cargo test (avec features nécessaires)
- [ ] Cache Rust (actions/cache)

Critères d'acceptation
- [ ] Workflow vert sur PR et push vers main.

Référence: ${DOC_LINK}
BODY
        ;;
      "[CLI] Nettoyer incohérences handshake ou implémenter MVP")
        edit_body_from_stdin "$num" <<'BODY'
Contexte
Le CLI référence des concepts handshake; la doc v0.2.0 introduit X3DH/Double Ratchet. Décider: masquer pour v0.2.0 ou livrer un MVP, repousser le complet en v0.3.0.

Tâches
- [ ] Option A: cacher commandes non-fonctionnelles.
- [ ] Option B: implémenter un MVP (Noise ou pré-X3DH) stable.
- [ ] Harmoniser messages d'erreur/aide.

Critères d'acceptation
- [ ] CLI sans incohérences; chemin handshake documenté.

Référence: ${DOC_LINK}
BODY
        ;;
    esac
    comment_with_file "$num" "🛠️ Body mis à jour suivant audit v0.2.0.\nSource: ${DOC_LINK}"
    add_labels "$num" "status:wip"
    set_milestone_title "$num" "$V020_TITLE"
  else
    warn "Issue introuvable pour édition: $title"
  fi
done

# Create missing issues
for title in "${CREATE_TITLES[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    ok "Déjà présent: #$num $title"
  else
    info "Create: $title"
    case "$title" in
      "[Repo] Ajouter squelette code (Cargo.toml/crates) + synchro docs")
        gh issue create --repo "$REPO" -t "$title" -m "$V020_TITLE" -l "v0.2.0" -l "type:docs" -b "$(cat <<'BODY'
Contexte
Le repo actuel est majoritairement documentaire. Ajouter le squelette Rust (workspace, crates network/crypto/cli) pour aligner avec la doc v0.2.0.

Tâches
- [ ] Créer workspace Cargo + crates vides (lib + bin).
- [ ] Publier premiers modules (mdns, messaging, cli stubs).
- [ ] Intégrer pre-commit + CI.
- [ ] Mettre à jour docs pour correspondre au code réel.

Critères d'acceptation
- [ ] cargo build/test OK en CI; commandes CLI de base compilent.
BODY
)"
        ;;
      "[Docs] Résoudre contradictions v0.2.0 (SIMULÉ vs RÉEL)")
        gh issue create --repo "$REPO" -t "$title" -m "$V020_TITLE" -l "v0.2.0" -l "type:docs" -b "$(cat <<'BODY'
Contexte
Le document v0.2.0 présente des contradictions (WebRTC/DHT simulé vs réel).

Tâches
- [ ] Ajouter un tableau d'état par composant (Réel/Simulé/À faire).
- [ ] Corriger les sections en conflit.
- [ ] Lier issues correspondantes.

Critères d'acceptation
- [ ] Doc cohérente et alignée avec backlog.
BODY
)"
        ;;
      "[Release] Notes v0.2.0 et plan de transition v0.3.0")
        gh issue create --repo "$REPO" -t "$title" -m "$V020_TITLE" -l "v0.2.0" -l "type:docs" -b "$(cat <<'BODY'
Tâches
- [ ] Rédiger CHANGELOG pour v0.2.0.
- [ ] Lister fonctionnalités déplacées en v0.3.0 (STUN/TURN, signaling, DHT réseau).
- [ ] Plan de migration des issues et labels.
BODY
)"
        ;;
    esac
    ok "Créé: $title"
  fi
done

ok "Audit/Sync terminé."
