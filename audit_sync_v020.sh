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

# --- helpers ---
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
  if gh label view "$name" --repo "$REPO" >/dev/null 2>&1; then
    gh label edit "$name" --repo "$REPO" --description "$desc" --color "$color" >/dev/null || true
  else
    gh label create "$name" --repo "$REPO" --description "$desc" --color "$color" >/dev/null || true
  fi
}

issue_number_by_title() {
  local title="$1"
  gh issue list --repo "$REPO" --state all --json number,title | jq -r --arg t "$title" '.[] | select(.title==$t) | .number' | head -n1
}

comment_and_labels() {
  local num="$1" comment="$2"; shift 2
  gh issue comment "$num" --repo "$REPO" --body "$comment"
  if [[ $# -gt 0 ]]; then
    # For labels, we add them one by one to avoid quoting issues
    for lb in "$@"; do
      gh issue edit "$num" --repo "$REPO" -l "$lb"
    done
  fi
}

set_milestone() {
  local num="$1" title="$2"
  gh issue edit "$num" --repo "$REPO" -m "$title"
}

close_issue() {
  local num="$1"
  gh issue close "$num" --repo "$REPO" -r "completed"
}

reopen_issue() {
  local num="$1"
  gh issue reopen "$num" --repo "$REPO"
}

edit_body() {
  local num="$1" file="$2"
  gh issue edit "$num" --repo "$REPO" -F "$file"
}

# --- 1) ensure milestones and labels ---
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

# Link to doc (branch) for comments
DOC_LINK="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${DOC_V020_PATH}"

# --- 2) mapping decisions from audit ---
# Titles must match existing issues
declare -A CLOSE_OK=(
  ["[mDNS] Implémenter la découverte LAN réelle"]="true"
  ["[Tests] TDD mDNS (mocks + intégration ignorée)"]="true"
  ["[Discovery] `UnifiedDiscovery` : merge/TTL/dédup"]="true"
  ["[Docs] Checklist d’acceptance + guide démo 2 nœuds"]="true"
)

declare -A MOVE_TO_V030=(
  ["[NAT] STUN/TURN réels pour ICE"]="true"
  ["[Signaling] API d’échange SDP/Candidats"]="true"
  ["[Directory] Brancher sur la DHT (clé/valeur + TTL)"]="true"
)

# Bodies to (re)write for issues still open/refined
declare -A NEW_BODIES
NEW_BODIES["[CLI] \`net-list-peers\` démarre mDNS et affiche les pairs (JSON)"]="Contexte
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
- Audit doc v0.2.0 (branche: ${BRANCH}) : ${DOC_LINK}
"
NEW_BODIES["[WebRTC] Data Channels réels (offer/answer + ICE)"]="Contexte
La doc v0.2.0 présente des passages contradictoires (MVP simulé vs connexions réelles). Clarifier et livrer une implémentation **réelle** (webrtc-rs ou équivalent) avec DC fiables.

Tâches
- [ ] Lib WebRTC réelle (offer/answer, DTLS/SCTP).
- [ ] ICE réel consommant candidats STUN/TURN (quand prêt).
- [ ] Test e2e: message fiable via DataChannel.
- [ ] Mesure latence <200ms en LAN.
- [ ] Documenter limites actuelles.

Critères d'acceptation
- [ ] Demo `net-connect` → `send` passe sur 2 nœuds.

Référence: ${DOC_LINK}
"
NEW_BODIES["[Messaging] File & Store robustes (dédup/retry/ack)"]="Contexte
La doc v0.2.0 mentionne un FileMessageStore JSON avec retries. Finaliser dédup/ack et tests charge.

Tâches
- [ ] ID stable + dédup réception.
- [ ] Retries backoff (1s/2s/3s/… plafonné).
- [ ] Accusés de réception end-to-end.
- [ ] Tests charge: 100 messages avec pertes simulées.

Critères d'acceptation
- [ ] 100 envois → 100 acks ou erreurs claires < 60s.

Référence: ${DOC_LINK}
"
NEW_BODIES["[DHT] MVP réseau (Kademlia: ping/store/find)"]="Contexte
La doc v0.2.0 parle d'un MVP Kademlia; préciser l'état (local vs réseau). Livrer I/O réseau réel + tests multi-nœuds.

Tâches
- [ ] Messages Kademlia (PING, STORE, FIND_NODE, FIND_VALUE).
- [ ] Table de routage + timeouts/evictions.
- [ ] Tests 3–5 nœuds (lookup, put/get).
- [ ] Intégration CLI (dht-put/dht-get) avec nodes de bootstrap.

Critères d'acceptation
- [ ] PUT/GET répliqués; latence <2s en LAN.

Référence: ${DOC_LINK}
"
NEW_BODIES["[CI] GitHub Actions (fmt, clippy, test)"]="Contexte
Aucun workflow CI détecté. Ajouter pipeline standard Rust + linting + coverage (optionnel).

Tâches
- [ ] cargo fmt -- --check
- [ ] cargo clippy -- -D warnings
- [ ] cargo test (avec features nécessaires)
- [ ] Cache Rust (actions/cache)

Critères d'acceptation
- [ ] Workflow vert sur PR et push vers main.

Référence: ${DOC_LINK}
"
NEW_BODIES["[CLI] Nettoyer incohérences handshake ou implémenter MVP"]="Contexte
Le CLI référence des concepts handshake; la doc v0.2.0 introduit X3DH/Double Ratchet. Décider: masquer pour v0.2.0 ou livrer MVP clair, repousser complet en v0.3.0.

Tâches
- [ ] Option A: cacher commandes non-fonctionnelles.
- [ ] Option B: livrer MVP handshake (Noise ou pré-X3DH) stable.
- [ ] Harmoniser messages d'erreur/aide.

Critères d'acceptation
- [ ] CLI sans incohérences; chemin handshake documenté.

Référence: ${DOC_LINK}
"

# New issues to create if missing
declare -A CREATE_NEW
CREATE_NEW["[Repo] Ajouter squelette code (Cargo.toml/crates) + synchro docs"]="Contexte
Le repo actuel est majoritairement documentaire. Ajouter le squelette Rust (workspace, crates network/crypto/cli) pour aligner avec la doc v0.2.0.

Tâches
- [ ] Créer workspace Cargo + crates vides (lib + bin).
- [ ] Publier premiers modules (mdns, messaging, cli stubs).
- [ ] Intégrer pre-commit + CI.
- [ ] Mettre à jour docs pour correspondre au code réel.

Critères d'acceptation
- [ ] cargo build/test OK en CI; commandes CLI de base compilent."
CREATE_NEW["[Docs] Résoudre contradictions v0.2.0 (SIMULÉ vs RÉEL)"]="Contexte
Le document v0.2.0 présente des contradictions (WebRTC/DHT simulé vs réel).

Tâches
- [ ] Ajouter un tableau d'état par composant (Réel/Simulé/À faire).
- [ ] Corriger les sections en conflit.
- [ ] Lier issues correspondantes.

Critères d'acceptation
- [ ] Doc cohérente et alignée avec backlog."
CREATE_NEW["[Release] Notes v0.2.0 et plan de transition v0.3.0"]="Tâches
- [ ] Rédiger CHANGELOG pour v0.2.0.
- [ ] Lister fonctionnalités déplacées en v0.3.0 (STUN/TURN, signaling, DHT réseau).
- [ ] Plan de migration des issues et labels."

# --- 3) apply mapping ---
info "Application des décisions d'audit…"

# Close set
for title in "${!CLOSE_OK[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    info "Close: #$num $title"
    comment_and_labels "$num" "✅ Audit v0.2.0: considéré livré selon ${DOC_LINK}\nClôture automatique. Si désaccord, ré-ouvrez en commentant avec éléments concrets." "status:done" "v0.2.0"
    set_milestone "$num" "$V020_TITLE"
    close_issue "$num"
  else
    warn "Issue introuvable pour clôture: $title"
  fi
done

# Move to v0.3.0
for title in "${!MOVE_TO_V030[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    info "Move: #$num $title → $V030_TITLE"
    comment_and_labels "$num" "↪️ Déplacé vers **${V030_TITLE}** suite à l'audit v0.2.0.\nVoir ${DOC_LINK} (section Transition v0.3.0)." "moved:v0.3.0"
    set_milestone "$num" "$V030_TITLE"
    reopen_issue "$num" || true
  else
    warn "Issue introuvable pour déplacement: $title"
  fi
done

# Rewrite bodies for refined issues
for title in "${!NEW_BODIES[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    tmp="$(mktemp)"
    printf "%s" "${NEW_BODIES[$title]}" > "$tmp"
    info "Edit body: #$num $title"
    edit_body "$num" "$tmp"
    comment_and_labels "$num" "🛠️ Body mis à jour suivant audit v0.2.0.\nSource: ${DOC_LINK}" "status:wip"
    set_milestone "$num" "$V020_TITLE"
    rm -f "$tmp"
  else
    warn "Issue introuvable pour édition: $title"
  fi
done

# Create missing new issues
for title in "${!CREATE_NEW[@]}"; do
  num="$(issue_number_by_title "$title" || true)"
  if [[ -n "${num:-}" ]]; then
    ok "Déjà présent: #$num $title"
  else
    info "Create: $title"
    body="${CREATE_NEW[$title]}"
    gh issue create --repo "$REPO" -t "$title" -b "$body" -m "$V020_TITLE" -l "v0.2.0" -l "type:docs" >/dev/null
    ok "Créé: $title"
  fi
done

ok "Audit/Sync terminé."
