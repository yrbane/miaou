#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   REPO="yrbane/miaou" bash create_all_milestones.sh
# Options:
#   MODE=docs      # default: scan docs/versions/*.md on GitHub to infer titles from first H1
#   MODE=list      # read titles from env MILESTONES (comma-separated)
#   MODE=json      # read milestones from JSON file path in MILESTONES_JSON (array of objects)
#
# JSON shape (if MODE=json):
#   [
#     {"title":"v0.1.0 - Première griffe","description":"...", "due_on":"2025-09-30T00:00:00Z","state":"open"},
#     {"title":"v0.2.0 - Radar & Moustaches"}
#   ]
#
# Requirements: gh, jq, base64, awk, sed

REPO="${REPO:-yrbane/miaou}"
MODE="${MODE:-docs}"
MILESTONES_JSON="${MILESTONES_JSON:-}"
MILESTONES="${MILESTONES:-}"

command -v gh >/dev/null 2>&1 || { echo "ERROR: GitHub CLI 'gh' requis (gh auth login)"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: 'jq' requis"; exit 1; }
command -v awk >/dev/null 2>&1 || { echo "ERROR: 'awk' requis"; exit 1; }
command -v sed >/dev/null 2>&1 || { echo "ERROR: 'sed' requis"; exit 1; }

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }

fetch_milestone_number() {
  # $1: title
  local title="$1"
  gh api "repos/$REPO/milestones?state=all" --paginate \
    | jq -r --arg t "$title" 'map(select(.title==$t)) | .[0].number // empty'
}

create_or_update_milestone() {
  # args: title [description] [due_on] [state]
  local title="$1"; shift || true
  local description="${1:-}"; shift || true
  local due_on="${1:-}"; shift || true
  local state="${1:-}"    # "open" | "closed" or empty

  local num
  num="$(fetch_milestone_number "$title" || true)"
  if [[ -z "$num" ]]; then
    info "Create: $title"
    args=( -f "title=$title" )
    [[ -n "$description" ]] && args+=( -f "description=$description" )
    [[ -n "$due_on" ]]      && args+=( -f "due_on=$due_on" )
    [[ -n "$state" ]]       && args+=( -f "state=$state" )
    gh api "repos/$REPO/milestones" --method POST "${args[@]}" >/dev/null
    ok "Created: $title"
  else
    info "Update: $title (#$num)"
    args=()
    [[ -n "$description" ]] && args+=( -f "description=$description" )
    [[ -n "$due_on" ]]      && args+=( -f "due_on=$due_on" )
    [[ -n "$state" ]]       && args+=( -f "state=$state" )
    if [[ ${#args[@]} -gt 0 ]]; then
      gh api "repos/$REPO/milestones/$num" --method PATCH "${args[@]}" >/dev/null
      ok "Updated: $title (#$num)"
    else
      ok "Exists (no change): $title (#$num)"
    fi
  fi
}

create_from_docs() {
  info "Scan docs/versions on $REPO"
  # List markdown files
  local items
  if ! items="$(gh api "repos/$REPO/contents/docs/versions" -X GET 2>/dev/null)"; then
    warn "docs/versions introuvable sur le repo. Passe en MODE=list ou MODE=json."
    return 0
  fi

  echo "$items" | jq -r '.[] | select(.type=="file" and (.name|endswith(".md"))) | .path' | while read -r path; do
    info "Parse $path"
    # Fetch content, decode, extract first H1 as title; fallback to filename without .md
    local content
    if ! content="$(gh api "repos/$REPO/contents/$path" | jq -r '.content' | base64 -d 2>/dev/null)"; then
      warn "Impossible de lire $path"
      continue
    fi
    local title
    title="$(printf "%s" "$content" | awk -F'# ' '/^# /{print $2; exit}')"
    if [[ -z "$title" ]]; then
      title="$(basename "$path" .md)"
    fi
    # Optional: extract due date from a line like "due_on: 2025-09-30" or ISO datetime
    local due_on
    due_on="$(printf "%s" "$content" | awk -F': ' '/^due_on:/{print $2; exit}')"
    # Normalize due_on to ISO Z if only date present
    if [[ -n "${due_on:-}" && "$due_on" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      due_on="${due_on}T00:00:00Z"
    fi
    create_or_update_milestone "$title" "" "${due_on:-}" "open"
  done
}

create_from_list() {
  if [[ -z "${MILESTONES:-}" ]]; then
    warn "MILESTONES vide. Exemple: MILESTONES='v0.1.0 - Première griffe,v0.2.0 - Radar & Moustaches'"
    return 0
  fi
  IFS=',' read -r -a arr <<< "$MILESTONES"
  for t in "${arr[@]}"; do
    # trim spaces
    t="$(echo "$t" | sed -e 's/^ *//' -e 's/ *$//')"
    [[ -z "$t" ]] && continue
    create_or_update_milestone "$t" "" "" "open"
  done
}

create_from_json() {
  if [[ -z "${MILESTONES_JSON:-}" ]]; then
    warn "MILESTONES_JSON non défini. Fournis le chemin d'un fichier JSON."
    return 0
  fi
  [[ -f "$MILESTONES_JSON" ]] || { warn "Fichier introuvable: $MILESTONES_JSON"; return 0; }
  jq -c '.[]' "$MILESTONES_JSON" | while read -r row; do
    title="$(echo "$row" | jq -r '.title')"
    desc="$(echo "$row" | jq -r '.description // empty')"
    due="$(echo "$row" | jq -r '.due_on // empty')"
    state="$(echo "$row" | jq -r '.state // empty')"
    [[ -z "$title" ]] && { warn "Entrée JSON sans 'title'."; continue; }
    create_or_update_milestone "$title" "$desc" "$due" "$state"
  done
}

case "$MODE" in
  docs) create_from_docs ;;
  list) create_from_list ;;
  json) create_from_json ;;
  *) echo "MODE invalide: $MODE (docs|list|json)"; exit 2 ;;
esac

ok "Terminé"
