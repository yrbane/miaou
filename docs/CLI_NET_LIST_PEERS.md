# CLI net-list-peers - Issue #2 Implementation

## 📋 Résumé

Implémentation complète de la commande `net unified list-peers` selon les spécifications de l'issue #2, avec retries exponentiels, codes de retour corrects, et format JSON spécifié.

## 🔧 Fonctionnalités Implémentées

### ✅ Retries avec Backoff Exponentiel
- **Pattern** : Timeout initial → 1s → 2s → 3s
- **Total** : 3 tentatives supplémentaires après le timeout initial
- **Indication visuelle** : `🔄 Tentative N avec délai de Xs...`

### ✅ Codes de Retour Corrects (Issue #2)
- **Code 0** : ≥1 pair découvert (succès)
- **Code 2** : Aucun pair découvert après tous les retries  
- **Code 1** : Erreur technique (réseau, JSON, etc.)

### ✅ Format JSON Spécifié
```json
{
  "discovered_peers": [
    {
      "id": "full_peer_id",
      "short_id": "short_id",
      "addresses": ["192.168.1.100:54321"],
      "protocols": ["mDNS", "DHT"],
      "latency_ms": null
    }
  ],
  "count": 0,
  "timestamp": 1756537876,
  "discovery_timeout_sec": 5,
  "total_attempts": 3,
  "methods": ["mDNS", "DHT"]
}
```

### ✅ Timing Fix (collect_peers avant discovered_peers)
Séquence correcte pour chaque tentative :
1. `discovery.start()`
2. `sleep(timeout/delay)`
3. `discovery.collect_peers()` ← **FIX TIMING**
4. `discovery.discovered_peers()`
5. `discovery.stop()`

## 🚀 Commande et Usage

### Syntaxe
```bash
# Découverte avec timeout de 5s (défaut)
miaou-cli net unified list-peers

# Timeout personnalisé
miaou-cli net unified list-peers --timeout 10

# Format JSON
miaou-cli --json net unified list-peers --timeout 5
```

### Codes de Sortie
```bash
# Test succès (pairs trouvés)
echo $?  # → 0

# Test aucun pair
echo $?  # → 2  

# Test erreur
echo $?  # → 1
```

## 🧪 Tests Automatisés

### Suite de Tests d'Intégration
- **`test_net_list_peers_no_peers_exit_code_2`** : Validation code retour 2
- **`test_net_list_peers_json_format`** : Structure JSON valide
- **`test_net_list_peers_retry_behavior`** : Timing des retries (5-10s)
- **`test_net_list_peers_help`** : Aide disponible
- **`test_net_list_peers_with_different_timeouts`** : Flexibilité timeout
- **`test_net_list_peers_error_handling`** : Gestion paramètres invalides

### Exécution Tests
```bash
# Test spécifique code retour 2
cargo test --package miaou-cli --test net_list_peers_integration test_net_list_peers_no_peers_exit_code_2

# Tous les tests d'intégration
cargo test --package miaou-cli --test net_list_peers_integration

# Test avec logs détaillés
RUST_LOG=info cargo test --package miaou-cli --test net_list_peers_integration -- --nocapture
```

## 📊 Critères d'Acceptation Validés

### ✅ Critère Issue #2.1: Timing Fix
- `collect_peers()` appelé avant `discovered_peers()` dans chaque retry
- Séquence start → sleep → collect → discover → stop respectée

### ✅ Critère Issue #2.2: Format JSON
- Structure avec `discovered_peers`, `count`, `timestamp`
- Champs `id`, `short_id`, `addresses`, `protocols`, `latency_ms`
- JSON valide et bien formatté

### ✅ Critère Issue #2.3: Codes Retour
- 0 pour succès (≥1 peer découvert)
- 2 pour échec normal (0 peer après retries)
- 1 pour erreur technique

### ✅ Critère Issue #2.4: Retries Backoff
- Pattern 1s → 2s → 3s après timeout initial
- Messages informatifs `🔄 Tentative N...`
- Arrêt anticipé si pairs trouvés

### ✅ Critère Issue #2.5: Performance LAN
- **Timeout** : Configurable (défaut 5s)
- **Total Max** : ~11s (5s initial + 1+2+3s retries)
- **Critère "2 instances → ≥1 peer sous 8s"** : ✅ Respecté si pairs présents

### ✅ Critère Issue #2.6: Tests CLI
- Suite complète de tests d'intégration
- Validation codes retour, JSON, timing
- Couverture succès/aucun/erreur

## 🔄 Architecture Technique

### Modifications Apportées

1. **`miaou-core/src/lib.rs`**
   - Ajout `MiaouError::NoPeersDiscovered` pour code retour 2

2. **`miaou-cli/src/main.rs`**
   - Mise à jour `main()` pour gérer le code retour 2
   - Refactoring complet de `UnifiedCommand::ListPeers`
   - Pattern retry avec backoff exponentiel
   - Format JSON conforme aux spécifications

3. **`miaou-cli/tests/net_list_peers_integration.rs`** (nouveau)
   - Suite de tests d'intégration complète
   - Validation codes retour, JSON, timing

4. **`miaou-cli/Cargo.toml`**
   - Ajout dépendances test : `assert_cmd`, `predicates`

### Compatibilité
- ✅ Rétrocompatible avec comportement existant
- ✅ Conserve la commande legacy `NetListPeers`
- ✅ Améliore seulement `net unified list-peers`

## 🎯 Impact et Bénéfices

### Pour les Utilisateurs
- **Fiabilité** : Retries automatiques si échec temporaire
- **Clarté** : Codes retour distincts pour différents cas
- **Intégration** : Format JSON standardisé pour scripts

### Pour le Développement
- **Tests** : Suite complète d'intégration
- **Monitoring** : Codes retour pour supervision
- **Debug** : Logs structurés avec indicateurs visuels

L'implémentation est **production-ready** et respecte tous les critères de l'issue #2.