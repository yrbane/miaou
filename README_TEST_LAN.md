# 🧪 Guide de Test LAN - Miaou v0.2.0

## 🎯 Test rapide de découverte mDNS (2 terminaux)

### Terminal 1 : Démarrer l'annonce mDNS
```bash
# Compiler le projet
cargo build --workspace

# NOUVELLE SYNTAXE v0.2.0: Annoncer via mDNS (60 secondes)
./target/debug/miaou-cli lan mdns announce --duration 60

# OU syntaxe legacy:
# ./target/debug/miaou-cli net-start --duration 60
```

Vous devriez voir :
```
🚀 Démarrage du service réseau P2P...
📡 Service mDNS enregistré: _miaou._tcp.local sur le port 4242
✅ Service réseau P2P démarré avec succès !
   Peer ID: cli-net-start-abc123
   Adresse: 192.168.1.100:4242
   mDNS Discovery: actif
   DHT Discovery: simulé (v0.2.0)
```

### Terminal 2 : Découvrir et se connecter
```bash
# NOUVELLE SYNTAXE v0.2.0: Découverte mDNS directe
./target/debug/miaou-cli --json lan mdns list-peers --timeout 3

# OU découverte unifiée (mDNS + DHT simulé):
./target/debug/miaou-cli --json net unified list-peers --timeout 5

# OU syntaxe legacy:
# ./target/debug/miaou-cli --json net-list-peers --timeout 3
```

Vous devriez voir du JSON comme :
```json
{
  "method": "mdns",
  "peers": [
    {
      "id": "miaou-peer-1234",
      "addresses": ["192.168.1.100:4242"]
    }
  ],
  "count": 1,
  "timeout_seconds": 3
}
```

```bash
# Se connecter à ce pair (WebRTC simulé en v0.2.0)
./target/debug/miaou-cli net-connect miaou-peer-1234
```

## 🚀 Commandes disponibles v0.2.0

### 🔍 Réseau et découverte

#### Commandes LAN (mDNS direct)
```bash
# Annoncer sur mDNS
./target/debug/miaou-cli lan mdns announce [--duration SECONDS] [--port PORT]

# Lister pairs mDNS
./target/debug/miaou-cli lan mdns list-peers [--timeout SECONDS]
```

#### Commandes réseau unifiées
```bash
# Démarrer découverte unifiée
./target/debug/miaou-cli net unified start [--duration SECONDS] [--methods mdns,dht]

# Annoncer sur tous les canaux
./target/debug/miaou-cli net unified announce

# Lister pairs unifiés
./target/debug/miaou-cli net unified list-peers [--timeout SECONDS]

# Rechercher un pair spécifique  
./target/debug/miaou-cli net unified find <PEER_ID> [--timeout SECONDS]
```

#### Commandes legacy (rétrocompatibilité)
```bash
# Démarrer le service réseau
./target/debug/miaou-cli net-start [--duration SECONDS] [--daemon]

# Lister les pairs découverts
./target/debug/miaou-cli net-list-peers [--timeout SECONDS]

# Se connecter à un pair
./target/debug/miaou-cli net-connect <PEER_ID>

# Informations réseau
./target/debug/miaou-cli network-info [--json]

# Diagnostics réseau (NAT/STUN/TURN)
./target/debug/miaou-cli diagnostics [--json]
```

### 💬 Messaging (persistance locale)
```bash
# Envoyer un message
./target/debug/miaou-cli send <TO> "<MESSAGE>"

# Recevoir les messages en attente
./target/debug/miaou-cli recv

# Historique des messages
./target/debug/miaou-cli history [--limit N] [--peer PEER_ID]
```

### 🗄️ Annuaire DHT (local uniquement en v0.2.0)
```bash
# Publier une clé publique
./target/debug/miaou-cli dht-put signing <KEY_HEX>
./target/debug/miaou-cli dht-put encryption <KEY_HEX>

# Récupérer une clé publique
./target/debug/miaou-cli dht-get <PEER_ID> signing
./target/debug/miaou-cli dht-get <PEER_ID> encryption
```

### 🔐 Cryptographie (v0.1.0)
```bash
# Générer une paire de clés
./target/debug/miaou-cli key-generate

# Exporter une clé publique
./target/debug/miaou-cli key-export <KEY_ID>

# Signer un message
./target/debug/miaou-cli sign <KEY_ID> "<MESSAGE>"

# Vérifier une signature
./target/debug/miaou-cli verify <KEY_ID> "<MESSAGE>" <SIGNATURE>

# Chiffrement AEAD
./target/debug/miaou-cli aead-encrypt <KEY_HEX> <NONCE_HEX> <AAD_HEX> "<MESSAGE>"
./target/debug/miaou-cli aead-decrypt <KEY_HEX> <NONCE_HEX> <AAD_HEX> <CIPHERTEXT_HEX>
```

## 📊 Mode JSON pour scripts

Toutes les commandes réseau supportent `--json` pour une sortie structurée :

```bash
# Exemple avec network-info
./target/debug/miaou-cli --json network-info
```

Sortie JSON :
```json
{
  "command": "network-info",
  "version": "0.2.0",
  "warning": "Certaines métriques sont simulées en v0.2.0 MVP",
  "data": {
    "mdns_peers": 2,
    "dht_peers": 0,
    "manual_peers": 0,
    "active_connections": 2,
    "webrtc_established": 0,
    "latency_ms": 100,
    "throughput_msg_per_sec": 1000
  },
  "timestamp": 1756400000
}
```

## ⚠️ Limitations v0.2.0 MVP

| Fonctionnalité | État | Note |
|----------------|------|------|
| **mDNS Discovery** | ✅ Réel | Découverte LAN fonctionnelle |
| **WebRTC DataChannels** | 🟡 Simulé | Architecture complète, I/O simulé |
| **DHT Kademlia** | 🟡 Local | Logique complète, pas de réseau UDP |
| **STUN/TURN** | 🟡 Simulé | Candidats ICE générés, pas de serveurs réels |
| **NAT Traversal** | 🟡 Simulé | Détection type NAT simulée |
| **Messaging** | ✅ Réel | Persistance JSON atomique |

## 🧪 Scripts de test End-to-End

### Test découverte mDNS complète
```bash
./test_cli_mdns_integration.sh
```

### Test messaging avec persistance
```bash
./test_e2e_messaging.sh
```

### Test annuaire DHT
```bash
./test_e2e_dht.sh
```

### Test parcours complet net-connect
```bash
./test_e2e_net_connect.sh
```

## 🐛 Dépannage

### "Aucun pair découvert"
- Vérifiez que les 2 instances sont sur le même réseau local
- Vérifiez que le firewall autorise le port 5353 (mDNS)
- Attendez 5-10 secondes après le démarrage

### "Connexion WebRTC échouée"
- Normal en v0.2.0 : WebRTC est simulé
- La découverte mDNS fonctionne, mais pas la connexion réelle
- v0.3.0 apportera l'implémentation WebRTC complète

### Mode verbose
```bash
# Activer les logs détaillés
RUST_LOG=debug ./target/debug/miaou-cli net-start
```

## 📈 Métriques v0.2.0

- **369 tests** validés (↑ 305% vs v0.1.0)
- **95.5%** de couverture maintenue
- **14 commandes CLI** (10 réseau + 4 crypto)
- **5 crates** dans le workspace
- **mDNS réel** + architecture P2P complète

## 🚀 Prochaines étapes (v0.3.0)

1. **WebRTC réel** avec `webrtc-rs`
2. **DHT réseau UDP** Kademlia complet
3. **STUN/TURN réels** (`stun.l.google.com:19302`)
4. **Handshake X3DH** + Double Ratchet
5. **Benchmarks** latence < 100ms LAN

---

*Pour plus de détails, voir `docs/V0.2.0_RELEASE_CHECKLIST.md`*