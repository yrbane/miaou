#!/bin/bash

# Script de démonstration complète mDNS pour Miaou
# Teste la découverte mutuelle entre instances

echo "🧪 === Test complet de découverte mDNS Miaou ==="
echo

# Nettoyer processus existants
echo "🧹 Nettoyage des processus existants..."
pkill -f "miaou-cli.*net-start" 2>/dev/null || true
sleep 1

echo "📡 Démarrage de deux instances Miaou en arrière-plan..."

# Instance 1
echo "   Lancement instance 1..."
timeout 15s ./target/debug/miaou-cli net-start --duration 15 > instance1.log 2>&1 &
PID1=$!

# Instance 2  
echo "   Lancement instance 2..."
timeout 15s ./target/debug/miaou-cli net-start --duration 15 > instance2.log 2>&1 &
PID2=$!

echo "   PIDs des instances: $PID1, $PID2"
echo

# Attendre que les services démarrent
echo "⏳ Attente démarrage des services (5s)..."
sleep 5

# Vérifier avec avahi-browse
echo "🔍 Vérification services mDNS actifs avec avahi-browse:"
timeout 3s avahi-browse -t _miaou._tcp 2>/dev/null | head -10 || echo "   avahi-browse non disponible"
echo

# Test de la commande net-list-peers
echo "👥 Test de la commande net-list-peers:"
./target/debug/miaou-cli net-list-peers
echo

# Attendre un peu plus pour laisser les instances communiquer
echo "⏳ Attente communication inter-instances (3s)..."
sleep 3

# Tester à nouveau net-list-peers
echo "👥 Nouveau test net-list-peers après communication:"
./target/debug/miaou-cli net-list-peers
echo

# Afficher les logs des instances
echo "📜 Logs de l'instance 1:"
if [ -f instance1.log ]; then
    cat instance1.log | tail -20
else
    echo "   Fichier log non trouvé"
fi
echo

echo "📜 Logs de l'instance 2:"
if [ -f instance2.log ]; then
    cat instance2.log | tail -20
else
    echo "   Fichier log non trouvé"
fi

# Attendre que les instances se terminent
echo
echo "⏳ Attente fin des instances..."
wait $PID1 2>/dev/null
wait $PID2 2>/dev/null

echo
echo "✅ Test terminé - vérifiez les logs ci-dessus pour la découverte mutuelle"

# Nettoyer
rm -f instance1.log instance2.log