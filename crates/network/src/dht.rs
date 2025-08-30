//! DHT (Distributed Hash Table) pour découverte P2P globale
//!
//! TDD: Tests écrits AVANT implémentation
//! Architecture SOLID : DHT Kademlia-like pour découverte décentralisée

use crate::{NetworkError, PeerId, PeerInfo};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Distance XOR entre deux PeerIds (métrique Kademlia)
pub fn xor_distance(a: &PeerId, b: &PeerId) -> Vec<u8> {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    // Padding pour avoir la même longueur
    let max_len = a_bytes.len().max(b_bytes.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];

    a_padded[..a_bytes.len()].copy_from_slice(a_bytes);
    b_padded[..b_bytes.len()].copy_from_slice(b_bytes);

    // XOR byte par byte
    a_padded
        .iter()
        .zip(b_padded.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// K-bucket pour stocker les pairs par distance
#[derive(Clone, Debug)]
pub struct KBucket {
    /// Taille maximale du bucket (K dans Kademlia, typiquement 20)
    k: usize,
    /// Pairs dans ce bucket, triés par dernière vue
    peers: Vec<(PeerId, PeerInfo, u64)>, // (id, info, last_seen)
}

impl KBucket {
    /// Crée un nouveau K-bucket
    pub fn new(k: usize) -> Self {
        Self {
            k,
            peers: Vec::new(),
        }
    }

    /// Ajoute ou met à jour un pair dans le bucket
    pub fn add_or_update(&mut self, peer_id: PeerId, info: PeerInfo) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Vérifier si le pair existe déjà
        if let Some(pos) = self.peers.iter().position(|(id, _, _)| id == &peer_id) {
            // Mettre à jour et déplacer en fin (plus récent)
            self.peers.remove(pos);
            self.peers.push((peer_id, info, now));
            return true;
        }

        // Si bucket pas plein, ajouter
        if self.peers.len() < self.k {
            self.peers.push((peer_id, info, now));
            return true;
        }

        // Bucket plein - politique de remplacement LRU
        // On pourrait ping le plus ancien pour voir s'il est toujours vivant
        // Pour l'instant, on refuse simplement
        false
    }

    /// Récupère les pairs du bucket
    pub fn get_peers(&self) -> Vec<(PeerId, PeerInfo)> {
        self.peers
            .iter()
            .map(|(id, info, _)| (id.clone(), info.clone()))
            .collect()
    }

    /// Supprime un pair du bucket
    pub fn remove(&mut self, peer_id: &PeerId) -> bool {
        if let Some(pos) = self.peers.iter().position(|(id, _, _)| id == peer_id) {
            self.peers.remove(pos);
            true
        } else {
            false
        }
    }

    /// Nombre de pairs dans le bucket
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Le bucket est-il vide?
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Le bucket est-il plein?
    pub fn is_full(&self) -> bool {
        self.peers.len() >= self.k
    }
}

/// Configuration DHT
#[derive(Clone, Debug)]
pub struct DhtConfig {
    /// Taille des K-buckets
    pub k_bucket_size: usize,
    /// Nombre de bits pour l'ID (160 bits comme Kademlia standard)
    pub id_bits: usize,
    /// Paramètre alpha pour recherches parallèles
    pub alpha: usize,
    /// Timeout pour requêtes RPC (en secondes)
    pub rpc_timeout_seconds: u64,
    /// Intervalle de refresh des buckets (en secondes)
    pub refresh_interval_seconds: u64,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            k_bucket_size: 20, // Standard Kademlia
            id_bits: 160,      // 160 bits comme BitTorrent DHT
            alpha: 3,          // 3 requêtes parallèles
            rpc_timeout_seconds: 5,
            refresh_interval_seconds: 3600, // 1 heure
        }
    }
}

/// Messages RPC pour le DHT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtMessage {
    /// PING - vérifier qu'un nœud est vivant
    Ping {
        /// ID du pair qui envoie le ping
        sender_id: PeerId,
    },
    /// PONG - réponse au ping
    Pong {
        /// ID du pair qui répond au ping
        sender_id: PeerId,
    },
    /// FIND_NODE - trouver les K nœuds les plus proches d'un ID
    FindNode {
        /// ID du pair qui fait la requête
        sender_id: PeerId,
        /// ID cible à rechercher
        target_id: PeerId,
    },
    /// NODES - réponse avec les nœuds trouvés
    Nodes {
        /// ID du pair qui répond
        sender_id: PeerId,
        /// Liste des nœuds proches trouvés
        nodes: Vec<(PeerId, SocketAddr)>,
    },
    /// STORE - stocker une valeur dans le DHT
    Store {
        /// ID du pair qui stocke
        sender_id: PeerId,
        /// Clé de la valeur
        key: Vec<u8>,
        /// Valeur à stocker
        value: Vec<u8>,
    },
    /// FIND_VALUE - chercher une valeur dans le DHT
    FindValue {
        /// ID du pair qui cherche
        sender_id: PeerId,
        /// Clé recherchée
        key: Vec<u8>,
    },
    /// VALUE - réponse avec la valeur trouvée
    Value {
        /// ID du pair qui répond
        sender_id: PeerId,
        /// Valeur trouvée
        value: Vec<u8>,
    },
}

/// Routing table basée sur Kademlia
pub struct RoutingTable {
    /// Notre propre ID
    pub local_id: PeerId,
    /// Configuration DHT
    config: DhtConfig,
    /// K-buckets organisés par distance (bit de différence le plus significatif)
    buckets: Vec<Arc<Mutex<KBucket>>>,
    /// Cache de valeurs stockées localement
    storage: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl RoutingTable {
    /// Crée une nouvelle table de routage
    pub fn new(local_id: PeerId, config: DhtConfig) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..config.id_bits {
            buckets.push(Arc::new(Mutex::new(KBucket::new(config.k_bucket_size))));
        }

        Self {
            local_id,
            config,
            buckets,
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Retourne la configuration DHT
    pub fn config(&self) -> &DhtConfig {
        &self.config
    }

    /// Calcule l'index du bucket pour un pair donné
    fn bucket_index(&self, peer_id: &PeerId) -> usize {
        let distance = xor_distance(&self.local_id, peer_id);

        // Trouver le bit le plus significatif différent
        for (byte_idx, byte) in distance.iter().enumerate() {
            if *byte != 0 {
                // Trouver le bit le plus significatif dans ce byte
                let bit_idx = 7 - byte.leading_zeros() as usize;
                return byte_idx * 8 + bit_idx;
            }
        }

        // Même ID (ne devrait pas arriver)
        0
    }

    /// Ajoute un pair à la table de routage
    pub fn add_peer(&self, peer_id: PeerId, info: PeerInfo) -> bool {
        if peer_id == self.local_id {
            return false; // Ne pas s'ajouter soi-même
        }

        let bucket_idx = self.bucket_index(&peer_id);
        if bucket_idx >= self.buckets.len() {
            return false;
        }

        let mut bucket = self.buckets[bucket_idx].lock().unwrap();
        bucket.add_or_update(peer_id, info)
    }

    /// Trouve les K nœuds les plus proches d'un ID donné
    pub fn find_closest_nodes(&self, target: &PeerId, count: usize) -> Vec<(PeerId, PeerInfo)> {
        // Créer une liste de tous les pairs avec leur distance au target
        let mut all_peers: Vec<(Vec<u8>, PeerId, PeerInfo)> = Vec::new();

        for bucket in &self.buckets {
            let bucket = bucket.lock().unwrap();
            for (peer_id, peer_info) in bucket.get_peers() {
                let distance = xor_distance(&peer_id, target);
                all_peers.push((distance, peer_id, peer_info));
            }
        }

        // Trier par distance
        all_peers.sort_by(|a, b| a.0.cmp(&b.0));

        // Retourner les K plus proches
        all_peers
            .into_iter()
            .take(count)
            .map(|(_, id, info)| (id, info))
            .collect()
    }

    /// Supprime un pair de la table
    pub fn remove_peer(&self, peer_id: &PeerId) -> bool {
        let bucket_idx = self.bucket_index(peer_id);
        if bucket_idx >= self.buckets.len() {
            return false;
        }

        let mut bucket = self.buckets[bucket_idx].lock().unwrap();
        bucket.remove(peer_id)
    }

    /// Stocke une valeur localement
    pub fn store_value(&self, key: Vec<u8>, value: Vec<u8>) {
        let mut storage = self.storage.lock().unwrap();
        storage.insert(key, value);
    }

    /// Récupère une valeur stockée localement
    pub fn get_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        let storage = self.storage.lock().unwrap();
        storage.get(key).cloned()
    }

    /// Compte le nombre total de pairs dans la table
    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.lock().unwrap().len()).sum()
    }
}

/// Trait pour le DHT
#[async_trait]
pub trait DistributedHashTable: Send + Sync {
    /// Démarre le DHT
    async fn start(&mut self) -> Result<(), NetworkError>;

    /// Arrête le DHT
    async fn stop(&mut self) -> Result<(), NetworkError>;

    /// Bootstrap avec des nœuds connus
    async fn bootstrap(&mut self, nodes: Vec<(PeerId, SocketAddr)>) -> Result<(), NetworkError>;

    /// Trouve les nœuds les plus proches d'un ID
    async fn find_node(&self, target: &PeerId) -> Result<Vec<(PeerId, PeerInfo)>, NetworkError>;

    /// Stocke une valeur dans le DHT
    async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), NetworkError>;

    /// Récupère une valeur du DHT
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NetworkError>;

    /// Annonce notre présence dans le DHT
    async fn announce(&self) -> Result<(), NetworkError>;
}

/// Implémentation Kademlia du DHT
pub struct KademliaDht {
    /// Table de routage
    pub routing_table: Arc<RoutingTable>,
    /// Configuration
    config: DhtConfig,
    /// État du DHT
    is_running: Arc<Mutex<bool>>,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<(PeerId, SocketAddr)>,
}

impl KademliaDht {
    /// Crée un nouveau DHT Kademlia
    pub fn new(local_id: PeerId, config: DhtConfig) -> Self {
        Self {
            routing_table: Arc::new(RoutingTable::new(local_id.clone(), config.clone())),
            config,
            is_running: Arc::new(Mutex::new(false)),
            bootstrap_nodes: Vec::new(),
        }
    }

    /// Traite un message RPC entrant
    pub fn handle_rpc(
        &self,
        message: DhtMessage,
        _sender_addr: SocketAddr,
    ) -> Result<Option<DhtMessage>, NetworkError> {
        match message {
            DhtMessage::Ping { sender_id } => {
                // Ajouter le sender à notre table
                let peer_info = PeerInfo::new(sender_id.clone());
                self.routing_table.add_peer(sender_id.clone(), peer_info);

                // Répondre avec Pong
                Ok(Some(DhtMessage::Pong {
                    sender_id: self.routing_table.local_id.clone(),
                }))
            }

            DhtMessage::FindNode {
                sender_id,
                target_id,
            } => {
                // Ajouter le sender
                let peer_info = PeerInfo::new(sender_id.clone());
                self.routing_table.add_peer(sender_id.clone(), peer_info);

                // Trouver les nœuds les plus proches
                let closest = self
                    .routing_table
                    .find_closest_nodes(&target_id, self.config.k_bucket_size);
                let nodes: Vec<(PeerId, SocketAddr)> = closest
                    .into_iter()
                    .filter_map(|(id, info)| info.addresses.first().map(|addr| (id, *addr)))
                    .collect();

                Ok(Some(DhtMessage::Nodes {
                    sender_id: self.routing_table.local_id.clone(),
                    nodes,
                }))
            }

            DhtMessage::Store {
                sender_id,
                key,
                value,
            } => {
                // Ajouter le sender
                let peer_info = PeerInfo::new(sender_id.clone());
                self.routing_table.add_peer(sender_id, peer_info);

                // Stocker la valeur
                self.routing_table.store_value(key, value);

                Ok(None) // Pas de réponse nécessaire
            }

            DhtMessage::FindValue { sender_id, key } => {
                // Ajouter le sender
                let peer_info = PeerInfo::new(sender_id.clone());
                self.routing_table.add_peer(sender_id.clone(), peer_info);

                // Chercher la valeur localement
                if let Some(value) = self.routing_table.get_value(&key) {
                    Ok(Some(DhtMessage::Value {
                        sender_id: self.routing_table.local_id.clone(),
                        value,
                    }))
                } else {
                    // Sinon, retourner les nœuds les plus proches de la clé
                    let key_as_peer = PeerId::from_bytes(key);
                    let closest = self
                        .routing_table
                        .find_closest_nodes(&key_as_peer, self.config.k_bucket_size);
                    let nodes: Vec<(PeerId, SocketAddr)> = closest
                        .into_iter()
                        .filter_map(|(id, info)| info.addresses.first().map(|addr| (id, *addr)))
                        .collect();

                    Ok(Some(DhtMessage::Nodes {
                        sender_id: self.routing_table.local_id.clone(),
                        nodes,
                    }))
                }
            }

            _ => Ok(None), // Autres messages ignorés
        }
    }
}

#[async_trait]
impl DistributedHashTable for KademliaDht {
    async fn start(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.lock().unwrap();
        if *running {
            return Err(NetworkError::General("DHT already running".to_string()));
        }
        *running = true;

        // TDD: Pour MVP, on démarre simplement
        // En production, démarrer listener UDP/TCP ici

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), NetworkError> {
        let mut running = self.is_running.lock().unwrap();
        if !*running {
            return Err(NetworkError::General("DHT not running".to_string()));
        }
        *running = false;

        Ok(())
    }

    async fn bootstrap(&mut self, nodes: Vec<(PeerId, SocketAddr)>) -> Result<(), NetworkError> {
        if nodes.is_empty() {
            return Err(NetworkError::General(
                "No bootstrap nodes provided".to_string(),
            ));
        }

        self.bootstrap_nodes = nodes.clone();

        // Ajouter les bootstrap nodes à notre table
        for (peer_id, addr) in nodes {
            let mut peer_info = PeerInfo::new(peer_id.clone());
            peer_info.add_address(addr);
            self.routing_table.add_peer(peer_id, peer_info);
        }

        // TDD: Pour MVP, on considère le bootstrap réussi
        // En production, faire des PING et FIND_NODE ici

        Ok(())
    }

    async fn find_node(&self, target: &PeerId) -> Result<Vec<(PeerId, PeerInfo)>, NetworkError> {
        // Recherche locale d'abord
        let closest = self
            .routing_table
            .find_closest_nodes(target, self.config.k_bucket_size);

        if closest.is_empty() {
            return Err(NetworkError::General(
                "No peers in routing table".to_string(),
            ));
        }

        // TDD: Pour MVP, retourner juste les résultats locaux
        // En production, faire une recherche itérative Kademlia ici

        Ok(closest)
    }

    async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), NetworkError> {
        // Stocker localement
        self.routing_table.store_value(key.clone(), value.clone());

        // TDD: Pour MVP, stockage local seulement
        // En production, répliquer sur les K nœuds les plus proches

        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NetworkError> {
        // Chercher localement d'abord
        if let Some(value) = self.routing_table.get_value(key) {
            return Ok(Some(value));
        }

        // TDD: Pour MVP, recherche locale seulement
        // En production, faire une recherche FIND_VALUE itérative

        Ok(None)
    }

    async fn announce(&self) -> Result<(), NetworkError> {
        // Annoncer notre présence en stockant notre info sous notre ID
        let our_info = PeerInfo::new(self.routing_table.local_id.clone());
        let serialized = serde_json::to_vec(&our_info)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        self.put(self.routing_table.local_id.as_bytes().to_vec(), serialized)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance() {
        // Test distance XOR
        let a = PeerId::from_bytes(vec![0xFF, 0x00]);
        let b = PeerId::from_bytes(vec![0x00, 0xFF]);

        let distance = xor_distance(&a, &b);
        assert_eq!(distance, vec![0xFF, 0xFF]);

        // Distance avec soi-même = 0
        let self_distance = xor_distance(&a, &a);
        assert_eq!(self_distance, vec![0x00, 0x00]);
    }

    #[test]
    fn test_kbucket_add_and_get() {
        // Test K-bucket
        let mut bucket = KBucket::new(3);

        let peer1 = PeerId::from_bytes(b"peer1".to_vec());
        let info1 = PeerInfo::new(peer1.clone());
        assert!(bucket.add_or_update(peer1.clone(), info1));
        assert_eq!(bucket.len(), 1);

        let peer2 = PeerId::from_bytes(b"peer2".to_vec());
        let info2 = PeerInfo::new(peer2.clone());
        assert!(bucket.add_or_update(peer2.clone(), info2));
        assert_eq!(bucket.len(), 2);

        let peer3 = PeerId::from_bytes(b"peer3".to_vec());
        let info3 = PeerInfo::new(peer3.clone());
        assert!(bucket.add_or_update(peer3.clone(), info3));
        assert_eq!(bucket.len(), 3);
        assert!(bucket.is_full());

        // Bucket plein, nouveau pair refusé
        let peer4 = PeerId::from_bytes(b"peer4".to_vec());
        let info4 = PeerInfo::new(peer4.clone());
        assert!(!bucket.add_or_update(peer4, info4));
        assert_eq!(bucket.len(), 3);
    }

    #[test]
    fn test_kbucket_update_existing() {
        // Test mise à jour d'un pair existant
        let mut bucket = KBucket::new(3);

        let peer = PeerId::from_bytes(b"peer".to_vec());
        let info1 = PeerInfo::new(peer.clone());
        assert!(bucket.add_or_update(peer.clone(), info1));

        // Mettre à jour le même pair
        let mut info2 = PeerInfo::new(peer.clone());
        info2.add_address("127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert!(bucket.add_or_update(peer.clone(), info2));

        assert_eq!(bucket.len(), 1); // Toujours un seul pair
    }

    #[test]
    fn test_kbucket_remove() {
        // Test suppression
        let mut bucket = KBucket::new(3);

        let peer1 = PeerId::from_bytes(b"peer1".to_vec());
        let info1 = PeerInfo::new(peer1.clone());
        bucket.add_or_update(peer1.clone(), info1);

        assert!(bucket.remove(&peer1));
        assert_eq!(bucket.len(), 0);
        assert!(!bucket.remove(&peer1)); // Déjà supprimé
    }

    #[test]
    fn test_routing_table_bucket_index() {
        // Test calcul index bucket
        let local_id = PeerId::from_bytes(vec![0b1000_0000]); // 128
        let config = DhtConfig::default();
        let table = RoutingTable::new(local_id.clone(), config);

        let peer1 = PeerId::from_bytes(vec![0b0000_0000]); // 0
        let idx1 = table.bucket_index(&peer1);
        assert_eq!(idx1, 7); // Bit 7 différent

        let peer2 = PeerId::from_bytes(vec![0b1100_0000]); // 192
        let idx2 = table.bucket_index(&peer2);
        assert_eq!(idx2, 6); // Bit 6 différent
    }

    #[test]
    fn test_routing_table_add_peer() {
        // Test ajout de pairs
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let config = DhtConfig::default();
        let table = RoutingTable::new(local_id.clone(), config);

        let peer = PeerId::from_bytes(b"peer".to_vec());
        let info = PeerInfo::new(peer.clone());

        assert!(table.add_peer(peer.clone(), info));
        assert_eq!(table.peer_count(), 1);

        // Ne pas s'ajouter soi-même
        let self_info = PeerInfo::new(local_id.clone());
        assert!(!table.add_peer(local_id, self_info));
        assert_eq!(table.peer_count(), 1);
    }

    #[test]
    fn test_routing_table_find_closest() {
        // Test recherche des plus proches
        let local_id = PeerId::from_bytes(vec![0x00]);
        let config = DhtConfig::default();
        let table = RoutingTable::new(local_id, config);

        // Ajouter quelques pairs
        for i in 1..=5 {
            let peer = PeerId::from_bytes(vec![i]);
            let info = PeerInfo::new(peer.clone());
            table.add_peer(peer, info);
        }

        // Chercher les plus proches de 3
        let target = PeerId::from_bytes(vec![0x03]);
        let closest = table.find_closest_nodes(&target, 3);

        assert_eq!(closest.len(), 3);
        // Le plus proche devrait être 3 lui-même
        assert_eq!(closest[0].0.as_bytes(), &[0x03]);
    }

    #[test]
    fn test_routing_table_storage() {
        // Test stockage de valeurs
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let config = DhtConfig::default();
        let table = RoutingTable::new(local_id, config);

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        table.store_value(key.clone(), value.clone());
        assert_eq!(table.get_value(&key), Some(value));
        assert_eq!(table.get_value(b"nonexistent"), None);
    }

    #[test]
    fn test_dht_config_default() {
        // Test configuration par défaut
        let config = DhtConfig::default();
        assert_eq!(config.k_bucket_size, 20);
        assert_eq!(config.id_bits, 160);
        assert_eq!(config.alpha, 3);
        assert_eq!(config.rpc_timeout_seconds, 5);
        assert_eq!(config.refresh_interval_seconds, 3600);
    }

    #[tokio::test]
    async fn test_kademlia_dht_creation() {
        // Test création DHT Kademlia
        let local_id = PeerId::from_bytes(b"node1".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id, config);

        assert_eq!(dht.routing_table.peer_count(), 0);
    }

    #[tokio::test]
    async fn test_kademlia_start_stop() {
        // Test démarrage/arrêt DHT
        let local_id = PeerId::from_bytes(b"node1".to_vec());
        let config = DhtConfig::default();
        let mut dht = KademliaDht::new(local_id, config);

        // Démarrer
        assert!(dht.start().await.is_ok());

        // Ne peut pas démarrer deux fois
        assert!(dht.start().await.is_err());

        // Arrêter
        assert!(dht.stop().await.is_ok());

        // Ne peut pas arrêter deux fois
        assert!(dht.stop().await.is_err());
    }

    #[tokio::test]
    async fn test_kademlia_bootstrap() {
        // Test bootstrap avec nœuds
        let local_id = PeerId::from_bytes(b"node1".to_vec());
        let config = DhtConfig::default();
        let mut dht = KademliaDht::new(local_id, config);

        let bootstrap_nodes = vec![
            (
                PeerId::from_bytes(b"boot1".to_vec()),
                "127.0.0.1:8001".parse::<SocketAddr>().unwrap(),
            ),
            (
                PeerId::from_bytes(b"boot2".to_vec()),
                "127.0.0.1:8002".parse::<SocketAddr>().unwrap(),
            ),
        ];

        assert!(dht.bootstrap(bootstrap_nodes).await.is_ok());
        assert_eq!(dht.routing_table.peer_count(), 2);

        // Bootstrap sans nœuds échoue
        assert!(dht.bootstrap(vec![]).await.is_err());
    }

    #[tokio::test]
    async fn test_kademlia_put_get() {
        // Test stockage/récupération
        let local_id = PeerId::from_bytes(b"node1".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id, config);

        let key = b"my_key".to_vec();
        let value = b"my_value".to_vec();

        assert!(dht.put(key.clone(), value.clone()).await.is_ok());

        let retrieved = dht.get(&key).await.unwrap();
        assert_eq!(retrieved, Some(value));

        // Clé inexistante
        let missing = dht.get(b"missing").await.unwrap();
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_kademlia_announce() {
        // Test annonce de présence
        let local_id = PeerId::from_bytes(b"announcer".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id.clone(), config);

        assert!(dht.announce().await.is_ok());

        // Vérifier que notre info est stockée
        let stored = dht.get(local_id.as_bytes()).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_kademlia_find_node() {
        // Test recherche de nœuds
        let local_id = PeerId::from_bytes(b"finder".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id, config);

        // Ajouter des pairs d'abord
        for i in 1..=3 {
            let peer = PeerId::from_bytes(vec![i]);
            let mut info = PeerInfo::new(peer.clone());
            info.add_address(format!("127.0.0.1:800{}", i).parse::<SocketAddr>().unwrap());
            dht.routing_table.add_peer(peer, info);
        }

        let target = PeerId::from_bytes(vec![0x02]);
        let found = dht.find_node(&target).await.unwrap();
        assert!(!found.is_empty());
        assert!(found.len() <= 3);
    }

    #[tokio::test]
    async fn test_handle_rpc_ping() {
        // Test traitement RPC Ping
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id.clone(), config);

        let sender_id = PeerId::from_bytes(b"sender".to_vec());
        let ping = DhtMessage::Ping {
            sender_id: sender_id.clone(),
        };

        let response = dht
            .handle_rpc(ping, "127.0.0.1:9000".parse::<SocketAddr>().unwrap())
            .unwrap();
        assert!(response.is_some());

        if let Some(DhtMessage::Pong {
            sender_id: pong_sender,
        }) = response
        {
            assert_eq!(pong_sender, local_id);
        } else {
            panic!("Expected Pong response");
        }

        // Le sender devrait être ajouté à la table
        assert_eq!(dht.routing_table.peer_count(), 1);
    }

    #[tokio::test]
    async fn test_handle_rpc_find_node() {
        // Test traitement RPC FindNode
        let local_id = PeerId::from_bytes(b"local".to_vec());
        let config = DhtConfig::default();
        let dht = KademliaDht::new(local_id.clone(), config);

        // Ajouter quelques pairs
        for i in 1..=3 {
            let peer = PeerId::from_bytes(vec![i]);
            let mut info = PeerInfo::new(peer.clone());
            info.add_address(format!("127.0.0.1:900{}", i).parse::<SocketAddr>().unwrap());
            dht.routing_table.add_peer(peer, info);
        }

        let sender_id = PeerId::from_bytes(b"sender".to_vec());
        let target_id = PeerId::from_bytes(vec![0x02]);
        let find_node = DhtMessage::FindNode {
            sender_id,
            target_id,
        };

        let response = dht
            .handle_rpc(find_node, "127.0.0.1:9000".parse::<SocketAddr>().unwrap())
            .unwrap();
        assert!(response.is_some());

        if let Some(DhtMessage::Nodes { nodes, .. }) = response {
            assert!(!nodes.is_empty());
        } else {
            panic!("Expected Nodes response");
        }
    }

    #[tokio::test]
    async fn test_dht_message_serialization() {
        // TDD: Test sérialisation des messages DHT
        let sender_id = PeerId::from_bytes(b"sender".to_vec());
        let target_id = PeerId::from_bytes(b"target".to_vec());

        // Test Ping
        let ping = DhtMessage::Ping {
            sender_id: sender_id.clone(),
        };
        let serialized = bincode::serialize(&ping).unwrap();
        let deserialized: DhtMessage = bincode::deserialize(&serialized).unwrap();
        match deserialized {
            DhtMessage::Ping { sender_id: s } => assert_eq!(s, sender_id),
            _ => panic!("Wrong message type"),
        }

        // Test FindNode
        let find_node = DhtMessage::FindNode {
            sender_id: sender_id.clone(),
            target_id: target_id.clone(),
        };
        let serialized = bincode::serialize(&find_node).unwrap();
        let deserialized: DhtMessage = bincode::deserialize(&serialized).unwrap();
        match deserialized {
            DhtMessage::FindNode {
                sender_id: s,
                target_id: t,
            } => {
                assert_eq!(s, sender_id);
                assert_eq!(t, target_id);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_routing_table_multiple_peers() {
        // TDD: Test table de routage avec plusieurs pairs
        let config = DhtConfig::default();
        let local_id = PeerId::from_bytes(b"local_multi".to_vec());
        let table = RoutingTable::new(local_id.clone(), config);

        // Ajouter plusieurs pairs avec différentes distances
        let peers = vec![
            (
                PeerId::from_bytes(vec![0x01]),
                "192.168.1.1:8000".parse::<SocketAddr>().unwrap(),
            ),
            (
                PeerId::from_bytes(vec![0x02]),
                "192.168.1.2:8000".parse::<SocketAddr>().unwrap(),
            ),
            (
                PeerId::from_bytes(vec![0x04]),
                "192.168.1.4:8000".parse::<SocketAddr>().unwrap(),
            ),
            (
                PeerId::from_bytes(vec![0x08]),
                "192.168.1.8:8000".parse::<SocketAddr>().unwrap(),
            ),
        ];

        for (peer_id, addr) in &peers {
            let mut info = PeerInfo::new(peer_id.clone());
            info.add_address(*addr);
            table.add_peer(peer_id.clone(), info);
        }

        // Test find_closest avec différentes tailles
        let target = PeerId::from_bytes(vec![0x05]);
        let closest_3 = table.find_closest_nodes(&target, 3);
        assert!(closest_3.len() <= 3);

        let closest_10 = table.find_closest_nodes(&target, 10);
        assert_eq!(closest_10.len(), peers.len()); // Tous les pairs car moins de 10
    }

    #[tokio::test]
    async fn test_dht_storage_operations() {
        // TDD: Test opérations de stockage DHT
        let config = DhtConfig::default();
        let local_id = PeerId::from_bytes(b"dht_storage_local".to_vec());
        let dht = KademliaDht::new(local_id.clone(), config);

        let key1 = b"storage_key_1".to_vec();
        let value1 = b"storage_value_1".to_vec();
        let key2 = b"storage_key_2".to_vec();
        let value2 = b"storage_value_2".to_vec();

        // Stocker plusieurs valeurs
        dht.put(key1.clone(), value1.clone()).await.unwrap();
        dht.put(key2.clone(), value2.clone()).await.unwrap();

        // Récupérer les valeurs
        let retrieved1 = dht.get(&key1).await.unwrap();
        assert_eq!(retrieved1, Some(value1));

        let retrieved2 = dht.get(&key2).await.unwrap();
        assert_eq!(retrieved2, Some(value2));

        // Tester une clé inexistante
        let nonexistent = dht.get(b"nonexistent".as_ref()).await.unwrap();
        assert_eq!(nonexistent, None);
    }

    #[tokio::test]
    async fn test_dht_bootstrap_process() {
        // TDD: Test processus de bootstrap DHT
        let config = DhtConfig::default();
        let local_id = PeerId::from_bytes(b"dht_bootstrap_local".to_vec());
        let mut dht = KademliaDht::new(local_id.clone(), config);

        // Créer des nœuds bootstrap
        let bootstrap_nodes = vec![
            (
                PeerId::from_bytes(b"boot1".to_vec()),
                "198.51.100.1:8000".parse::<SocketAddr>().unwrap(),
            ),
            (
                PeerId::from_bytes(b"boot2".to_vec()),
                "198.51.100.2:8000".parse::<SocketAddr>().unwrap(),
            ),
        ];

        // Le bootstrap devrait ajouter les nœuds à la table de routage
        dht.bootstrap(bootstrap_nodes.clone()).await.unwrap();

        // Vérifier que des nœuds ont été ajoutés
        assert!(dht.routing_table.peer_count() > 0);
    }

    #[tokio::test]
    async fn test_dht_lifecycle_comprehensive() {
        // TDD: Test lifecycle DHT complet
        let config = DhtConfig::default();
        let local_id = PeerId::from_bytes(b"dht_lifecycle".to_vec());
        let mut dht = KademliaDht::new(local_id.clone(), config);

        // Démarrer
        dht.start().await.unwrap();

        // Opérations pendant que démarré
        dht.put(b"lifecycle_key".to_vec(), b"lifecycle_value".to_vec())
            .await
            .unwrap();
        let retrieved = dht.get(b"lifecycle_key").await.unwrap();
        assert_eq!(retrieved, Some(b"lifecycle_value".to_vec()));

        // Announce devrait réussir
        assert!(dht.announce().await.is_ok());

        // Arrêter
        dht.stop().await.unwrap();
    }

    #[test]
    fn test_kbucket_capacity() {
        // TDD: Test capacité K-bucket
        let mut bucket = KBucket::new(3);

        // Ajouter des pairs jusqu'à la capacité
        for i in 0..25 {
            // Plus que la capacité par défaut
            let peer_id = PeerId::from_bytes(vec![i as u8]);
            let addr = format!("192.168.1.{}:8000", i + 1)
                .parse::<SocketAddr>()
                .unwrap();
            let mut info = PeerInfo::new(peer_id.clone());
            info.add_address(addr);
            bucket.add_or_update(peer_id, info);
        }

        // Le bucket ne devrait pas dépasser sa capacité
        assert!(bucket.peers.len() <= 3); // K = 3 pour ce test
    }

    #[test]
    fn test_routing_table_bucket_distribution() {
        // TDD: Test distribution dans les K-buckets
        let config = DhtConfig::default();
        let local_id = PeerId::from_bytes(vec![0x80]); // 10000000 en binaire
        let table = RoutingTable::new(local_id.clone(), config);

        // Ajouter des pairs dans différents buckets
        let peer1 = PeerId::from_bytes(vec![0x81]);
        let mut info1 = PeerInfo::new(peer1.clone());
        info1.add_address("192.168.1.1:8000".parse::<SocketAddr>().unwrap());
        table.add_peer(peer1, info1); // Bucket 0

        let peer2 = PeerId::from_bytes(vec![0x82]);
        let mut info2 = PeerInfo::new(peer2.clone());
        info2.add_address("192.168.1.2:8000".parse::<SocketAddr>().unwrap());
        table.add_peer(peer2, info2); // Bucket 1

        let peer3 = PeerId::from_bytes(vec![0x00]);
        let mut info3 = PeerInfo::new(peer3.clone());
        info3.add_address("192.168.1.100:8000".parse::<SocketAddr>().unwrap());
        table.add_peer(peer3, info3); // Bucket 7

        let target = PeerId::from_bytes(vec![0x81]);
        let closest = table.find_closest_nodes(&target, 5);

        // Devrait trouver des pairs
        assert!(!closest.is_empty());
    }
}
