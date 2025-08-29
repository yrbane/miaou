# Patch: v0.2.0 ➜ v0.3.0 (prod réseau)
# Focus: DHT Kademlia UDP réel, boucle d’écoute, réponses corrélées, intégration UnifiedDiscovery (sans thread_local)
# Remarque: WebRTC reste derrière le feature flag; ce patch supprime les chemins "simulation" du DHT prod et rend la découverte pleinement exploitable.

### 1) crates/network/src/dht_production_impl.rs (remplacement complet)

```diff
*** Begin Patch
*** Update File: crates/network/src/dht_production_impl.rs
@@
-//! DHT Kademlia Production - Implémentations réseau réelles
-//!
-//! Version production remplaçant les simulations TDD par des connexions UDP réelles.
-//! Implémente les RPC Kademlia avec networking, recherche itérative et réplication.
+//! DHT Kademlia Production – implémentation réseau réelle (UDP)
+//!
+//! ✓ Boucle d’écoute asynchrone
+//! ✓ Corrélation requête/réponse via waiters par adresse
+//! ✓ PING/PONG, FIND_NODE, FIND_VALUE, STORE
+//! ✓ Recherche itérative et réplication minimale
@@
-use tokio::net::UdpSocket;
-use tokio::sync::Mutex;
+use tokio::net::UdpSocket;
+use tokio::sync::{Mutex, oneshot};
@@
 pub struct ProductionKademliaDht {
@@
-    /// Socket UDP pour communication réseau
-    socket: Arc<Mutex<Option<UdpSocket>>>,
+    /// Socket UDP pour communication réseau
+    socket: Arc<Mutex<Option<Arc<UdpSocket>>>>,
@@
-    /// Requêtes en cours (pour gestion timeout)
-    pending_requests: Arc<Mutex<HashMap<String, tokio::time::Instant>>>,
+    /// Attentes de réponses par adresse source
+    response_waiters: Arc<Mutex<HashMap<SocketAddr, oneshot::Sender<DhtMessage>>>>,
 }
@@
         Self {
             routing_table: Arc::new(RoutingTable::new(local_id, dht_config.clone())),
             dht_config,
             production_config,
-            socket: Arc::new(Mutex::new(None)),
+            socket: Arc::new(Mutex::new(None)),
             is_running: Arc::new(Mutex::new(false)),
             bootstrap_nodes: Arc::new(Mutex::new(Vec::new())),
-            pending_requests: Arc::new(Mutex::new(HashMap::new())),
+            response_waiters: Arc::new(Mutex::new(HashMap::new())),
         }
     }
@@
-    async fn start_udp_server(&self) -> Result<(), NetworkError> {
+    async fn start_udp_server(&self) -> Result<(), NetworkError> {
         let bind_addr = format!("0.0.0.0:{}", self.production_config.listen_port);
-        let socket = UdpSocket::bind(&bind_addr).await.map_err(|e| {
+        let socket = UdpSocket::bind(&bind_addr).await.map_err(|e| {
             NetworkError::TransportError(format!("Impossible de binder UDP {}: {}", bind_addr, e))
         })?;
 
         let local_addr = socket.local_addr().map_err(|e| {
             NetworkError::TransportError(format!("Erreur obtention adresse locale: {}", e))
         })?;
 
-        info!("🌐 DHT Production UDP serveur démarré sur {}", local_addr);
+        info!("🌐 DHT Production UDP serveur démarré sur {}", local_addr);
 
-        // Stocker le socket
-        {
-            let mut socket_guard = self.socket.lock().await;
-            *socket_guard = Some(socket);
-        }
-
-        // Démarrer la boucle d'écoute (en arrière-plan)
-        // Note: Pour production complète, utiliser un Arc<UdpSocket> partagé
-        // Pour MVP, on lit directement depuis le socket principal dans send_message
-
-        info!("🎧 Boucle d'écoute DHT prête (lecture via send_message pour MVP)");
-
-        // TODO: Implémenter vraie boucle d'écoute avec Arc<UdpSocket>
-        // let routing_table = self.routing_table.clone();
-        // tokio::spawn(async move {
-        //     Self::listen_loop(socket_clone, routing_table).await;
-        // });
+        // Partager le socket et démarrer la boucle d’écoute
+        let socket = Arc::new(socket);
+        {
+            let mut guard = self.socket.lock().await;
+            *guard = Some(socket.clone());
+        }
+
+        let routing = self.routing_table.clone();
+        let waiters = self.response_waiters.clone();
+        tokio::spawn(async move {
+            Self::listen_loop(socket, routing, waiters).await;
+        });
 
         Ok(())
     }
@@
-    async fn listen_loop(socket: Arc<UdpSocket>, routing_table: Arc<RoutingTable>) {
+    async fn listen_loop(
+        socket: Arc<UdpSocket>,
+        routing_table: Arc<RoutingTable>,
+        response_waiters: Arc<Mutex<HashMap<SocketAddr, oneshot::Sender<DhtMessage>>>>,
+    ) {
         let mut buffer = vec![0u8; 8192]; // 8KB buffer
 
         loop {
             match socket.recv_from(&mut buffer).await {
                 Ok((len, sender_addr)) => {
                     let data = &buffer[..len];
 
                     // Désérialiser le message DHT
                     match bincode::deserialize::<DhtMessage>(data) {
                         Ok(message) => {
                             debug!("📨 Message DHT reçu de {}: {:?}", sender_addr, message);
-
-                            // Créer DHT temporaire pour traiter le message
-                            let mut temp_dht = KademliaDht::new(
-                                routing_table.local_id.clone(),
-                                routing_table.config().clone(),
-                            );
-                            temp_dht.routing_table = routing_table.clone();
-
-                            // Traiter le message
-                            match temp_dht.handle_rpc(message, sender_addr) {
-                                Ok(Some(response)) => {
-                                    // Envoyer la réponse
-                                    if let Ok(response_data) = bincode::serialize(&response) {
-                                        if let Err(e) =
-                                            socket.send_to(&response_data, sender_addr).await
-                                        {
-                                            warn!(
-                                                "Erreur envoi réponse DHT à {}: {}",
-                                                sender_addr, e
-                                            );
-                                        } else {
-                                            debug!("📤 Réponse DHT envoyée à {}", sender_addr);
-                                        }
-                                    }
-                                }
-                                Ok(None) => {
-                                    // Pas de réponse nécessaire
-                                    debug!("Message DHT traité sans réponse");
-                                }
-                                Err(e) => {
-                                    warn!("Erreur traitement message DHT: {}", e);
-                                }
-                            }
+
+                            // Si c’est une réponse, réveille un waiter
+                            let is_response = matches!(
+                                message,
+                                DhtMessage::Pong { .. }
+                                    | DhtMessage::Nodes { .. }
+                                    | DhtMessage::Value { .. }
+                            );
+
+                            if is_response {
+                                let maybe_tx = {
+                                    let mut guard = response_waiters.lock().await;
+                                    guard.remove(&sender_addr)
+                                };
+                                if let Some(tx) = maybe_tx {
+                                    let _ = tx.send(message);
+                                    continue;
+                                }
+                                // Pas de waiter – tomber en traitement RPC (benin)
+                            }
+
+                            // Traiter la requête RPC
+                            let mut temp_dht = KademliaDht::new(
+                                routing_table.local_id.clone(),
+                                routing_table.config().clone(),
+                            );
+                            temp_dht.routing_table = routing_table.clone();
+
+                            match temp_dht.handle_rpc(message, sender_addr) {
+                                Ok(Some(response)) => {
+                                    if let Ok(bytes) = bincode::serialize(&response) {
+                                        if let Err(e) = socket.send_to(&bytes, sender_addr).await {
+                                            warn!("Erreur envoi réponse DHT à {}: {}", sender_addr, e);
+                                        }
+                                    }
+                                }
+                                Ok(None) => {}
+                                Err(e) => warn!("Erreur traitement message DHT: {}", e),
+                            }
                         }
                         Err(e) => {
                             warn!(
                                 "Erreur désérialisation message DHT de {}: {}",
                                 sender_addr, e
                             );
                         }
                     }
                 }
                 Err(e) => {
                     error!("Erreur réception UDP: {}", e);
                     tokio::time::sleep(Duration::from_millis(100)).await;
                 }
             }
         }
     }
@@
-    async fn send_message(
+    async fn send_message(
         &self,
         message: DhtMessage,
         target_addr: SocketAddr,
     ) -> Result<Option<DhtMessage>, NetworkError> {
-        let socket_guard = self.socket.lock().await;
-        let socket = socket_guard
-            .as_ref()
-            .ok_or_else(|| NetworkError::TransportError("DHT non démarré".to_string()))?;
+        let socket = {
+            let guard = self.socket.lock().await;
+            guard
+                .as_ref()
+                .cloned()
+                .ok_or_else(|| NetworkError::TransportError("DHT non démarré".to_string()))?
+        };
@@
-        // Pour les messages nécessitant réponse (Ping, FindNode, FindValue)
+        // Pour les messages nécessitant réponse (Ping, FindNode, FindValue)
         match message {
             DhtMessage::Ping { .. }
             | DhtMessage::FindNode { .. }
             | DhtMessage::FindValue { .. } => {
-                // Attendre réponse avec timeout
-                let timeout_duration =
-                    Duration::from_millis(self.production_config.network_timeout_ms);
-
-                match timeout(timeout_duration, self.receive_response()).await {
-                    Ok(Ok(response)) => Ok(Some(response)),
-                    Ok(Err(e)) => Err(e),
-                    Err(_) => {
-                        warn!("Timeout attente réponse DHT de {}", target_addr);
-                        Err(NetworkError::TransportError(
-                            "Timeout réponse DHT".to_string(),
-                        ))
-                    }
-                }
+                // Installer un waiter pour la réponse en provenance de target_addr
+                let (tx, rx) = oneshot::channel();
+                {
+                    let mut guard = self.response_waiters.lock().await;
+                    guard.insert(target_addr, tx);
+                }
+
+                let timeout_duration = Duration::from_millis(self.production_config.network_timeout_ms);
+                match timeout(timeout_duration, rx).await {
+                    Ok(Ok(resp)) => Ok(Some(resp)),
+                    Ok(Err(_)) => Err(NetworkError::TransportError("Canal réponse fermé".into())),
+                    Err(_) => {
+                        // Nettoyer waiter expiré
+                        let _ = self.response_waiters.lock().await.remove(&target_addr);
+                        warn!("Timeout attente réponse DHT de {}", target_addr);
+                        Err(NetworkError::TransportError("Timeout réponse DHT".into()))
+                    }
+                }
             }
             _ => Ok(None), // Messages sans réponse
         }
     }
-
-    /// Attend une réponse DHT (simple implémentation pour MVP production)
-    async fn receive_response(&self) -> Result<DhtMessage, NetworkError> {
-        // Pour MVP production, on simule une réponse rapide
-        // En production complète, il faudrait un système de corrélation request/response
-        tokio::time::sleep(Duration::from_millis(10)).await;
-
-        // Retourner une réponse factice pour que les tests passent
-        Ok(DhtMessage::Pong {
-            sender_id: PeerId::from_bytes(b"test_response".to_vec()),
-        })
-    }
*** End Patch
```

### 2) crates/network/src/unified_discovery.rs (remplacement des `thread_local!` par Mutex Arc)

```diff
*** Begin Patch
*** Update File: crates/network/src/unified_discovery.rs
@@
-use std::thread_local;
+use tokio::sync::Mutex as TokioMutex;
@@
-    /// Instance DHT Production (optionnelle)
-    production_dht: Option<Arc<ProductionKademliaDht>>,
+    /// Instance DHT Production (optionnelle) – interior mutability
+    production_dht: Arc<TokioMutex<Option<Arc<ProductionKademliaDht>>>>,
@@
-            production_dht: None,
+            production_dht: Arc::new(TokioMutex::new(None)),
@@
-    async fn start_production_dht(&self) -> Result<(), NetworkError> {
+    async fn start_production_dht(&self) -> Result<(), NetworkError> {
@@
-        // Créer instance DHT Production
-        let mut production_dht =
-            ProductionKademliaDht::new(self.local_peer_id.clone(), dht_config, production_config);
-
-        // Démarrer le DHT
-        production_dht.start().await?;
-
-        // Bootstrap si on a des nodes
-        if !self.bootstrap_nodes.is_empty() {
-            info!(
-                "📡 Bootstrap DHT Production avec {} nœuds",
-                self.bootstrap_nodes.len()
-            );
-            production_dht
-                .bootstrap(self.bootstrap_nodes.clone())
-                .await?;
-        }
-
-        // Créer un pointeur Arc vers l'instance
-        let production_dht_arc = Arc::new(production_dht);
-
-        // Pour éviter unsafe, je vais utiliser une approche différente
-        // On stocke temporairement l'Arc dans une variable static thread-local
-        thread_local! {
-            static TEMP_DHT: std::cell::RefCell<Option<Arc<ProductionKademliaDht>>> = std::cell::RefCell::new(None);
-        }
-        TEMP_DHT.with(|dht| {
-            *dht.borrow_mut() = Some(production_dht_arc.clone());
-        });
+        // Créer instance DHT Production
+        let mut dht_inst = ProductionKademliaDht::new(
+            self.local_peer_id.clone(),
+            dht_config,
+            production_config,
+        );
+        dht_inst.start().await?;
+        if !self.bootstrap_nodes.is_empty() {
+            info!("📡 Bootstrap DHT Production avec {} nœuds", self.bootstrap_nodes.len());
+            dht_inst.bootstrap(self.bootstrap_nodes.clone()).await?;
+        }
+        let arc = Arc::new(dht_inst);
+        {
+            let mut guard = self.production_dht.lock().await;
+            *guard = Some(arc);
+        }
@@
-        // DHT Production - utilise thread-local storage temporaire
-        if states.get(&DiscoveryMethod::Dht).is_some_and(|s| s.active) {
-            thread_local! {
-                static TEMP_DHT: std::cell::RefCell<Option<Arc<ProductionKademliaDht>>> = std::cell::RefCell::new(None);
-            }
-            TEMP_DHT.with(|dht| {
-                if let Some(_production_dht) = &*dht.borrow() {
-                    // Pour l'instant on ne fait pas d'announce
-                    info!("📢 DHT Production prêt pour annonce");
-                }
-            });
-        }
+        // DHT Production – si actif, annoncer via put()
+        if states.get(&DiscoveryMethod::Dht).is_some_and(|s| s.active) {
+            if let Some(dht) = self.production_dht.lock().await.as_ref().cloned() {
+                // On encode le PeerInfo au format JSON et on le stocke clé=PeerId
+                let bytes = serde_json::to_vec(peer_info)
+                    .map_err(|e| NetworkError::SerializationError(e.to_string()))?;
+                dht.put(peer_info.id.as_bytes().to_vec(), bytes).await?;
+                info!("📢 Annonce publiée dans DHT Production");
+            }
+        }
*** End Patch
```

### 3) (Optionnel mais recommandé) Cargo – pas de changements obligatoires

*Pas de nouvelle dépendance requise pour ces patches. Si vous souhaitez plus de logs lisibles en binaire, ajoutez `tracing-subscriber` dans le binaire/CLI.*

```toml
# Exemple (dans le binaire uniquement)
[dependencies]
tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter"] }
```

---

## Notes d’intégration

- **DHT Production** : la boucle d’écoute tourne en tâche de fond, les réponses sont routées vers l’appelant via `oneshot`. On supporte désormais de *vraies* requêtes réseau et des timeouts propres.
- **UnifiedDiscovery** : plus de `thread_local!` ; l’instance DHT est stockée via `Arc<Mutex<Option<…>>>` et utilisée dans `announce()` pour publier le `PeerInfo` dans la DHT.
- **Compatibilité TDD** : tous les tests existants ciblant le DHT production ne devraient plus rencontrer de chemins « simulés ». La simulation WebRTC n’est **pas** touchée par ce patch.
- **Rollout** : activez la méthode `Dht` dans la `DiscoveryConfig` pour bénéficier de la DHT prod.

## Quick check (exemple)

```rust
// Création
let local = PeerId::from_bytes(b"alice".to_vec());
let mut dht = ProductionKademliaDht::new(local, DhtConfig::default(), ProductionDhtConfig::default());
dht.start().await?;

// Put/Get
dht.put(b"key".to_vec(), b"value".to_vec()).await?;
assert_eq!(dht.get(b"key").await?, Some(b"value".to_vec()));
```

```rust
// UnifiedDiscovery
let mut cfg = DiscoveryConfig::default();
cfg.methods = vec![DiscoveryMethod::Mdns, DiscoveryMethod::Dht];
let local_id = PeerId::from_bytes(b"node".to_vec());
let local_info = PeerInfo::new(local_id.clone());
let discovery = UnifiedDiscovery::new(cfg, local_id.clone(), local_info.clone());
discovery.start().await?;
discovery.announce(&local_info).await?; // Publie aussi dans la DHT
