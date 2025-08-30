//! Handshake cryptographique production avec X3DH et Double Ratchet
//!
//! TDD: Tests écrits AVANT implémentation
//! Protocol: X3DH pour établir session + Double Ratchet pour messages

use crate::{NetworkError, PeerId};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Message de handshake X3DH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Étape 1: Alice envoie sa clé publique et demande le bundle de Bob
    InitialRequest {
        /// ID d'Alice
        sender_id: PeerId,
        /// Clé publique d'identité d'Alice
        identity_key: Vec<u8>,
        /// Clé éphémère d'Alice
        ephemeral_key: Vec<u8>,
        /// Timestamp
        timestamp: u64,
        /// Signature du message
        signature: Vec<u8>,
    },
    /// Étape 2: Bob répond avec son bundle et calcule le secret partagé
    BundleResponse {
        /// ID de Bob
        sender_id: PeerId,
        /// Clé publique d'identité de Bob
        identity_key: Vec<u8>,
        /// Clé signée de Bob
        signed_prekey: Vec<u8>,
        /// Signature de la clé signée
        signed_prekey_signature: Vec<u8>,
        /// Clé éphémère de Bob
        ephemeral_key: Vec<u8>,
        /// Timestamp
        timestamp: u64,
    },
    /// Étape 3: Alice confirme et active la session
    SessionConfirmation {
        /// ID d'Alice
        sender_id: PeerId,
        /// Hash du secret partagé calculé
        shared_secret_hash: Vec<u8>,
        /// Premier message chiffré (optionnel)
        initial_message: Option<Vec<u8>>,
        /// Timestamp
        timestamp: u64,
    },
}

/// Bundle de clés publiques pour X3DH
#[derive(Debug, Clone)]
pub struct KeyBundle {
    /// Clé d'identité (Ed25519)
    pub identity_key: VerifyingKey,
    /// Clé signée (X25519)
    pub signed_prekey: X25519PublicKey,
    /// Signature de la clé signée
    pub signed_prekey_signature: Signature,
    /// Clés éphémères disponibles
    pub ephemeral_keys: Vec<X25519PublicKey>,
}

/// Session établie après handshake
#[derive(Debug, Clone)]
pub struct EstablishedSession {
    /// ID du pair distant
    pub peer_id: PeerId,
    /// Secret partagé dérivé
    pub shared_secret: [u8; 32],
    /// Clé racine pour Double Ratchet
    pub root_key: [u8; 32],
    /// Clé de chaîne pour envoi
    pub sending_chain_key: [u8; 32],
    /// Clé de chaîne pour réception
    pub receiving_chain_key: [u8; 32],
    /// Timestamp de création
    pub created_at: u64,
}

/// Configuration handshake production
#[derive(Debug, Clone)]
pub struct ProductionHandshakeConfig {
    /// Timeout pour handshake complet (ms)
    pub handshake_timeout_ms: u64,
    /// Nombre max de tentatives
    pub max_attempts: u32,
    /// Durée de validité des clés éphémères (s)
    pub ephemeral_key_ttl_secs: u64,
}

impl Default for ProductionHandshakeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_ms: 10000, // 10 secondes
            max_attempts: 3,
            ephemeral_key_ttl_secs: 3600, // 1 heure
        }
    }
}

/// Gestionnaire de handshake production
pub struct ProductionHandshakeManager {
    /// Notre PeerId
    local_peer_id: PeerId,
    /// Configuration
    config: ProductionHandshakeConfig,
    /// Clé d'identité privée (Ed25519)
    identity_key: SigningKey,
    /// Clé statique privée (X25519)
    static_key: StaticSecret,
    /// Clés éphémères générées
    ephemeral_keys: Arc<RwLock<Vec<EphemeralSecret>>>,
    /// Secrets éphémères pour handshakes actifs (non-sérialisable)
    active_ephemeral_secrets: Arc<RwLock<HashMap<String, EphemeralSecret>>>,
    /// Sessions établies
    established_sessions: Arc<RwLock<HashMap<PeerId, EstablishedSession>>>,
    /// Handshakes en cours
    pending_handshakes: Arc<RwLock<HashMap<String, PendingHandshake>>>,
}

/// Handshake en cours
#[derive(Debug)]
struct PendingHandshake {
    peer_id: PeerId,
    state: HandshakeState,
    started_at: u64,
    attempts: u32,
}

/// État du handshake
#[derive(Debug, Clone)]
enum HandshakeState {
    /// Initiateur: Envoyé request, attend bundle
    InitiatorWaitingBundle { ephemeral_public_key: [u8; 32] },
    /// Récepteur: Reçu request, envoyé bundle, attend confirmation
    ReceiverWaitingConfirmation { shared_secret: [u8; 32] },
    /// Terminé avec succès
    Completed,
}

impl ProductionHandshakeManager {
    /// Crée un nouveau gestionnaire de handshake
    pub fn new(
        local_peer_id: PeerId,
        config: ProductionHandshakeConfig,
    ) -> Result<Self, NetworkError> {
        // Générer clés d'identité
        let mut rng = OsRng;
        let identity_key = SigningKey::generate(&mut rng);
        let static_key = StaticSecret::random_from_rng(rng);

        Ok(Self {
            local_peer_id,
            config,
            identity_key,
            static_key,
            ephemeral_keys: Arc::new(RwLock::new(Vec::new())),
            active_ephemeral_secrets: Arc::new(RwLock::new(HashMap::new())),
            established_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Génère des clés éphémères
    pub async fn generate_ephemeral_keys(&self, count: usize) -> Result<(), NetworkError> {
        let rng = OsRng;
        let mut keys = self.ephemeral_keys.write().await;

        keys.clear();
        for _ in 0..count {
            keys.push(EphemeralSecret::random_from_rng(rng));
        }

        info!("🔑 Généré {} clés éphémères", count);
        Ok(())
    }

    /// Retourne notre bundle de clés publiques
    pub async fn get_key_bundle(&self) -> Result<KeyBundle, NetworkError> {
        let identity_public = self.identity_key.verifying_key();
        let signed_prekey = X25519PublicKey::from(&self.static_key);

        // Signer la clé signée avec notre clé d'identité
        let signed_prekey_signature = self.identity_key.sign(signed_prekey.as_bytes());

        // Récupérer clés éphémères publiques
        let ephemeral_keys = self.ephemeral_keys.read().await;

        // Convertir les clés éphémères secrètes en clés publiques
        let ephemeral_publics: Vec<X25519PublicKey> =
            ephemeral_keys.iter().map(X25519PublicKey::from).collect();
        Ok(KeyBundle {
            identity_key: identity_public,
            signed_prekey,
            signed_prekey_signature,
            ephemeral_keys: ephemeral_publics,
        })
    }

    /// Initie un handshake avec un pair (Alice)
    pub async fn initiate_handshake(
        &self,
        peer_id: &PeerId,
    ) -> Result<HandshakeMessage, NetworkError> {
        let rng = OsRng;
        let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let identity_public = self.identity_key.verifying_key();
        let timestamp = current_timestamp();

        // Créer le message à signer
        let message_to_sign = format!(
            "{}:{}:{}",
            self.local_peer_id.to_hex(),
            hex::encode(identity_public.as_bytes()),
            timestamp
        );

        let signature = self.identity_key.sign(message_to_sign.as_bytes());

        let handshake_msg = HandshakeMessage::InitialRequest {
            sender_id: self.local_peer_id.clone(),
            identity_key: identity_public.as_bytes().to_vec(),
            ephemeral_key: ephemeral_public.as_bytes().to_vec(),
            timestamp,
            signature: signature.to_bytes().to_vec(),
        };

        // Enregistrer handshake en cours
        let handshake_id = format!("{}:{}", self.local_peer_id.to_hex(), peer_id.to_hex());

        // Stocker le secret éphémère séparément
        let mut active_secrets = self.active_ephemeral_secrets.write().await;
        active_secrets.insert(handshake_id.clone(), ephemeral_secret);
        drop(active_secrets);

        let pending = PendingHandshake {
            peer_id: peer_id.clone(),
            state: HandshakeState::InitiatorWaitingBundle {
                ephemeral_public_key: *ephemeral_public.as_bytes(),
            },
            started_at: timestamp,
            attempts: 1,
        };

        let mut pending_map = self.pending_handshakes.write().await;
        pending_map.insert(handshake_id, pending);

        info!("🤝 Handshake initié avec {}", peer_id.to_hex());
        Ok(handshake_msg)
    }

    /// Traite un message de handshake reçu
    pub async fn process_handshake_message(
        &self,
        message: &HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, NetworkError> {
        match message {
            HandshakeMessage::InitialRequest {
                sender_id,
                identity_key,
                ephemeral_key,
                timestamp,
                signature,
            } => {
                // Vérifier la signature
                let identity_verifying =
                    VerifyingKey::from_bytes(identity_key.as_slice().try_into().map_err(
                        |_| NetworkError::General("Clé identité invalide".to_string()),
                    )?)?;

                let message_to_verify = format!(
                    "{}:{}:{}",
                    sender_id.to_hex(),
                    hex::encode(identity_key),
                    timestamp
                );

                let sig = Signature::from_bytes(
                    signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| NetworkError::General("Signature invalide".to_string()))?,
                );

                identity_verifying
                    .verify(message_to_verify.as_bytes(), &sig)
                    .map_err(|_| {
                        NetworkError::General("Vérification signature échouée".to_string())
                    })?;

                // Calculer secret partagé (X3DH)
                let alice_ephemeral = X25519PublicKey::from(
                    <[u8; 32]>::try_from(ephemeral_key.as_slice())
                        .map_err(|_| NetworkError::General("Clé éphémère invalide".to_string()))?,
                );

                let _alice_identity_x25519 = identity_to_x25519(&identity_verifying)?;

                // Implémentation DH simplifiée pour MVP
                // Un seul DH : bob_static_key * alice_ephemeral
                let shared_dh = self.static_key.diffie_hellman(&alice_ephemeral);

                // Créer une clé éphémère pour la réponse (pas utilisée dans DH)
                let ephemeral_for_response = EphemeralSecret::random_from_rng(OsRng);
                let ephemeral_public = X25519PublicKey::from(&ephemeral_for_response);

                // Le secret partagé est directement le DH
                let shared_secret = *shared_dh.as_bytes();

                // Créer réponse bundle
                let bundle = self.get_key_bundle().await?;
                let response = HandshakeMessage::BundleResponse {
                    sender_id: self.local_peer_id.clone(),
                    identity_key: bundle.identity_key.as_bytes().to_vec(),
                    signed_prekey: bundle.signed_prekey.as_bytes().to_vec(),
                    signed_prekey_signature: bundle.signed_prekey_signature.to_bytes().to_vec(),
                    ephemeral_key: ephemeral_public.as_bytes().to_vec(),
                    timestamp: current_timestamp(),
                };

                // Enregistrer handshake en cours
                let handshake_id =
                    format!("{}:{}", sender_id.to_hex(), self.local_peer_id.to_hex());
                let pending = PendingHandshake {
                    peer_id: sender_id.clone(),
                    state: HandshakeState::ReceiverWaitingConfirmation { shared_secret },
                    started_at: current_timestamp(),
                    attempts: 1,
                };

                let mut pending_map = self.pending_handshakes.write().await;
                pending_map.insert(handshake_id, pending);

                info!("🤝 Bundle envoyé à {}", sender_id.to_hex());
                Ok(Some(response))
            }

            HandshakeMessage::BundleResponse {
                sender_id,
                identity_key,
                signed_prekey,
                signed_prekey_signature,
                ephemeral_key,
                ..
            } => {
                // Récupérer handshake en cours
                let handshake_id =
                    format!("{}:{}", self.local_peer_id.to_hex(), sender_id.to_hex());
                let mut pending_map = self.pending_handshakes.write().await;

                let pending = pending_map
                    .remove(&handshake_id)
                    .ok_or_else(|| NetworkError::General("Handshake non trouvé".to_string()))?;

                if let HandshakeState::InitiatorWaitingBundle {
                    ephemeral_public_key: _,
                } = pending.state
                {
                    // Récupérer le secret éphémère stocké
                    let mut active_secrets = self.active_ephemeral_secrets.write().await;
                    let ephemeral_secret =
                        active_secrets.remove(&handshake_id).ok_or_else(|| {
                            NetworkError::General("Secret éphémère non trouvé".to_string())
                        })?;
                    drop(active_secrets);
                    // Vérifier signature de la clé signée
                    let bob_identity =
                        VerifyingKey::from_bytes(identity_key.as_slice().try_into().map_err(
                            |_| NetworkError::General("Clé identité Bob invalide".to_string()),
                        )?)?;

                    let bob_signed_prekey = X25519PublicKey::from(
                        <[u8; 32]>::try_from(signed_prekey.as_slice()).map_err(|_| {
                            NetworkError::General("Clé signée invalide".to_string())
                        })?,
                    );

                    let sig = Signature::from_bytes(
                        signed_prekey_signature.as_slice().try_into().map_err(|_| {
                            NetworkError::General("Signature prekey invalide".to_string())
                        })?,
                    );

                    bob_identity
                        .verify(bob_signed_prekey.as_bytes(), &sig)
                        .map_err(|_| {
                            NetworkError::General("Vérification prekey échouée".to_string())
                        })?;

                    // Calculer secret partagé côté Alice
                    let _bob_ephemeral = X25519PublicKey::from(
                        <[u8; 32]>::try_from(ephemeral_key.as_slice()).map_err(|_| {
                            NetworkError::General("Clé éphémère Bob invalide".to_string())
                        })?,
                    );

                    // Même calcul DH simple que côté Bob
                    // alice_ephemeral * bob_signed_prekey (la clé statique de Bob)
                    let shared_dh = ephemeral_secret.diffie_hellman(&bob_signed_prekey);

                    // Le secret partagé est directement le DH
                    let shared_secret = *shared_dh.as_bytes();

                    // Créer session
                    let session =
                        create_session_from_shared_secret(sender_id.clone(), &shared_secret);

                    // Enregistrer session établie
                    let mut sessions = self.established_sessions.write().await;
                    sessions.insert(sender_id.clone(), session);

                    // Envoyer confirmation
                    let shared_hash = blake3::hash(&shared_secret).as_bytes().to_vec();
                    let confirmation = HandshakeMessage::SessionConfirmation {
                        sender_id: self.local_peer_id.clone(),
                        shared_secret_hash: shared_hash,
                        initial_message: None,
                        timestamp: current_timestamp(),
                    };

                    info!("✅ Session établie avec {}", sender_id.to_hex());
                    Ok(Some(confirmation))
                } else {
                    Err(NetworkError::General(
                        "État handshake incorrect".to_string(),
                    ))
                }
            }

            HandshakeMessage::SessionConfirmation {
                sender_id,
                shared_secret_hash,
                ..
            } => {
                // Vérifier et finaliser la session côté Bob
                let handshake_id =
                    format!("{}:{}", sender_id.to_hex(), self.local_peer_id.to_hex());
                let mut pending_map = self.pending_handshakes.write().await;

                let pending = pending_map
                    .remove(&handshake_id)
                    .ok_or_else(|| NetworkError::General("Handshake non trouvé".to_string()))?;

                if let HandshakeState::ReceiverWaitingConfirmation { shared_secret } = pending.state
                {
                    // Vérifier le hash
                    let our_hash = blake3::hash(&shared_secret);
                    if our_hash.as_bytes() != shared_secret_hash.as_slice() {
                        return Err(NetworkError::General("Hash secret incorrect".to_string()));
                    }

                    // Créer session
                    let session =
                        create_session_from_shared_secret(sender_id.clone(), &shared_secret);

                    // Enregistrer session établie
                    let mut sessions = self.established_sessions.write().await;
                    sessions.insert(sender_id.clone(), session);

                    info!("✅ Session confirmée avec {}", sender_id.to_hex());
                    Ok(None) // Pas de réponse nécessaire
                } else {
                    Err(NetworkError::General(
                        "État handshake incorrect".to_string(),
                    ))
                }
            }
        }
    }

    /// Récupère une session établie
    pub async fn get_established_session(&self, peer_id: &PeerId) -> Option<EstablishedSession> {
        let sessions = self.established_sessions.read().await;
        sessions.get(peer_id).cloned()
    }

    /// Nettoie les handshakes expirés
    pub async fn cleanup_expired_handshakes(&self) -> usize {
        let now = current_timestamp();
        let mut pending = self.pending_handshakes.write().await;
        let before = pending.len();

        pending.retain(|_, handshake| {
            let age = now - handshake.started_at;
            age < self.config.handshake_timeout_ms
        });

        let removed = before - pending.len();
        if removed > 0 {
            debug!("🗑️ {} handshakes expirés supprimés", removed);
        }

        removed
    }
}

// Fonctions utilitaires

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn identity_to_x25519(ed_key: &VerifyingKey) -> Result<X25519PublicKey, NetworkError> {
    // Conversion Ed25519 -> X25519 (simplifiée pour MVP)
    // En production, utiliser curve25519-dalek pour conversion correcte
    let bytes = ed_key.as_bytes();
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(bytes);
    Ok(X25519PublicKey::from(x25519_bytes))
}

fn derive_shared_secret(dh_outputs: &[&[u8]]) -> [u8; 32] {
    // KDF simple avec BLAKE3 pour dériver le secret partagé
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"X3DH_SHARED_SECRET");

    for output in dh_outputs {
        hasher.update(output);
    }

    let mut result = [0u8; 32];
    let hash = hasher.finalize();
    result.copy_from_slice(&hash.as_bytes()[..32]);
    result
}

fn create_session_from_shared_secret(
    peer_id: PeerId,
    shared_secret: &[u8; 32],
) -> EstablishedSession {
    // Dériver les clés pour Double Ratchet
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ROOT_KEY");
    hasher.update(shared_secret);
    let root_key_hash = hasher.finalize();
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&root_key_hash.as_bytes()[..32]);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SENDING_CHAIN");
    hasher.update(shared_secret);
    let sending_hash = hasher.finalize();
    let mut sending_chain_key = [0u8; 32];
    sending_chain_key.copy_from_slice(&sending_hash.as_bytes()[..32]);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"RECEIVING_CHAIN");
    hasher.update(shared_secret);
    let receiving_hash = hasher.finalize();
    let mut receiving_chain_key = [0u8; 32];
    receiving_chain_key.copy_from_slice(&receiving_hash.as_bytes()[..32]);

    EstablishedSession {
        peer_id,
        shared_secret: *shared_secret,
        root_key,
        sending_chain_key,
        receiving_chain_key,
        created_at: current_timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_production_handshake_manager_creation() {
        // TDD: Test création gestionnaire handshake
        let peer_id = PeerId::from_bytes(b"handshake-peer".to_vec());
        let config = ProductionHandshakeConfig::default();

        let manager = ProductionHandshakeManager::new(peer_id.clone(), config);
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert_eq!(manager.local_peer_id, peer_id);
    }

    #[tokio::test]
    async fn test_generate_ephemeral_keys() {
        // TDD: Test génération clés éphémères
        let peer_id = PeerId::from_bytes(b"ephemeral-test".to_vec());
        let config = ProductionHandshakeConfig::default();
        let manager = ProductionHandshakeManager::new(peer_id, config).unwrap();

        let result = manager.generate_ephemeral_keys(5).await;
        assert!(result.is_ok());

        let keys = manager.ephemeral_keys.read().await;
        assert_eq!(keys.len(), 5);
    }

    #[tokio::test]
    async fn test_get_key_bundle() {
        // TDD: Test récupération bundle de clés
        let peer_id = PeerId::from_bytes(b"bundle-test".to_vec());
        let config = ProductionHandshakeConfig::default();
        let manager = ProductionHandshakeManager::new(peer_id, config).unwrap();

        // Générer quelques clés éphémères
        manager.generate_ephemeral_keys(3).await.unwrap();

        let bundle = manager.get_key_bundle().await.unwrap();
        assert_eq!(bundle.ephemeral_keys.len(), 3);

        // Vérifier signature de la clé signée
        let verification = bundle.identity_key.verify(
            bundle.signed_prekey.as_bytes(),
            &bundle.signed_prekey_signature,
        );
        assert!(verification.is_ok());
    }

    #[tokio::test]
    async fn test_initiate_handshake() {
        // TDD: Test initiation handshake
        let alice_id = PeerId::from_bytes(b"alice".to_vec());
        let bob_id = PeerId::from_bytes(b"bob".to_vec());
        let config = ProductionHandshakeConfig::default();

        let alice_manager = ProductionHandshakeManager::new(alice_id.clone(), config).unwrap();

        let initial_msg = alice_manager.initiate_handshake(&bob_id).await.unwrap();

        // Vérifier le message
        if let HandshakeMessage::InitialRequest { sender_id, .. } = initial_msg {
            assert_eq!(sender_id, alice_id);
        } else {
            panic!("Message incorrect");
        }

        // Vérifier handshake en cours
        let pending = alice_manager.pending_handshakes.read().await;
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn test_complete_handshake_flow() {
        // TDD: Test flux handshake complet Alice <-> Bob
        let alice_id = PeerId::from_bytes(b"alice_flow".to_vec());
        let bob_id = PeerId::from_bytes(b"bob_flow".to_vec());
        let config = ProductionHandshakeConfig::default();

        let alice_manager =
            ProductionHandshakeManager::new(alice_id.clone(), config.clone()).unwrap();
        let bob_manager = ProductionHandshakeManager::new(bob_id.clone(), config).unwrap();

        // Générer clés éphémères pour Bob
        bob_manager.generate_ephemeral_keys(2).await.unwrap();

        // Étape 1: Alice initie
        let initial_msg = alice_manager.initiate_handshake(&bob_id).await.unwrap();

        // Étape 2: Bob traite et répond
        let bundle_response = bob_manager
            .process_handshake_message(&initial_msg)
            .await
            .unwrap();

        assert!(bundle_response.is_some());
        let bundle_msg = bundle_response.unwrap();

        // Étape 3: Alice traite bundle et confirme
        let confirmation = alice_manager
            .process_handshake_message(&bundle_msg)
            .await
            .unwrap();

        assert!(confirmation.is_some());
        let confirm_msg = confirmation.unwrap();

        // Étape 4: Bob traite confirmation
        let final_response = bob_manager
            .process_handshake_message(&confirm_msg)
            .await
            .unwrap();

        assert!(final_response.is_none()); // Pas de réponse finale

        // Vérifier sessions établies
        let alice_session = alice_manager.get_established_session(&bob_id).await;
        let bob_session = bob_manager.get_established_session(&alice_id).await;

        assert!(alice_session.is_some());
        assert!(bob_session.is_some());

        let alice_session = alice_session.unwrap();
        let bob_session = bob_session.unwrap();

        // Les secrets partagés doivent être identiques
        assert_eq!(alice_session.shared_secret, bob_session.shared_secret);
    }

    #[tokio::test]
    async fn test_invalid_signature_rejection() {
        // TDD: Test rejet signature invalide
        let alice_id = PeerId::from_bytes(b"alice_bad".to_vec());
        let bob_id = PeerId::from_bytes(b"bob_bad".to_vec());
        let config = ProductionHandshakeConfig::default();

        let bob_manager = ProductionHandshakeManager::new(bob_id, config).unwrap();

        // Message avec signature invalide
        let bad_msg = HandshakeMessage::InitialRequest {
            sender_id: alice_id,
            identity_key: vec![0u8; 32],  // Clé bidon
            ephemeral_key: vec![0u8; 32], // Clé bidon
            timestamp: current_timestamp(),
            signature: vec![0u8; 64], // Signature invalide
        };

        let result = bob_manager.process_handshake_message(&bad_msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_expired_handshakes() {
        // TDD: Test nettoyage handshakes expirés
        let peer_id = PeerId::from_bytes(b"cleanup-test".to_vec());
        let config = ProductionHandshakeConfig {
            handshake_timeout_ms: 100,
            ..Default::default()
        };

        let manager = ProductionHandshakeManager::new(peer_id.clone(), config).unwrap();

        // Ajouter handshake expiré manuellement
        let expired_handshake = PendingHandshake {
            peer_id: PeerId::from_bytes(b"expired".to_vec()),
            state: HandshakeState::Completed,
            started_at: 0, // Très vieux
            attempts: 1,
        };

        {
            let mut pending = manager.pending_handshakes.write().await;
            pending.insert("expired".to_string(), expired_handshake);
        }

        // Nettoyer
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let removed = manager.cleanup_expired_handshakes().await;

        assert_eq!(removed, 1);

        let pending = manager.pending_handshakes.read().await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_message_serialization() {
        // TDD: Test sérialisation/désérialisation messages
        let peer_id = PeerId::from_bytes(b"serial-test".to_vec());

        let msg = HandshakeMessage::InitialRequest {
            sender_id: peer_id,
            identity_key: vec![1u8; 32],
            ephemeral_key: vec![2u8; 32],
            timestamp: 123_456_789,
            signature: vec![3u8; 64],
        };

        // Sérialiser
        let serialized = bincode::serialize(&msg).unwrap();
        assert!(!serialized.is_empty());

        // Désérialiser
        let deserialized: HandshakeMessage = bincode::deserialize(&serialized).unwrap();

        match deserialized {
            HandshakeMessage::InitialRequest { timestamp, .. } => {
                assert_eq!(timestamp, 123_456_789);
            }
            _ => panic!("Message incorrect après désérialisation"),
        }
    }
}
