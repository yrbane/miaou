#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! **Crate miaou-network** - Communication P2P décentralisée pour Miaou
//!
//! Ce crate fournit les primitives réseau pour établir des connexions P2P
//! sécurisées entre pairs, avec découverte automatique et NAT traversal.
//!
//! # Architecture SOLID
//!
//! - **S**ingle Responsibility : Chaque module a une responsabilité unique
//! - **O**pen/Closed : Extensible via traits sans modifier le code existant
//! - **L**iskov Substitution : Toutes les implémentations de Transport sont interchangeables
//! - **I**nterface Segregation : Traits minimaux et spécifiques
//! - **D**ependency Inversion : Dépend d'abstractions, pas d'implémentations

pub mod connection;
pub mod discovery;
pub mod error;
pub mod peer;
pub mod transport;

pub use connection::{Connection, ConnectionState};
pub use discovery::{Discovery, DiscoveryConfig, DiscoveryMethod};
pub use error::NetworkError;
pub use peer::{PeerId, PeerInfo};
pub use transport::{Transport, TransportConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Vérifier que les modules principaux sont accessibles
        let _ = std::mem::size_of::<NetworkError>();
    }
}
