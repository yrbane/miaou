//! Tests cryptographiques pour Miaou
//! 
//! Organisation des tests selon les standards de l'industrie :
//! - Known Answer Tests (KAT) avec vecteurs officiels
//! - Tests de propriétés cryptographiques
//! - Tests de performance et limites
//! - Tests de sécurité et cas d'erreur

pub mod known_answer_tests;
pub mod property_tests;
pub mod integration_tests;