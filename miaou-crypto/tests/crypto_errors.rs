// miaou-crypto/tests/crypto_errors.rs
use miaou_crypto::{
    decrypt, encrypt_auto_nonce, test_crypto_availability, AeadKeyRef, CryptoError,
};
use rand_core::OsRng;

#[test]
fn decrypt_fails_on_wrong_aad() {
    let key = AeadKeyRef::from_bytes([7u8; 32]);
    let mut rng = OsRng;
    let aad_ok = b"ctx/v1";
    let aad_ko = b"ctx/v2";
    let ct = encrypt_auto_nonce(&key, aad_ok, b"hi", &mut rng).unwrap();
    let err = decrypt(&key, aad_ko, &ct).unwrap_err();
    assert!(matches!(err, CryptoError::DecryptionFailed));
}

#[test]
fn self_test_succeeds() {
    test_crypto_availability().expect("self test must pass");
}
