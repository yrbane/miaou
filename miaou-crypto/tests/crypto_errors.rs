// miaou-crypto/tests/crypto_errors.rs
use miaou_crypto::{test_crypto_availability, decrypt, encrypt, AeadKeyRef, CryptoError};
use rand_core::OsRng;

#[test]
fn decrypt_fails_on_wrong_aad() {
    let key = AeadKeyRef::from_bytes([7u8; 32]);
    let mut rng = OsRng;
    let aad_ok = b"ctx/v1";
    let aad_ko = b"ctx/v2";
    let ct = miaou_crypto::aead::encrypt_auto_nonce(&key, aad_ok, b"hi", &mut rng).unwrap();
    let err = miaou_crypto::aead::decrypt(&key, aad_ko, &ct).unwrap_err();
    matches!(err, CryptoError::AeadDecrypt(_));
}

#[test]
fn self_test_succeeds() {
    test_crypto_availability().expect("self test must pass");
}
