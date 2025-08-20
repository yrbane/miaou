// miaou-core/tests/storage_contract.rs
use miaou_core::{StorageBackend, StorageError};

struct FailingStorage;
impl StorageBackend for FailingStorage {
    fn store(&mut self, _k: &str, _d: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, "simulated").into(),
        ))
    }
    fn retrieve(&self, _k: &str) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::NotFound)
    }
    fn delete(&mut self, _k: &str) -> Result<(), StorageError> {
        Ok(())
    }
    fn exists(&self, _k: &str) -> bool {
        false
    }
}

#[test]
fn storage_error_paths_are_handled() {
    let mut st = FailingStorage;
    assert!(st.store("x", b"y").is_err());
    assert!(st.retrieve("x").is_err());
    assert!(!st.exists("x"));
    assert!(st.delete("x").is_ok());
}
