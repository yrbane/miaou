//! Benchmarks de performance cryptographique
//! 
//! Mesure des performances des primitives cryptographiques de Miaou
//! pour s'assurer qu'elles respectent les objectifs de performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use miaou::crypto::{
    encryption::{ChaCha20Poly1305Cipher, EncryptionEngine},
    signing::{Ed25519KeyPair, Ed25519Signer, SigningEngine},
    hashing::{Blake3Hasher, HashingEngine, Argon2Hasher, Argon2Config},
    primitives::{random_bytes, derive_subkey},
};

fn benchmark_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    
    let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
    
    // Test différentes tailles de données
    for size in [1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        let data = vec![0x42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("chacha20_poly1305_encrypt", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let encrypted = cipher.encrypt_with_random_nonce(black_box(&data)).unwrap();
                    black_box(encrypted)
                })
            }
        );
        
        // Benchmark du déchiffrement
        let encrypted = cipher.encrypt_with_random_nonce(&data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("chacha20_poly1305_decrypt", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let decrypted = cipher.decrypt_with_nonce(black_box(&encrypted)).unwrap();
                    black_box(decrypted)
                })
            }
        );
    }
    
    group.finish();
}

fn benchmark_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    
    let keypair = Ed25519KeyPair::generate().unwrap();
    let (private_key, public_key) = Ed25519Signer::generate_keypair().unwrap();
    
    // Test différentes tailles de messages
    for size in [32, 256, 1024, 4096, 16384].iter() {
        let message = vec![0x33u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Benchmark signature
        group.bench_with_input(
            BenchmarkId::new("ed25519_sign", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let signature = Ed25519Signer::sign(black_box(&private_key), black_box(&message)).unwrap();
                    black_box(signature)
                })
            }
        );
        
        // Benchmark vérification
        let signature = Ed25519Signer::sign(&private_key, &message).unwrap();
        group.bench_with_input(
            BenchmarkId::new("ed25519_verify", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let valid = Ed25519Signer::verify(
                        black_box(&public_key), 
                        black_box(&message), 
                        black_box(&signature)
                    ).unwrap();
                    black_box(valid)
                })
            }
        );
    }
    
    // Benchmark génération de paires de clés
    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            let keypair = Ed25519KeyPair::generate().unwrap();
            black_box(keypair)
        })
    });
    
    group.finish();
}

fn benchmark_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    
    // Test différentes tailles pour BLAKE3
    for size in [64, 1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        let data = vec![0x55u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("blake3", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let hash = Blake3Hasher::hash(black_box(&data));
                    black_box(hash)
                })
            }
        );
        
        // Test BLAKE3 avec clé
        let key = [0u8; 32];
        group.bench_with_input(
            BenchmarkId::new("blake3_keyed", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let hash = Blake3Hasher::hash_keyed(black_box(&key), black_box(&data));
                    black_box(hash)
                })
            }
        );
    }
    
    group.finish();
}

fn benchmark_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");
    
    let password = b"test_password_for_benchmarking";
    let salt = b"test_salt_16_byt";
    
    // Test différentes configurations Argon2
    let configs = vec![
        ("fast", Argon2Config::fast_insecure()),
        ("default", Argon2Config::default()),
        ("secure", Argon2Config::secure()),
    ];
    
    for (name, config) in configs {
        group.bench_function(&format!("argon2_derive_{}", name), |b| {
            b.iter(|| {
                let derived = Argon2Hasher::derive_key(
                    black_box(password),
                    black_box(salt),
                    black_box(&config)
                ).unwrap();
                black_box(derived)
            })
        });
        
        group.bench_function(&format!("argon2_hash_{}", name), |b| {
            b.iter(|| {
                let hash = Argon2Hasher::hash_password(
                    black_box(password),
                    black_box(&config)
                ).unwrap();
                black_box(hash)
            })
        });
    }
    
    group.finish();
}

fn benchmark_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives");
    
    // Benchmark génération de bytes aléatoires
    for size in [16, 32, 64, 128, 256, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("random_bytes", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let random = random_bytes(black_box(size)).unwrap();
                    black_box(random)
                })
            }
        );
    }
    
    // Benchmark dérivation de sous-clés
    let master_key = [0x42u8; 32];
    group.bench_function("derive_subkey", |b| {
        b.iter(|| {
            let subkey = derive_subkey(
                black_box(&master_key),
                black_box("test_context"),
                black_box(0)
            );
            black_box(subkey)
        })
    });
    
    // Benchmark comparaison sécurisée
    let data1 = vec![0x11u8; 1024];
    let data2 = vec![0x11u8; 1024];
    group.bench_function("secure_compare", |b| {
        b.iter(|| {
            let result = miaou::crypto::primitives::secure_compare(
                black_box(&data1),
                black_box(&data2)
            );
            black_box(result)
        })
    });
    
    group.finish();
}

fn benchmark_keystore_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("keystore");
    
    use miaou::crypto::keyring::{KeyStore, KeyStoreConfig, SecretKey};
    
    let config = KeyStoreConfig {
        argon2_config: Argon2Config::fast_insecure(), // Pour benchmarks rapides
        ..KeyStoreConfig::default()
    };
    
    // Benchmark création de trousseau
    group.bench_function("keystore_creation", |b| {
        b.iter(|| {
            let keystore = KeyStore::new_with_password(
                black_box(b"benchmark_password"),
                black_box(config.clone())
            ).unwrap();
            black_box(keystore)
        })
    });
    
    // Benchmark ajout de clés
    let mut keystore = KeyStore::new_with_password(b"test_password", config.clone()).unwrap();
    group.bench_function("keystore_add_key", |b| {
        b.iter(|| {
            let key = SecretKey::generate_encryption_key(
                "benchmark_key".to_string(),
                vec![]
            ).unwrap();
            keystore.add_secret_key(black_box(key)).unwrap();
        })
    });
    
    // Pré-remplir le trousseau pour les benchmarks de récupération
    let mut filled_keystore = KeyStore::new_with_password(b"test_password", config).unwrap();
    let mut key_ids = Vec::new();
    
    for i in 0..100 {
        let key = SecretKey::generate_encryption_key(
            format!("key_{}", i),
            vec![]
        ).unwrap();
        let key_id = key.metadata().key_id;
        key_ids.push(key_id);
        filled_keystore.add_secret_key(key).unwrap();
    }
    
    // Benchmark récupération de clés
    group.bench_function("keystore_get_key", |b| {
        let mut idx = 0;
        b.iter(|| {
            let key_id = &key_ids[idx % key_ids.len()];
            let retrieved = filled_keystore.get_secret_key(black_box(key_id)).unwrap();
            idx += 1;
            black_box(retrieved)
        })
    });
    
    // Benchmark export
    group.bench_function("keystore_export", |b| {
        b.iter(|| {
            let exported = filled_keystore.export_encrypted().unwrap();
            black_box(exported)
        })
    });
    
    group.finish();
}

fn benchmark_integrated_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrated_scenarios");
    
    // Scénario : chiffrement + signature d'un message
    let cipher = ChaCha20Poly1305Cipher::generate_key().unwrap();
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = vec![0x77u8; 4096];
    
    group.bench_function("encrypt_and_sign", |b| {
        b.iter(|| {
            let encrypted = cipher.encrypt_with_random_nonce(black_box(&message)).unwrap();
            let signature = keypair.sign(black_box(&encrypted.ciphertext)).unwrap();
            black_box((encrypted, signature))
        })
    });
    
    // Scénario : vérification + déchiffrement
    let encrypted = cipher.encrypt_with_random_nonce(&message).unwrap();
    let signature = keypair.sign(&encrypted.ciphertext).unwrap();
    
    group.bench_function("verify_and_decrypt", |b| {
        b.iter(|| {
            let valid = keypair.verify(black_box(&encrypted.ciphertext), black_box(&signature)).unwrap();
            if valid {
                let decrypted = cipher.decrypt_with_nonce(black_box(&encrypted)).unwrap();
                black_box(decrypted)
            } else {
                black_box(Vec::new())
            }
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_encryption,
    benchmark_signing,
    benchmark_hashing,
    benchmark_argon2,
    benchmark_primitives,
    benchmark_keystore_operations,
    benchmark_integrated_scenarios
);

criterion_main!(benches);