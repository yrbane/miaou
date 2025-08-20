//! Benchmarks de performance cryptographique
//! 
//! Mesure des performances des primitives cryptographiques de Miaou
//! pour s'assurer qu'elles respectent les objectifs de performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use miaou::crypto::{
    hash::{blake3_32, secure_compare},
    kdf::{Argon2Config, derive_key_32, hash_password},
    aead::{AeadKeyRef, random_nonce, encrypt_auto_nonce, decrypt},
    sign::Keypair,
};
use rand_core::OsRng;
use secrecy::SecretString;

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
                    let hash = blake3_32(black_box(&data));
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
                    let hash = miaou::crypto::hash::blake3_keyed(black_box(&key), black_box(&data));
                    black_box(hash)
                })
            }
        );
    }
    
    group.finish();
}

fn benchmark_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");
    
    let password = SecretString::new("test_password_for_benchmarking".to_string());
    let salt = miaou::crypto::kdf::generate_salt();
    
    // Test différentes configurations Argon2
    let configs = vec![
        ("fast", Argon2Config::fast_insecure()),
        ("default", Argon2Config::balanced()),
        ("secure", Argon2Config::secure()),
    ];
    
    for (name, config) in configs {
        group.bench_function(format!("argon2_derive_{}", name), |b| {
            b.iter(|| {
                let derived = derive_key_32(
                    black_box(&password),
                    black_box(&salt),
                    black_box(&config)
                ).unwrap();
                black_box(derived)
            })
        });
        
        group.bench_function(format!("argon2_hash_{}", name), |b| {
            b.iter(|| {
                let hash = hash_password(
                    black_box(&password),
                    black_box(&config)
                ).unwrap();
                black_box(hash)
            })
        });
    }
    
    group.finish();
}

fn benchmark_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    
    let key = AeadKeyRef::from_bytes([42u8; 32]);
    let mut rng = OsRng;
    let aad = b"benchmark_aad";
    
    // Test différentes tailles pour AEAD
    for size in [64, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0x42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let encrypted = encrypt_auto_nonce(
                        black_box(&key),
                        black_box(aad),
                        black_box(&data),
                        &mut rng,
                    ).unwrap();
                    black_box(encrypted)
                })
            }
        );
        
        // Benchmark decrypt
        let encrypted = encrypt_auto_nonce(&key, aad, &data, &mut rng).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let decrypted = decrypt(
                        black_box(&key),
                        black_box(aad),
                        black_box(&encrypted),
                    ).unwrap();
                    black_box(decrypted)
                })
            }
        );
    }
    
    group.finish();
}

fn benchmark_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("signatures");
    
    let keypair = Keypair::generate();
    let message = b"test message for signature benchmarking";
    
    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            let kp = Keypair::generate();
            black_box(kp)
        })
    });
    
    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let sig = keypair.sign(black_box(message));
            black_box(sig)
        })
    });
    
    let signature = keypair.sign(message);
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let result = keypair.verify(black_box(message), black_box(&signature));
            black_box(result)
        })
    });
    
    group.finish();
}

fn benchmark_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives");
    
    // Benchmark génération de nonces aléatoires
    let mut rng = OsRng;
    group.bench_function("random_nonce", |b| {
        b.iter(|| {
            let nonce = random_nonce(&mut rng);
            black_box(nonce)
        })
    });
    
    // Benchmark comparaison sécurisée
    let data1 = vec![0x11u8; 1024];
    let data2 = vec![0x11u8; 1024];
    group.bench_function("secure_compare", |b| {
        b.iter(|| {
            let result = secure_compare(
                black_box(&data1),
                black_box(&data2)
            );
            black_box(result)
        })
    });
    
    group.finish();
}

fn benchmark_combined_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined_operations");
    
    // Benchmark d'opérations combinées typiques
    let data = vec![0x33u8; 4096];
    
    group.bench_function("hash_and_derive", |b| {
        b.iter(|| {
            // Hash initial
            let hash = blake3_32(black_box(&data));
            
            // Dérivation de sous-clé basée sur le hash
            let subkey = miaou::crypto::kdf::derive_subkey_32(
                hash.as_slice(),
                b"derived_key"
            ).unwrap();
            
            black_box(subkey)
        })
    });
    
    group.bench_function("full_crypto_cycle", |b| {
        b.iter(|| {
            // Génération d'une paire de clés
            let keypair = Keypair::generate();
            
            // Chiffrement des données
            let aead_key = AeadKeyRef::from_bytes([42u8; 32]);
            let mut rng = OsRng;
            let encrypted = encrypt_auto_nonce(&aead_key, b"aad", &data, &mut rng).unwrap();
            
            // Signature des données chiffrées
            let signature = keypair.sign(&encrypted.ciphertext);
            
            black_box((encrypted, signature))
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_hashing,
    benchmark_argon2,
    benchmark_aead,
    benchmark_signatures,
    benchmark_primitives,
    benchmark_combined_operations
);

criterion_main!(benches);