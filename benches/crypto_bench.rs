// Benchmarks détaillés pour les primitives cryptographiques
// Performance tests pour Miaou v0.1.0

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use miaou_crypto::{
    aead::{AeadKeyRef, encrypt_auto_nonce, decrypt},
    sign::Keypair,
    hash::blake3_32,
    kdf::{Argon2Config, hash_password},
};
use secrecy::SecretString;
use rand_core::OsRng;

fn bench_blake3_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hashing");
    
    // Test différentes tailles de données
    for size in [1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        let data = vec![0u8; *size];
        
        group.bench_with_input(BenchmarkId::new("hash", size), size, |b, &_size| {
            b.iter(|| blake3_32(black_box(&data)))
        });
    }
    group.finish();
}

fn bench_ed25519_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_operations");
    
    let keypair = Keypair::generate();
    let message = b"benchmark message for signature testing";
    let signature = keypair.sign(message);
    
    group.bench_function("key_generation", |b| {
        b.iter(|| Keypair::generate())
    });
    
    group.bench_function("signing", |b| {
        b.iter(|| keypair.sign(black_box(message)))
    });
    
    group.bench_function("verification", |b| {
        b.iter(|| keypair.verify(black_box(message), black_box(&signature)).unwrap())
    });
    
    group.finish();
}

fn bench_chacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_poly1305");
    
    let key = AeadKeyRef::from_bytes([42u8; 32]);
    let aad = b"benchmark_aad";
    let mut rng = OsRng;
    
    // Test différentes tailles de données
    for size in [64, 256, 1024, 4096, 16384].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        let data = vec![0u8; *size];
        let encrypted = encrypt_auto_nonce(&key, aad, &data, &mut rng).unwrap();
        
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, &_size| {
            b.iter(|| encrypt_auto_nonce(&key, aad, black_box(&data), &mut rng).unwrap())
        });
        
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, &_size| {
            b.iter(|| decrypt(&key, aad, black_box(&encrypted)).unwrap())
        });
    }
    group.finish();
}

fn bench_argon2_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2_kdf");
    
    let password = SecretString::new("test_password_for_benchmarking".to_string());
    
    group.bench_function("fast_insecure", |b| {
        let config = Argon2Config::fast_insecure();
        b.iter(|| hash_password(black_box(&password), black_box(&config)).unwrap())
    });
    
    group.bench_function("balanced", |b| {
        let config = Argon2Config::balanced();
        b.iter(|| hash_password(black_box(&password), black_box(&config)).unwrap())
    });
    
    group.bench_function("secure", |b| {
        let config = Argon2Config::secure();
        b.iter(|| hash_password(black_box(&password), black_box(&config)).unwrap())
    });
    
    group.finish();
}

fn bench_combined_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined_workflow");
    
    // Workflow complet : génération clé + chiffrement + signature
    let message = b"Complete workflow test message";
    let aad = b"workflow_test";
    let mut rng = OsRng;
    
    group.bench_function("complete_encrypt_sign", |b| {
        b.iter(|| {
            // Génération des clés
            let keypair = Keypair::generate();
            let aead_key = AeadKeyRef::from_bytes([42u8; 32]);
            
            // Chiffrement
            let encrypted = encrypt_auto_nonce(&aead_key, aad, black_box(message), &mut rng).unwrap();
            
            // Signature du chiffré
            let signature = keypair.sign(&encrypted.ciphertext);
            
            // Hash du tout pour intégrité
            let mut combined = encrypted.ciphertext.clone();
            combined.extend_from_slice(&signature.to_bytes());
            let _hash = blake3_32(&combined);
            
            (encrypted, signature)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_blake3_hashing,
    bench_ed25519_operations,
    bench_chacha20_poly1305,
    bench_argon2_kdf,
    bench_combined_workflow
);
criterion_main!(benches);