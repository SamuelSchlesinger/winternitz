use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use winternitz::{WinternitzOTS, WinternitzOTSPlus};

fn bench_wots_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS Key Generation");
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            let mut wots = WinternitzOTS::<32, 80>::new(16).unwrap();
            wots.generate_keys().unwrap();
        })
    });
    
    group.finish();
}

fn bench_wots_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS Signature");
    let message = b"This is a test message to be signed with Winternitz OTS";
    
    // Create keys once
    let mut wots = WinternitzOTS::<32, 80>::new(16).unwrap();
    wots.generate_keys().unwrap();
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            let mut signature = [[0u8; 32]; 80];
            wots.sign(message, &mut signature).unwrap();
        })
    });
    
    group.finish();
}

fn bench_wots_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS Verification");
    let message = b"This is a test message to be signed with Winternitz OTS";
    
    // Create keys and signature once
    let mut wots = WinternitzOTS::<32, 80>::new(16).unwrap();
    wots.generate_keys().unwrap();
    let mut signature = [[0u8; 32]; 80];
    wots.sign(message, &mut signature).unwrap();
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            wots.verify(message, &signature).unwrap()
        })
    });
    
    group.finish();
}

fn bench_wots_plus_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS+ Key Generation");
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            let mut wots = WinternitzOTSPlus::<32, 80>::new(16).unwrap();
            wots.generate_keys().unwrap();
        })
    });
    
    group.finish();
}

fn bench_wots_plus_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS+ Signature");
    let message = b"This is a test message to be signed with Winternitz OTS";
    
    // Create keys once
    let mut wots = WinternitzOTSPlus::<32, 80>::new(16).unwrap();
    wots.generate_keys().unwrap();
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            let mut signature = [[0u8; 32]; 80];
            wots.sign(message, &mut signature).unwrap();
        })
    });
    
    group.finish();
}

fn bench_wots_plus_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS+ Verification");
    let message = b"This is a test message to be signed with Winternitz OTS";
    
    // Create keys and signature once
    let mut wots = WinternitzOTSPlus::<32, 80>::new(16).unwrap();
    wots.generate_keys().unwrap();
    let mut signature = [[0u8; 32]; 80];
    wots.sign(message, &mut signature).unwrap();
    
    group.bench_function("stack-based", |b| {
        b.iter(|| {
            wots.verify(message, &signature).unwrap()
        })
    });
    
    group.finish();
}

fn bench_winternitz_parameter(c: &mut Criterion) {
    let mut group = c.benchmark_group("Winternitz Parameter Comparison");
    let message = b"This is a test message to be signed with Winternitz OTS";
    
    // For smaller values of w, we need larger L values to accommodate the increased length
    // Use w=16 as a baseline since that's what the tests use
    
    // Benchmark only w=16 which we know works with L=80
    let w = 16;
    
    // Benchmark key generation
    group.bench_with_input(BenchmarkId::new("keygen", w), &w, |b, &w| {
        b.iter(|| {
            let mut wots = WinternitzOTS::<32, 80>::new(w).unwrap();
            wots.generate_keys().unwrap();
        })
    });
    
    // Generate common key for sign/verify benchmarks
    let mut wots = WinternitzOTS::<32, 80>::new(w).unwrap();
    wots.generate_keys().unwrap();
    
    // Benchmark signature
    group.bench_with_input(BenchmarkId::new("sign", w), &w, |b, _| {
        b.iter(|| {
            let mut signature = [[0u8; 32]; 80];
            wots.sign(message, &mut signature).unwrap();
        })
    });
    
    // Create signature once for verify benchmark
    let mut signature = [[0u8; 32]; 80];
    wots.sign(message, &mut signature).unwrap();
    
    // Benchmark verification
    group.bench_with_input(BenchmarkId::new("verify", w), &w, |b, _| {
        b.iter(|| {
            wots.verify(message, &signature).unwrap()
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_wots_keygen,
    bench_wots_sign,
    bench_wots_verify,
    bench_wots_plus_keygen,
    bench_wots_plus_sign,
    bench_wots_plus_verify,
    bench_winternitz_parameter,
);
criterion_main!(benches);