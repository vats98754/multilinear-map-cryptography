//! Prover performance benchmarks for Twist and Shout protocols

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use twist_and_shout::*;

fn benchmark_twist_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("twist_prover");
    
    for log_size in [8, 10, 12].iter() {
        let (prover_params, _) = setup_params(*log_size);
        let memory_size = 1 << log_size;
        
        group.bench_with_input(
            BenchmarkId::new("memory_operations", memory_size),
            log_size,
            |b, &log_size| {
                b.iter(|| {
                    // This will be implemented when we have the full Twist protocol
                    black_box(log_size);
                })
            },
        );
    }
    
    group.finish();
}

fn benchmark_shout_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("shout_prover");
    
    for log_size in [8, 10, 12].iter() {
        let (prover_params, _) = setup_params(*log_size);
        let table_size = 1 << log_size;
        
        group.bench_with_input(
            BenchmarkId::new("lookup_operations", table_size),
            log_size,
            |b, &log_size| {
                b.iter(|| {
                    // This will be implemented when we have the full Shout protocol
                    black_box(log_size);
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, benchmark_twist_prover, benchmark_shout_prover);
criterion_main!(benches);