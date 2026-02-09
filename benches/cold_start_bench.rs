// Cold-start benchmark for judge-v1 performance contract
// Measures end-to-end latency from CLI invocation to payload execution
// Target: p50 < 100ms, p95 < 200ms for simple payloads

use std::process::Command;
use std::time::{Duration, Instant};

/// Benchmark configuration
const ITERATIONS: usize = 100;
const WARMUP_ITERATIONS: usize = 10;

/// Latency percentiles
struct LatencyStats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    min: Duration,
    max: Duration,
    mean: Duration,
}

impl LatencyStats {
    fn from_samples(mut samples: Vec<Duration>) -> Self {
        samples.sort();
        let len = samples.len();
        
        let p50_idx = (len as f64 * 0.50) as usize;
        let p95_idx = (len as f64 * 0.95) as usize;
        let p99_idx = (len as f64 * 0.99) as usize;
        
        let sum: Duration = samples.iter().sum();
        let mean = sum / len as u32;
        
        Self {
            p50: samples[p50_idx],
            p95: samples[p95_idx],
            p99: samples[p99_idx],
            min: samples[0],
            max: samples[len - 1],
            mean,
        }
    }
    
    fn print(&self, label: &str) {
        println!("\n{}", label);
        println!("  p50: {:?}", self.p50);
        println!("  p95: {:?}", self.p95);
        println!("  p99: {:?}", self.p99);
        println!("  min: {:?}", self.min);
        println!("  max: {:?}", self.max);
        println!("  mean: {:?}", self.mean);
    }
}

/// Benchmark result
struct BenchmarkResult {
    scenario: String,
    stats: LatencyStats,
    passed: bool,
    reason: Option<String>,
}

impl BenchmarkResult {
    fn print(&self) {
        println!("\n=== {} ===", self.scenario);
        self.stats.print("Latency");
        
        if self.passed {
            println!("✅ PASS");
        } else {
            println!("❌ FAIL: {}", self.reason.as_ref().unwrap());
        }
    }
}

/// Measure cold-start latency for a simple C++ hello world
fn benchmark_cpp_hello_world() -> BenchmarkResult {
    let code = r#"
#include <iostream>
int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
"#;
    
    let mut samples = Vec::new();
    
    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=cpp17")
            .arg("--code")
            .arg(code)
            .output();
    }
    
    // Actual benchmark
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=cpp17")
            .arg("--code")
            .arg(code)
            .output();
        let elapsed = start.elapsed();
        samples.push(elapsed);
    }
    
    let stats = LatencyStats::from_samples(samples);
    
    // Judge-v1 budget: p50 < 100ms, p95 < 200ms
    let passed = stats.p50 < Duration::from_millis(100) && stats.p95 < Duration::from_millis(200);
    let reason = if !passed {
        Some(format!(
            "p50={:?} (target <100ms), p95={:?} (target <200ms)",
            stats.p50, stats.p95
        ))
    } else {
        None
    };
    
    BenchmarkResult {
        scenario: "C++ Hello World".to_string(),
        stats,
        passed,
        reason,
    }
}

/// Measure cold-start latency for a simple Python hello world
fn benchmark_python_hello_world() -> BenchmarkResult {
    let code = r#"print("Hello, World!")"#;
    
    let mut samples = Vec::new();
    
    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=python3.11")
            .arg("--code")
            .arg(code)
            .output();
    }
    
    // Actual benchmark
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=python3.11")
            .arg("--code")
            .arg(code)
            .output();
        let elapsed = start.elapsed();
        samples.push(elapsed);
    }
    
    let stats = LatencyStats::from_samples(samples);
    
    // Python has higher startup overhead: p50 < 150ms, p95 < 300ms
    let passed = stats.p50 < Duration::from_millis(150) && stats.p95 < Duration::from_millis(300);
    let reason = if !passed {
        Some(format!(
            "p50={:?} (target <150ms), p95={:?} (target <300ms)",
            stats.p50, stats.p95
        ))
    } else {
        None
    };
    
    BenchmarkResult {
        scenario: "Python Hello World".to_string(),
        stats,
        passed,
        reason,
    }
}

/// Measure cold-start latency for a simple Java hello world
fn benchmark_java_hello_world() -> BenchmarkResult {
    let code = r#"
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"#;
    
    let mut samples = Vec::new();
    
    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=java17")
            .arg("--code")
            .arg(code)
            .output();
    }
    
    // Actual benchmark
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let _ = Command::new("rustbox")
            .arg("run")
            .arg("--lang=java17")
            .arg("--code")
            .arg(code)
            .output();
        let elapsed = start.elapsed();
        samples.push(elapsed);
    }
    
    let stats = LatencyStats::from_samples(samples);
    
    // Java has highest startup overhead: p50 < 250ms, p95 < 500ms
    let passed = stats.p50 < Duration::from_millis(250) && stats.p95 < Duration::from_millis(500);
    let reason = if !passed {
        Some(format!(
            "p50={:?} (target <250ms), p95={:?} (target <500ms)",
            stats.p50, stats.p95
        ))
    } else {
        None
    };
    
    BenchmarkResult {
        scenario: "Java Hello World".to_string(),
        stats,
        passed,
        reason,
    }
}

fn main() {
    println!("=== Rustbox Judge-V1 Cold-Start Benchmark ===");
    println!("Iterations: {} (after {} warmup)", ITERATIONS, WARMUP_ITERATIONS);
    
    let results = vec![
        benchmark_cpp_hello_world(),
        benchmark_python_hello_world(),
        benchmark_java_hello_world(),
    ];
    
    // Print all results
    for result in &results {
        result.print();
    }
    
    // Summary
    let passed_count = results.iter().filter(|r| r.passed).count();
    let total_count = results.len();
    
    println!("\n=== Summary ===");
    println!("{}/{} scenarios passed", passed_count, total_count);
    
    if passed_count == total_count {
        println!("✅ All cold-start budgets met");
        std::process::exit(0);
    } else {
        println!("❌ Some cold-start budgets exceeded");
        std::process::exit(1);
    }
}
