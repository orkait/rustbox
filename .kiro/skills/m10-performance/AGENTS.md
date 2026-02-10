# Performance - Agent Integration

> **Skill:** m10-performance
> **Agent:** performance-optimizer

## Quick Reference

This skill handles performance optimization in Rust. It can delegate to the performance-optimizer agent for comprehensive profiling, bottleneck identification, and optimization strategies.

## When to Use Agent

Use the agent when:
- Performance is below requirements
- Need to identify bottlenecks
- Optimizing hot paths
- Reducing allocations
- Improving algorithmic complexity

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/performance-optimizer.md>
)
```

## Performance Issues → Agent Mapping

| Issue | Agent Helps With |
|-------|------------------|
| Slow execution | Profiling and bottleneck identification |
| High memory usage | Allocation analysis and reduction |
| Poor scalability | Algorithmic improvements |
| Lock contention | Concurrency optimization |
| Cache misses | Data structure layout |

## Workflow

### Inline Mode (Known Optimization)
1. Identify specific optimization
2. Apply pattern from skill reference
3. Benchmark before/after

### Agent Mode (Unknown Bottleneck)
1. Describe performance issue
2. Invoke performance-optimizer agent
3. Agent profiles code
4. Agent identifies bottlenecks
5. Agent suggests optimizations
6. Apply and benchmark
7. Validate correctness

## Optimization Hierarchy

1. **Algorithm**: O(n²) → O(n log n) (biggest impact)
2. **Data Structures**: Vec vs HashMap vs BTreeMap
3. **Allocations**: Reduce heap allocations
4. **Copies**: Avoid unnecessary clones
5. **Micro-optimizations**: Only if proven necessary

## Agent Output Format

The agent provides:
- **Profiling Results**: Where time is spent
- **Bottlenecks Identified**: Hot paths and causes
- **Optimization Strategy**: Prioritized improvements
- **Implementation**: Optimized code
- **Benchmark Results**: Before/after comparison
- **Trade-offs**: Readability vs performance

## Common Optimizations

### 1. Reduce Allocations
```rust
// Before: allocate each iteration
for _ in 0..1000 {
    let mut buffer = Vec::new();
    process(&mut buffer);
}

// After: reuse allocation
let mut buffer = Vec::new();
for _ in 0..1000 {
    buffer.clear();
    process(&mut buffer);
}
```

### 2. Pre-allocate Capacity
```rust
// Before: multiple reallocations
let mut vec = Vec::new();
for i in 0..1000 {
    vec.push(i);
}

// After: single allocation
let mut vec = Vec::with_capacity(1000);
for i in 0..1000 {
    vec.push(i);
}
```

### 3. Use References
```rust
// Before: copies data
fn process(data: Vec<i32>) -> i32 {
    data.iter().sum()
}

// After: borrows data
fn process(data: &[i32]) -> i32 {
    data.iter().sum()
}
```

### 4. Iterator Chains
```rust
// Before: intermediate collections
let data: Vec<_> = input.iter().map(|x| x * 2).collect();
let result: Vec<_> = data.iter().filter(|x| **x > 10).collect();

// After: chained iterators
let result: Vec<_> = input
    .iter()
    .map(|x| x * 2)
    .filter(|x| *x > 10)
    .collect();
```

## Profiling Tools

The agent uses:
- **cargo-flamegraph**: CPU profiling
- **perf**: Linux performance analysis
- **Instruments**: macOS profiling
- **criterion**: Benchmarking
- **heaptrack**: Memory profiling

## Benchmarking

Always benchmark before and after:
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark(c: &mut Criterion) {
    c.bench_function("my_function", |b| {
        b.iter(|| my_function(black_box(42)))
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
```

## Related Agents

- **concurrency-expert**: For parallel optimization
- **ownership-analyzer**: For zero-copy optimization
- **refactor-assistant**: For performance refactoring

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Premature optimization | Wastes time | Profile first |
| Micro-optimizing cold paths | No impact | Focus on hot paths |
| Unsafe without proof | Risk without benefit | Benchmark first |
| Ignoring algorithm | Won't help O(n²) | Better algorithm |

## Success Criteria

Agent invocation is successful when:
1. Bottlenecks are identified through profiling
2. Optimizations are applied to hot paths
3. Improvements are validated with benchmarks
4. Code remains readable and maintainable
5. Performance meets requirements
