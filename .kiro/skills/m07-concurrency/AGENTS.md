# Concurrency - Agent Integration

> **Skill:** m07-concurrency
> **Agent:** concurrency-expert

## Quick Reference

This skill handles concurrency issues in Rust. It can delegate to the concurrency-expert agent for deep analysis of concurrent code, deadlock prevention, and performance optimization.

## When to Use Agent

Use the agent when:
- Designing concurrent architecture
- Debugging deadlocks or race conditions
- Optimizing concurrent performance
- Choosing synchronization primitives
- Converting between sync and async

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/concurrency-expert.md>
)
```

## Concurrency Issues → Agent Mapping

| Issue | Agent Helps With |
|-------|------------------|
| Deadlock | Lock ordering analysis |
| Lock contention | Synchronization primitive selection |
| Logical race | Ordering and synchronization design |
| Performance | Parallel vs async decision |
| Thread safety | Send/Sync implementation |
| Async design | Tokio/async-std patterns |

## Workflow

### Inline Mode (Simple Cases)
1. Identify concurrency pattern
2. Apply pattern from skill reference
3. Use Arc<Mutex<T>> or channels

### Agent Mode (Complex Issues)
1. Describe concurrency requirements
2. Invoke concurrency-expert agent
3. Agent analyzes architecture
4. Agent recommends primitives
5. Agent provides implementation
6. Test with stress tests

## Concurrency Patterns

### Pattern 1: Shared State
```rust
use std::sync::{Arc, Mutex};

let data = Arc::new(Mutex::new(Vec::new()));
let data_clone = Arc::clone(&data);

thread::spawn(move || {
    let mut data = data_clone.lock().unwrap();
    data.push(42);
});
```

### Pattern 2: Message Passing
```rust
use std::sync::mpsc;

let (tx, rx) = mpsc::channel();

thread::spawn(move || {
    tx.send(42).unwrap();
});

let value = rx.recv().unwrap();
```

### Pattern 3: Async/Await
```rust
#[tokio::main]
async fn main() {
    let result = fetch_data().await;
    process(result).await;
}
```

## Agent Output Format

The agent provides:
- **Current Situation**: Analysis of concurrency pattern
- **Issues Identified**: Deadlocks, races, bottlenecks
- **Recommended Approach**: Synchronization strategy
- **Implementation**: Code with proper primitives
- **Testing Strategy**: How to test concurrent code
- **Performance Considerations**: Scalability analysis

## Deadlock Prevention

The agent helps with:
1. **Lock Ordering**: Consistent lock acquisition order
2. **Try-Lock Pattern**: Non-blocking lock attempts
3. **Minimize Lock Scope**: Hold locks briefly
4. **Avoid Nested Locks**: Reduce lock complexity

## Performance Optimization

The agent helps with:
1. **Reduce Contention**: Use RwLock or Atomic
2. **Avoid False Sharing**: Cache line alignment
3. **Batch Operations**: Lock once, do many operations
4. **Choose Right Primitive**: Mutex vs RwLock vs Atomic

## Async vs Threads

| Use Threads | Use Async |
|-------------|-----------|
| CPU-bound work | I/O-bound work |
| Parallel computation | Network requests |
| Blocking operations | High concurrency |

## Related Agents

- **ownership-analyzer**: For Send/Sync issues
- **performance-optimizer**: For concurrent performance
- **unsafe-code-reviewer**: For lock-free code

## Testing Tools

- **Miri**: Detect undefined behavior
- **Loom**: Model checker for concurrency
- **ThreadSanitizer**: Runtime race detector
- **Stress tests**: High-load testing

## Success Criteria

Agent invocation is successful when:
1. Concurrency pattern is correct
2. No deadlocks or data races
3. Performance meets requirements
4. Code is testable
5. Synchronization is minimal but sufficient
