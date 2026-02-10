# Type-Driven Design - Agent Integration

> **Skill:** m05-type-driven
> **Agent:** type-system-designer

## Quick Reference

This skill handles type-driven design in Rust. It can delegate to the type-system-designer agent for comprehensive type system design and pattern selection.

## When to Use Agent

Use the agent when:
- Designing type-safe APIs
- Making invalid states unrepresentable
- Choosing between type patterns (newtype, type state, phantom data)
- Encoding invariants in types
- Creating compile-time validated APIs

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/type-system-designer.md>
)
```

## Type Design Scenarios

| Scenario | Agent Helps With |
|----------|------------------|
| Semantic type safety | Newtype pattern design |
| State machine | Type state pattern implementation |
| Compile-time validation | Phantom type usage |
| Capability markers | Marker trait design |
| Gradual construction | Builder pattern |
| Closed trait set | Sealed trait pattern |

## Workflow

### Inline Mode (Simple Pattern)
1. Identify constraint type
2. Apply pattern from skill reference
3. Implement with validation

### Agent Mode (Complex Design)
1. Describe type safety requirements
2. Invoke type-system-designer agent
3. Agent analyzes constraints
4. Agent chooses appropriate pattern
5. Agent provides full implementation
6. Apply and test

## Type Patterns

### Newtype
```rust
struct UserId(u64);
struct Email(String);
```

### Type State
```rust
struct Connection<State> {
    stream: TcpStream,
    _state: PhantomData<State>,
}
```

### Builder
```rust
ConfigBuilder::new()
    .host("localhost")
    .port(8080)
    .build()?
```

## Agent Output Format

The agent provides:
- **Requirements**: What constraints to enforce
- **Chosen Pattern**: Pattern name and rationale
- **Implementation**: Complete type definitions
- **Usage Example**: How to use the API
- **Benefits**: What the design achieves
- **Compile-Time Guarantees**: What compiler prevents

## Success Criteria

Agent invocation is successful when:
1. Invalid states are unrepresentable
2. Validation happens at construction
3. API is ergonomic
4. Zero or minimal runtime cost
5. Code is self-documenting
6. Compiler prevents misuse
