# Domain Modeling - Agent Integration

> **Skill:** m09-domain
> **Agent:** domain-modeler

## Quick Reference

This skill handles domain-driven design in Rust. It can delegate to the domain-modeler agent for comprehensive domain modeling guidance.

## When to Use Agent

Use the agent when:
- Modeling domain concepts (Entity, Value Object, Aggregate)
- Designing domain models from business requirements
- Defining aggregate boundaries
- Implementing domain invariants
- Separating domain from infrastructure

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/domain-modeler.md>
)
```

## Domain Modeling Scenarios

| Scenario | Agent Helps With |
|----------|------------------|
| Entity design | Identity and equality patterns |
| Value Object | Immutable value types |
| Aggregate | Consistency boundaries |
| Domain Service | Stateless operations |
| Domain Event | Event modeling |
| Repository | Persistence abstraction |

## Workflow

### Inline Mode (Known Pattern)
1. Identify domain concept type
2. Apply pattern from skill reference
3. Implement with business rules

### Agent Mode (Complex Domain)
1. Describe business requirements
2. Invoke domain-modeler agent
3. Agent classifies concepts
4. Agent designs types
5. Agent defines relationships
6. Apply domain model

## Domain Patterns

### Entity
```rust
struct User {
    id: UserId,
    email: Email,
    // Identity-based equality
}
```

### Value Object
```rust
struct Money {
    amount: i64,
    currency: Currency,
    // Value-based equality
}
```

### Aggregate
```rust
mod order {
    pub struct Order {
        id: OrderId,
        items: Vec<OrderItem>,  // Private children
    }
}
```

## Agent Output Format

The agent provides:
- **Domain Analysis**: Classification and identity
- **Implementation**: Type definitions and methods
- **Business Rules**: What invariants are enforced
- **Aggregate Boundaries**: Consistency boundaries
- **Usage Example**: How to use the model

## Success Criteria

Agent invocation is successful when:
1. Domain concepts are accurately modeled
2. Business rules are encapsulated
3. Invariants are maintained
4. Aggregate boundaries are clear
5. Domain is separated from infrastructure
6. Model is testable in isolation
