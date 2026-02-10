# Mental Models - Agent Integration

> **Skill:** m14-mental-model
> **Agent:** rust-mentor

## Quick Reference

This skill helps learners understand Rust concepts. It can delegate to the rust-mentor agent for comprehensive teaching with clear mental models and analogies.

## When to Use Agent

Use the agent when:
- Explaining Rust concepts to learners
- Correcting misconceptions
- Providing analogies for complex topics
- Helping developers transition from other languages
- Building intuition for Rust's design

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/rust-mentor.md>
)
```

## Teaching Scenarios

| Scenario | Agent Helps With |
|----------|------------------|
| Ownership confusion | Unique key analogy |
| Borrowing questions | Library book analogy |
| Lifetime issues | Ticket validity analogy |
| Move semantics | Handing over keys analogy |
| Language transition | Comparing with Java/Python/C++ |
| Misconceptions | Identifying and correcting |

## Workflow

### Inline Mode (Simple Concept)
1. Identify concept
2. Provide quick explanation from skill
3. Show example

### Agent Mode (Deep Learning)
1. Describe learning need
2. Invoke rust-mentor agent
3. Agent assesses background
4. Agent chooses mental model
5. Agent explains with analogy
6. Agent provides examples
7. Agent addresses misconceptions

## Mental Models

### Ownership
```
Ownership = Unique house key
- Only one person has the key
- Giving away key = can't enter anymore
- House demolished when last key lost
```

### Borrowing
```
Borrowing = Library book
- Read (&T) = many readers
- Write (&mut T) = one writer
- Must return before library closes
```

### Lifetimes
```
Lifetimes = Ticket validity
- "Valid until 5pm"
- Can't use expired ticket
- Ticket can't outlive event
```

## Agent Output Format

The agent provides:
- **Concept**: Clear definition
- **Analogy**: Relatable comparison
- **Why**: Design rationale
- **Example**: Concrete code
- **Common Mistake**: What to avoid
- **Correct Approach**: How to do it right
- **Next Steps**: What to learn next

## Success Criteria

Agent invocation is successful when:
1. Builds correct mental model
2. Uses relatable analogies
3. Explains the "why"
4. Shows concrete examples
5. Addresses misconceptions
6. Connects to prior knowledge
7. Provides learning path
