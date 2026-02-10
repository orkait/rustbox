# Anti-Patterns - Agent Integration

> **Skill:** m15-anti-pattern
> **Agent:** anti-pattern-detector

## Quick Reference

This skill identifies Rust anti-patterns and code smells. It can delegate to the anti-pattern-detector agent for comprehensive code review.

## When to Use Agent

Use the agent when:
- Reviewing code for anti-patterns
- Identifying code smells
- Refactoring problematic code
- Learning idiomatic Rust
- Improving code quality

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/anti-pattern-detector.md>
)
```

## Anti-Pattern Detection

| Anti-Pattern | Agent Detects |
|--------------|---------------|
| Clone everywhere | Ownership design issues |
| Unwrap in production | Missing error handling |
| String for everything | Primitive obsession |
| Index-based loops | Not using iterators |
| Boolean flags | Missing type state |
| Rc/Arc everywhere | Unclear ownership |
| Giant functions | Missing extraction |
| Public fields | Broken encapsulation |

## Workflow

### Inline Mode (Known Anti-Pattern)
1. Identify specific anti-pattern
2. Apply fix from skill reference
3. Validate improvement

### Agent Mode (Code Review)
1. Provide code to review
2. Invoke anti-pattern-detector agent
3. Agent scans for anti-patterns
4. Agent analyzes root causes
5. Agent suggests fixes
6. Agent provides refactoring steps
7. Apply improvements

## Common Anti-Patterns

### Clone Everywhere
```rust
// Bad
let copy1 = data.clone();
let copy2 = data.clone();

// Good
let ref1 = &data;
let ref2 = &data;
```

### Unwrap in Production
```rust
// Bad
let file = File::open("config").unwrap();

// Good
let file = File::open("config")
    .context("Failed to open config")?;
```

### String for Everything
```rust
// Bad
fn get_user(id: String) -> User { ... }

// Good
struct UserId(Uuid);
fn get_user(id: UserId) -> User { ... }
```

## Agent Output Format

The agent provides:
- **Anti-Patterns Found**: List with locations
- **Why Bad**: Problems with each pattern
- **Root Cause**: Design issues
- **Recommended Fix**: Better code
- **Benefits**: What improves
- **Refactoring Priority**: What to fix first

## Detection Checklist

The agent checks:
- [ ] Excessive `.clone()` calls
- [ ] `.unwrap()` in production
- [ ] String for everything
- [ ] Index-based loops
- [ ] Boolean flags for state
- [ ] Rc/Arc without justification
- [ ] Giant functions
- [ ] Public fields with invariants
- [ ] Unsafe without SAFETY comment

## Success Criteria

Agent invocation is successful when:
1. All anti-patterns identified
2. Root causes explained
3. Idiomatic alternatives suggested
4. Refactoring steps provided
5. Code quality improves
6. Better patterns learned
