# Error Handling - Agent Integration

> **Skill:** m06-error-handling
> **Agent:** error-handling-expert

## Quick Reference

This skill handles error handling design and implementation in Rust. It can delegate to the error-handling-expert agent for comprehensive error strategy design.

## When to Use Agent

Use the agent when:
- Designing error types for a new module/crate
- Refactoring existing error handling
- Choosing between error handling approaches
- Implementing error recovery strategies
- Converting between error types

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/error-handling-expert.md>
)
```

## Error Handling Scenarios

| Scenario | Agent Helps With |
|----------|------------------|
| Library error design | Custom error type design with thiserror |
| Application errors | anyhow integration and context |
| Error conversion | From/Into implementations |
| Error propagation | ? operator and error chains |
| Error recovery | Fallback and retry strategies |
| User-facing errors | Error message design |

## Workflow

### Inline Mode (Simple Cases)
1. Identify error handling need
2. Apply pattern from skill reference
3. Implement with Result<T, E>

### Agent Mode (Complex Design)
1. Describe error handling requirements
2. Invoke error-handling-expert agent
3. Agent designs error type hierarchy
4. Agent provides implementation
5. Apply and test error handling
6. Validate with error scenarios

## Library vs Application

### Library Error Design (Use Agent)
```
Requirements:
- Public API with custom errors
- Callers need to match on errors
- Error context and recovery

Agent provides:
- Custom error enum design
- thiserror implementation
- Conversion implementations
- Documentation
```

### Application Error Design (Use Agent)
```
Requirements:
- Internal error handling
- Good error messages
- Context at each layer

Agent provides:
- anyhow integration
- Context strategy
- Error logging approach
- User-facing messages
```

## Agent Output Format

The agent provides:
- **Current Approach**: Analysis of existing error handling
- **Issues Identified**: Problems with current approach
- **Recommended Design**: Error type definitions
- **Usage Examples**: How to use the error types
- **Propagation Strategy**: How errors flow through system
- **Recovery Strategy**: How to handle/recover from errors

## Common Patterns

### Pattern 1: Custom Error Type
```rust
#[derive(Error, Debug)]
pub enum MyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
}
```

### Pattern 2: Application Errors
```rust
use anyhow::{Context, Result};

fn load() -> Result<Data> {
    let data = read_file()
        .context("Failed to read file")?;
    Ok(data)
}
```

### Pattern 3: Error Recovery
```rust
let data = load_from_cache()
    .or_else(|_| load_from_network())
    .unwrap_or_default();
```

## Related Agents

- **ownership-analyzer**: For lifetime issues with errors
- **refactor-assistant**: For error handling refactoring
- **code-navigator**: For finding error usage

## Success Criteria

Agent invocation is successful when:
1. Error types match use case (library vs app)
2. Errors are actionable and informative
3. Error propagation is clean (? operator)
4. Recovery strategies are appropriate
5. Error messages help debugging
