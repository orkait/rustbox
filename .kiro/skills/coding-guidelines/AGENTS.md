# Coding Guidelines - Agent Integration

> **Skill:** coding-guidelines
> **Agent:** style-guide-enforcer

## Quick Reference

This skill handles Rust coding standards and best practices. It uses the style-guide-enforcer agent for comprehensive style review.

## When to Use Agent

Use the agent when:
- Reviewing code for style violations
- Enforcing naming conventions
- Learning idiomatic Rust patterns
- Configuring clippy/rustfmt
- Teaching best practices

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/style-guide-enforcer.md>
)
```

## Coverage

The agent enforces:
- Naming conventions (no `get_` prefix, iterator names, conversion names)
- Data type best practices (newtypes, pre-allocation)
- String handling (prefer `&str`, use `Cow`, `format!`)
- Error handling (`?` operator, `expect` over `unwrap`)
- Memory patterns (meaningful lifetimes, `try_borrow`)
- Concurrency (atomics, no locks across await)
- Deprecated pattern detection

## Success Criteria

Agent invocation is successful when:
1. All style violations identified
2. Explanations provided for each rule
3. Correct examples shown
4. Tool configurations recommended
5. Idiomatic patterns taught
