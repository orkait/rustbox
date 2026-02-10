# Zero-Cost Abstraction - Agent Integration

> **Skills:** m04-zero-cost, m11-ecosystem
> **Agent:** abstraction-architect

## Quick Reference

These skills handle generics, traits, and ecosystem integration. They share the abstraction-architect agent for comprehensive abstraction design and crate selection.

## When to Use Agent

Use the agent when:
- Choosing between static and dynamic dispatch
- Designing trait-based APIs
- Selecting crates from ecosystem
- Integrating external libraries
- Optimizing abstraction overhead
- Building plugin systems

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/abstraction-architect.md>
)
```

## Unified Coverage

The agent handles both skills:
- **m04-zero-cost**: Generics, traits, dispatch strategies
- **m11-ecosystem**: Crate selection and integration

## Success Criteria

Agent invocation is successful when:
1. Zero-cost abstractions used where possible
2. Appropriate dispatch strategy chosen
3. Well-maintained crates selected
4. Clean integration implemented
5. Acceptable performance
6. Minimal dependencies
