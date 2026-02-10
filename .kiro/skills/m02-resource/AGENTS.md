# Resource Management - Agent Integration

> **Skills:** m02-resource, m03-mutability, m12-lifecycle
> **Agent:** memory-resource-expert

## Quick Reference

These skills handle smart pointers, interior mutability, and resource lifecycle. They share the memory-resource-expert agent for comprehensive memory management guidance.

## When to Use Agent

Use the agent when:
- Choosing between Box/Rc/Arc/Weak
- Deciding on interior mutability (Cell/RefCell/Mutex/RwLock)
- Implementing RAII and Drop
- Designing connection pools
- Managing resource lifecycles
- Handling reference cycles

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/memory-resource-expert.md>
)
```

## Unified Coverage

The agent handles all three skills:
- **m02-resource**: Smart pointer selection
- **m03-mutability**: Interior mutability patterns
- **m12-lifecycle**: Resource lifecycle management

## Success Criteria

Agent invocation is successful when:
1. Appropriate smart pointers chosen
2. Interior mutability used correctly
3. Proper lifecycle management implemented
4. No memory leaks
5. Thread safety ensured
6. Acceptable performance overhead
