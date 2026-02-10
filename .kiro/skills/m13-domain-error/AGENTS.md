# Domain Error Strategy - Agent Integration

> **Skill:** m13-domain-error
> **Agent:** resilience-engineer

## Quick Reference

This skill handles domain error categorization and recovery strategies. It uses the resilience-engineer agent for comprehensive resilience design.

## When to Use Agent

Use the agent when:
- Categorizing errors by audience
- Designing error hierarchies
- Implementing retry strategies
- Building circuit breakers
- Creating fallback patterns
- Designing graceful degradation

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/resilience-engineer.md>
)
```

## Error Categories

The agent helps with:
- **User-facing**: Actionable error messages
- **Internal**: Developer debugging info
- **System**: Operations monitoring
- **Transient**: Retry strategies
- **Permanent**: Fail-fast patterns

## Success Criteria

Agent invocation is successful when:
1. Errors categorized appropriately
2. Recovery strategies implemented
3. Actionable feedback provided
4. System stability maintained
5. Observability enabled
6. Edge cases handled
