# Ownership & Lifetimes - Agent Integration

> **Skill:** m01-ownership
> **Agent:** ownership-analyzer

## Quick Reference

This skill handles ownership, borrowing, and lifetime issues in Rust. When complex ownership problems arise, it can delegate to the ownership-analyzer agent for deep analysis.

## When to Use Agent

Use the agent when:
- Ownership errors persist after 2-3 fix attempts
- Complex lifetime relationships need analysis
- Design-level ownership decisions are needed
- Multiple interrelated ownership issues exist

## Agent Invocation

```
Task(
  subagent_type: "general-purpose",
  run_in_background: true,
  prompt: <read from ../../agents/ownership-analyzer.md>
)
```

## Error Code → Agent Mapping

| Error Code | Description | Agent Helps With |
|------------|-------------|------------------|
| E0382 | Value moved | Ownership design analysis |
| E0597 | Borrow outlives owner | Lifetime relationship analysis |
| E0506 | Cannot assign while borrowed | Aliasing violation resolution |
| E0507 | Cannot move out of borrowed | Reference vs ownership design |
| E0515 | Cannot return local reference | Lifetime scope analysis |
| E0716 | Temporary value dropped | Scope boundary analysis |
| E0106 | Missing lifetime parameter | Lifetime annotation guidance |

## Workflow

### Inline Mode (No Agent)
1. Identify error code
2. Apply quick fix from skill reference
3. Validate with compiler

### Agent Mode (Complex Issues)
1. Identify persistent or complex issue
2. Invoke ownership-analyzer agent
3. Agent performs deep analysis
4. Agent suggests design-level solutions
5. Apply recommended changes
6. Validate with compiler

## Example: Strike 3 Escalation

```
Attempt 1: Add .clone()
    ↓ Still errors
Attempt 2: Change to reference
    ↓ Still errors
Attempt 3: Invoke agent
    ↓
Agent analyzes design
    ↓
Agent suggests Arc<T> for shared ownership
    ↓
Apply solution
    ↓
Success!
```

## Agent Output Format

The agent provides:
- **Problem Analysis**: What's wrong and why
- **Root Cause**: Design issue vs implementation issue
- **Recommended Fix**: Code changes with explanation
- **Trade-offs**: Pros and cons of approach
- **Alternatives**: Other possible solutions

## Related Agents

- **error-handling-expert**: For Result/Option lifetime issues
- **concurrency-expert**: For Send/Sync ownership issues
- **refactor-assistant**: For ownership-related refactoring

## Success Criteria

Agent invocation is successful when:
1. Root cause is identified (not just symptoms)
2. Fix aligns with design intent
3. Trade-offs are clearly explained
4. Code compiles and tests pass
5. Solution is maintainable
