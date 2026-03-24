---
allowed-tools: AskUserQuestion, Read, Glob, Grep, LSP, Agent, Write, Edit, Bash(mkdir *), Bash(cargo check *), Bash(maturin *), Bash(pytest *)
description: |
  Guided feature planning with iterative user input. Gathers requirements, validates assumptions against the codebase, proposes a solution, and optionally scaffolds or implements it.
  TRIGGER when: user wants to plan, design, architect, or think through a feature before coding. Keywords: "plan", "make a plan", "design", "architect", "think through", "figure out how to", "how should we", "what's the best way to".
  DO NOT TRIGGER when: user is asking a simple question, wants a direct code change, or is debugging an existing issue without needing a design phase.
user-invocable: true
arguments:
  - name: goal
    description: "Optional high-level goal to skip the first prompt. If not provided, the skill will ask."
    default: ""
---

# Feature Planning

Interactive planning workflow that gathers requirements, validates assumptions, and proposes a solution before any code
is written.

## Phase 1: Gather Requirements

Collect the plan proposal from the user. If the `goal` argument was provided, use it and skip the first question.

Ask the user the following questions **one at a time** using `AskUserQuestion`. After each answer, acknowledge it
briefly before asking the next question. **Stop and wait for the user's reply after each question.** Do not ask
multiple questions in one message.

1. **High-level goal** — "What is the high-level goal of this feature or change?"
2. **Essential requirements** — "What are the essential requirements? (things that must be true for this to be done)"
3. **Considerations** (optional) — "Anything specific to consider? (existing patterns, performance constraints,
   compatibility, etc. — say 'skip' if none)"
4. **Things to avoid** (optional) — "Anything to explicitly avoid? (approaches, dependencies, patterns, etc. — say '
   skip' if none)"

For questions 3-4, accept "skip" or "none" as valid answers and move on.

After collecting all answers, summarize the proposal back to the user in a compact format:

```
**Goal:** ...
**Must have:** ...
**Consider:** ...
**Avoid:** ...
```

Ask the user to confirm the proposal is correct before proceeding.

## Phase 2: Research and Assumptions

Read the codebase documentation to understand the problem space:

1. Read `.claude/CODEBASE.md` and any linked docs relevant to the goal.
2. Use LSP (`documentSymbol`, `goToDefinition`, `findReferences`, `workspaceSymbol`) for Rust/TS code exploration.
   Fall back to Glob/Grep/Read for docs, config files, and when LSP is unavailable.
3. Identify the modules, traits, and types involved.

Then list your **assumptions** — things you believe to be true based on your research that affect the solution design.
Present these to the user as a numbered list and ask them to confirm, correct, or add to them using `AskUserQuestion`
with options like "Confirmed", "Need corrections" (user types details), "Add more assumptions".

Example format:
> Based on my research, here are my assumptions:
> 1. This change affects `tycho-indexer/src/services/rpc.rs` and `tycho-common/src/dto.rs`
> 2. The `ExtractionGateway` trait doesn't need to change
> 3. ...
>
> Are these correct? Anything to add or fix?

Do not proceed until the user confirms.

## Phase 3: Propose Solution

With confirmed assumptions, propose a high-level solution. The proposal must include:

- **Approach** — 2-3 sentence summary of the solution
- **Files to modify** — list each file with a one-line description of the change
- **New files** (if any) — list each with purpose
- **Key design decisions** — any non-obvious choices and why

Present the proposal and ask the user to choose using `AskUserQuestion` (this is the one structured choice point):

1. **Accept and implement** — proceed to full implementation
2. **Accept and scaffold (auto-accept changes)** — create the structure with placeholder logic (Phase 4a)
3. **Reject** — user explains what's wrong, loop back to Phase 3

If rejected, incorporate the user's feedback, revise the proposal, and present again. If any different input is given,
process it and loop back to step 3.

## Phase 4a: Scaffold (if chosen)

Spawn a subagent using the Agent tool to perform the scaffolding. Pass it the full plan context (goal, requirements,
assumptions, proposed solution, and file list) so it has everything it needs.

**Subagent prompt must include these instructions:**

> You are scaffolding a feature. Create only structural changes — no business logic.
>
> Required changes:
> - New files with module declarations and imports
> - Empty or stub function/method signatures with `todo!()` bodies
> - New struct/enum definitions with fields
> - Trait implementations with `todo!()` bodies
> - Required `mod` declarations and `use` statements
> - Imports and calls to new scaffolded code, the user wants to see how it is connected to the existing codebase.
> - All structs and fields should be documented briefly so the user knows their intended purpose
> - Unit tests calling the public API of the new code with actual assertions based on user requirements. These tests
    should be market with #[ignore].
>
> Rules:
> - No business logic — use `todo!()` for function bodies
> - Add a brief comment above each `todo!()` describing what it should do
> - Make sure the scaffolded code is "connected", that it is called in controllers or factories.
> - After all changes, run `cargo check --workspace --all-features` to verify the code compiles
> - If `cargo check` fails, read the errors, fix them, and run `cargo check` again
> - Repeat until `cargo check` passes
> - Report back: files created/modified, and the final `cargo check` result

After the subagent completes, report the results to the user and tell them the scaffold is ready for review. Do NOT
proceed to implementation automatically.

## Phase 4b: Implement (if chosen)

1. Save the full plan to `.claude/plans/<name>.md` where `<name>` is a kebab-case slug derived from the goal.
   Include all gathered context: goal, requirements, assumptions, proposed solution, and files list.

2. Load the relevant knowledge documents for the implementation:
    - Rust: `.claude/knowledge/rust.md`
    - Python (tycho-client-py): `.claude/knowledge/python.md`

3. Implement the solution file by file. After completing all changes, run a quick validation:
    - `cargo check --workspace` for Rust changes
    - `maturin develop` + `pytest` for Python binding changes

4. Report what was implemented and any remaining work.

---

## Planning guidelines

- **No speculative features** — Don't add features, flags, or configuration unless actively needed.
- **No premature abstraction** — Don't create utilities until you've written the same code three times.
- **Clarity over cleverness** — Prefer explicit, readable code over dense one-liners.
- **Justify new dependencies** — Each dependency is attack surface and maintenance burden.
- **Finish the job** — Handle edge cases you can see. Clean up what you touched. Flag broken adjacent code. But don't
  invent new scope.