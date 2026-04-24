# Workflow Directives for CLAUDE

When responding to user input, always log this information to the user which knowledge docs you have read. Only say yes
if you actually read them. Respond like this:

> Knowledge docs: Rust: [yes/no], Python: [yes/no], Version-control: [yes/no], Solidity: [yes/no]
> Files loaded in context: [list of loaded documents]

By default, don't use the Explore agent as a first step in a conversation. The first step should always be to identify
and read the relevant documentation files.

Everytime a developer asks something new, you should check the list of available knowledge and inform
the user about it. If the user asks a question that requires exploring the project, always
check [.claude/CODEBASE.md](.claude/CODEBASE.md) and all the related linked documents first. Only go through files when
you've exhausted the path of documentation.

## Knowledge Documents

**MANDATORY**: Before responding to any input, scan this table for trigger matches. If ANY trigger matches, you MUST
`Read` the document BEFORE doing anything else. Tell the user which documents you loaded.

| Document        | Trigger                                                                 | Path                                   |
|-----------------|-------------------------------------------------------------------------|----------------------------------------|
| Rust            | Writing, reviewing, or debugging Rust code                              | `.claude/knowledge/rust.md`            |
| Version control | git, branch, commit, PR, push, rebase, merge, cherry-pick, tag, release | `.claude/knowledge/version_control.md` |
| Python          | Python code, tycho-client-py, changes to dto.rs or rpc.rs              | `.claude/knowledge/python.md`          |
| Solidity        | Solidity contracts, Foundry, forge, executors, tycho-execution          | `.claude/knowledge/solidity.md`        |

When spawning subagents, pass the relevant knowledge document contents to them.

## Skills

- `plan`: Guided feature planning with iterative user input. Gathers requirements, validates assumptions, proposes a
  solution. **Always use this skill** when the user wants to plan, design, or architect a feature before coding. Trigger
  words: "plan", "design", "architect", "think through", "figure out how to".
- `run-ci`: Run all CI checks. Optionally DB and node RPC dependent checks.
- `sync-docs`: Review all codebase documentation