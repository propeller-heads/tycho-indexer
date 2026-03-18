---
allowed-tools: Bash(cargo:*), Bash(diesel:*), Bash(psql:*), Bash(bash .claude/scripts/run-nextest.sh:*), Bash(printenv:*), Bash(git diff:*), Bash(git branch:*), Bash(git status:*), Read
description: "Run the full CI pipeline locally to catch failures before pushing. Use this skill before creating a PR, before pushing commits, or whenever you want to verify that CI will pass. Also use it when the user says 'run ci', 'check ci', 'run tests', 'lint', or 'will ci pass'."
user-invocable: true
---

# Run CI Locally

Run the same checks that GitHub Actions CI runs, locally, to catch failures before they hit the
remote pipeline. The canonical commands live in `.github/workflows/ci.yaml`.

## Environment

Environment variables needed for DB tests can be configured in `.claude/settings.local.json`:

```json
{
  "env": {
    "DATABASE_URL": "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0"
  }
}
```

DB tests require both `DATABASE_URL` set AND a running Postgres instance (see
`tycho-storage/README.md` for setup). Tests marked `#[ignore]` require `RPC_URL` pointing to an
archive node — these are always skipped.

## Context

- Current branch: !`git branch --show-current`
- Working tree status: !`git status --short`

## Workflow

### Phase 0: Check database availability and run migrations

Check that `DATABASE_URL` is set:

```bash
printenv DATABASE_URL
```

If the command fails (exit code 1), `DATABASE_URL` is not set. Mark DB as unavailable:
- All `serial_db` tests will be **skipped**
- Unit tests will exclude `tycho-storage` and `diesel` tests
- Set a `DB_SKIPPED` flag for the final report

If `DATABASE_URL` IS set, run migrations to ensure the schema is up to date:

```bash
diesel migration run --migration-dir ./tycho-storage/migrations
```

If migrations fail with "already exists" errors (stale schema), reset the database:

```bash
diesel database reset --migration-dir ./tycho-storage/migrations
```

If the reset fails because other connections are active, terminate them first using `psql` then
retry the reset. If migrations still fail after reset (e.g. Postgres not running), mark DB as
unavailable with the same behavior as above.

### Phase 1: Format (sequential)

Run formatting first because it modifies source files that all subsequent checks depend on.

```bash
cargo +nightly fmt --all
```

Check `git diff --stat -- '*.rs'` and report whether any files were reformatted.

### Phase 2: Clippy (sequential, gate for tests)

Run clippy next. If clippy fails, tests won't compile either, so there's no point running them.

```bash
cargo clippy --workspace --all-targets --all-features
```

Report pass/fail. If there are warnings or errors, list them.

**If clippy fails, stop here.** Report the errors and skip Phase 3.

### Phase 3: Parallel test checks

Only run this phase if clippy passed. Launch all test commands as **parallel foreground Bash calls
in a single message**. Do NOT use `run_in_background` — multiple Bash tool calls in one message
already execute concurrently.

**IMPORTANT**: Do NOT use `cargo nextest run` with `-E` / `--filter-expr` directly — the
parentheses in filter expressions break allowed-tools pattern matching and trigger permission
prompts. Use the wrapper script `.claude/scripts/run-nextest.sh` instead, which encapsulates
the filter expressions. Also do NOT pipe commands through `grep`, `tail`, or other commands.

#### Unit tests (parallel)

If DB is available:
```bash
bash .claude/scripts/run-nextest.sh unit
```

If DB is NOT available (exclude tycho-storage and diesel round-trip tests):
```bash
bash .claude/scripts/run-nextest.sh no-db
```

Report pass/fail with test count summary (passed, failed, ignored).

#### DB tests (serial) — only if DB is available

```bash
bash .claude/scripts/run-nextest.sh serial-db
```

Report pass/fail with test count summary. If DB is not available, skip entirely.

## Report

After all steps complete, provide a summary table. Combine results from both test runs (unit +
serial-db) to compute totals. Only report a test as "skipped" if it was genuinely not run at all
(e.g. DB unavailable, clippy failed). Do NOT count nextest filter exclusions as skipped — those
tests run in the other phase.

**How to compute the totals:**
- `passed` = unit passed + serial-db passed
- `failed` = unit failed + serial-db failed
- `ignored` = the `#[ignore]`-d count from nextest (tests requiring `RPC_URL` archive node)
- `skipped` = only tests that were NOT run in ANY phase (e.g. DB tests when DB is unavailable)

| Step     | Status            | Details                                    |
|----------|-------------------|--------------------------------------------|
| Format   | pass/fail         | files reformatted or clean                 |
| Clippy   | pass/fail         | warning/error count                        |
| Tests    | pass/fail/skipped | X passed, Y failed, Z ignored (need RPC_URL) |

If clippy failed, mark tests as "skipped (clippy failed)".

**If DB was not available**, add a warning above the table:

```
WARNING: DATABASE NOT AVAILABLE — serial_db, tycho-storage, and diesel round-trip tests were skipped.
```

Add a "skipped" count for the DB-dependent tests and tell the user how to enable them:

```
To run the full suite including DB tests:

1. Start Postgres:  docker-compose up -d db
2. Set DATABASE_URL (pick one):
   a) Per-session:    export DATABASE_URL="postgres://postgres:mypassword@localhost:5431/tycho_indexer_0"
   b) Persistent:     Add to .claude/settings.local.json:
                      { "env": { "DATABASE_URL": "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0" } }
3. Run migrations:  diesel migration run --migration-dir ./tycho-storage/migrations
4. Re-run:          /run-ci
```

If any step failed, list the specific errors below the table.
