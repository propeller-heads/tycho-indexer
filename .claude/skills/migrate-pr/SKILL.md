---
allowed-tools: Bash(./scripts/migrate-pr.sh:*), Bash(git am:*), Bash(git checkout:*), Bash(git branch:*), Bash(git log:*), Bash(git status:*), Bash(git add:*), Bash(git commit:*), Bash(git push:*), Bash(gh pr view:*), Bash(find:*), Bash(wiggle:*), Bash(brew install wiggle:*), Bash(cp:*), Bash(cargo check --workspace:*), Read, Edit
description: "Migrate an open PR from a related repository (tycho-protocol-sdk, tycho-simulation, tycho-execution) into this monorepo. Rewrites paths, strips unmapped diffs, and handles conflicts. Use when the user says 'migrate PR', 'port PR', or 'bring over PR from <repo>'."
user-invocable: true
---

# Migrate a PR into the Monorepo

Migrate an open PR from a related repository into this monorepo by rewriting paths, stripping
unmapped diffs, and applying patches.

## Context

- Current branch: !`git branch --show-current`
- Working tree: !`git status --short`

## Phase 1 — Gather information

If the user provided a PR URL or number, fetch the branch name and affected files:

```bash
gh pr view <number-or-url> --repo propeller-heads/<source-repo> --json headRefName,files,title
```

Confirm with the user:
- Which local path holds the source repo (e.g. `../tycho-protocol-sdk`)
- Whether the commits are still on an open branch, or already merged into the source repo's `main`

**If already merged into main**, find the merge commit and use a range instead of a branch name:

```bash
cd <source-repo>
git fetch origin
git log --oneline --merges origin/main | grep -i "<pr-title-or-number>"
# note the merge commit hash, e.g. b865ff1a
```

Pass `<merge>^1..<merge>^2` as the branch argument in Phase 2. The script will stay on
the current branch and apply the commits directly.

**If still on an open branch**, confirm it is rebased onto the source repo's `main`:

```
cd <source-repo>
git fetch origin
git rebase origin/main <branch>
# resolve conflicts, git rebase --continue
```

## Phase 2 — Run the migration script

The script auto-detects path mappings from the repo name:

```bash
# Open branch:
./scripts/migrate-pr.sh <source-repo-path> <branch-name>
# Already-merged PR (use merge commit parents as range):
./scripts/migrate-pr.sh <source-repo-path> <merge-commit>^1..<merge-commit>^2
```

Known mappings applied automatically:

| Source repo | Path mapping |
|---|---|
| `tycho-protocol-sdk` | `substreams→protocols/substreams`, `evm→protocols/adapter-integration/evm`, `protocol-testing→protocols/testing` |
| `tycho-simulation` | `tycho-integration-test→crates/tycho-integration-test`, `tycho-test→crates/tycho-test`, everything else → `crates/tycho-simulation/` |
| `tycho-execution` | everything → `crates/tycho-execution/` |

The script will:
1. Export commits from the source branch
2. Rewrite all diff paths to match the monorepo layout
3. Strip `.github/workflows/` and `Cargo.lock` diffs automatically
4. Apply patches with `git am`
5. On failure: retry with `--reject` to preserve partial application

## Phase 3 — Verify clean application

If the script exits 0, check the result:

```bash
git log --oneline <branch> ^main
git status --short
```

Then regenerate `Cargo.lock` (always needed after migration):

```bash
cargo check --workspace
git add protocols/substreams/Cargo.lock  # or whichever workspace was affected
git commit --amend --no-edit
```

## Phase 4 — Manual fixups

Some things the script cannot automate. Check for these after applying:

**Check `protocols/testing/src/state_registry.rs`**: if the PR registers a new decoder,
the imports and match arms may need adapting to what is already imported in the monorepo.
Read the file and compare with the `.rej` or patch diff.

---

## Conflict Resolution

### How `git am` handles multiple patches

`git am` applies patches one at a time in order. When a patch fails, it **stops at that
patch** — all previously applied patches are already committed and safe. Only the failing
patch is in a pending state. The workflow is:

1. Resolve the failure for the current patch
2. `git add` the resolved files
3. `git am --continue` — commits the current patch and moves to the **next** one
4. Repeat until all patches are applied

`--continue` does NOT re-apply already-committed patches. It resumes exactly where the
failure happened. If three patches were queued and patch 2 failed, `--continue` after
resolving patch 2 will proceed to patch 3.

---

### Step 1 — Understand what failed

When the script exits non-zero, check which patch failed and what it touched:

```bash
git am --show-current-patch=diff   # shows the failing patch in full
find . -name '*.rej'               # lists files with unapplied hunks
git log --oneline HEAD ^main       # shows commits already applied successfully
```

### Step 2 — Install wiggle (if needed)

```bash
brew install wiggle
```

`wiggle` applies `.rej` files using word-level diffing. Where it can't resolve automatically,
it inserts standard `<<<<<<<`/`=======`/`>>>>>>>` conflict markers — the same format as a
normal git merge conflict.

### Step 3 — Apply all .rej files

```bash
find . -name '*.rej' | while read -r rej; do
  target="${rej%.rej}"
  echo "Applying: $rej → $target"
  wiggle --merge "$target" "$rej" && rm "$rej"
done
```

`wiggle` exits 0 when it resolves cleanly, non-zero when conflict markers were inserted.
Either way, the file is modified in-place.

### Step 4 — Resolve conflict markers

Find files that still have conflict markers:

```bash
git diff --check
```

For each conflict:
- `<<<<<<< PATCH` — what the patch wanted to insert
- `=======` — boundary
- `>>>>>>> CURRENT` — what is currently in the file

Decide which to keep, or write a merged version by hand.

### Step 5 — Continue to the next patch

```bash
git add <all-resolved-files>
git am --continue      # commits this patch, then moves to the next one
```

Repeat steps 1–5 for each failing patch. `git am` will stop again for each one that needs
resolution.

### Other options

Skip a patch entirely (e.g. a CI change that doesn't belong here):

```bash
git am --skip
```

Abort the entire migration and start over from scratch:

```bash
git am --abort         # resets branch to before any patches were applied
git checkout main
git branch -D <branch>
```

### Common conflict causes

| File | Why it conflicts | Fix |
|---|---|---|
| `Cargo.toml` | Dep versions diverged between repos | Keep monorepo's workspace dep; add only new deps from the patch |
| `state_registry.rs` | Monorepo has different imports than source | Add only the new protocol import and match arm |
| `execution.rs` | Monorepo uses `../fixtures/` paths, source uses `../../evm/test/executors/` | Use `../fixtures/` path; copy the JSON file |
| Any `Cargo.lock` | Always diverges | Never migrate; regenerate with `cargo check --workspace` |

## Phase 5 — Finish

```bash
cargo check --workspace   # ensure it compiles and Cargo.lock is up to date
git push origin <branch>
```

Then open a PR against this repo and close the original PR with a link to it.
