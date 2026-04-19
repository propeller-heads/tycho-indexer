#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Compare per-test gas between two branches.

Runs `forge test --gas-report --json --match-test <testName>` for each
test in test_metadata.json, extracting the exact gas for the router
function called by that test. No setUp or test body overhead.

Usage:
    # Full auto: run on both branches and compare
    python3 gas_compare.py --foundry-dir ./crates/tycho-execution/contracts \
        --metadata crates/tycho-execution/.gas-compare/test_metadata.json

    # Compare pre-saved per-test results
    python3 gas_compare.py \
        --current crates/tycho-execution/.gas-compare/branch.json \
        --base crates/tycho-execution/.gas-compare/main.json \
        --metadata crates/tycho-execution/.gas-compare/test_metadata.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


def find_repo_root(start_dir):
    """Walk up to find the git repo root."""
    d = Path(start_dir).resolve()
    while d != d.parent:
        if (d / ".git").exists():
            return str(d)
        d = d.parent
    return None


def load_dotenv(foundry_dir):
    """Load .env file from foundry dir into environment."""
    env_file = Path(foundry_dir) / ".env"
    if not env_file.exists():
        return
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value
                    print(
                        f"  Loaded {key} from .env",
                        file=sys.stderr,
                    )


def check_rpc(foundry_dir):
    """Ensure RPC_URL is set."""
    load_dotenv(foundry_dir)
    if not os.environ.get("RPC_URL"):
        print(
            "ERROR: RPC_URL not set. Add to "
            "crates/tycho-execution/contracts/.env "
            "or export RPC_URL=https://...",
            file=sys.stderr,
        )
        sys.exit(1)


def run_single_test_gas(foundry_dir, test_name, router_fn):
    """Run gas-report for one test, return router function gas.

    Returns the mean gas for the target router function,
    or None if the test failed or function wasn't found.
    """
    cmd = [
        "forge",
        "test",
        "--gas-report",
        "--json",
        "--match-test",
        test_name,
        "--match-path",
        "test/TychoRouter*",
    ]

    result = subprocess.run(
        cmd,
        cwd=foundry_dir,
        capture_output=True,
        text=True,
        timeout=180,
    )

    stdout = result.stdout.strip()
    idx = stdout.find("[")
    if idx < 0:
        return None

    try:
        data = json.loads(stdout[idx:])
    except json.JSONDecodeError:
        return None

    for item in data:
        for sig, stats in item.get("functions", {}).items():
            fname = sig.split("(")[0]
            if fname == router_fn:
                return stats["mean"]

    return None


def collect_gas(foundry_dir, metadata):
    """Run all tests one-by-one, return {test_name: gas}."""
    check_rpc(foundry_dir)

    tests = [
        t for t in metadata["tests"] if not t.get("skipped")
    ]
    results = {}

    for i, test in enumerate(tests):
        name = test["test"]
        func = test["router_function"]
        print(
            f"  [{i + 1}/{len(tests)}] {name}...",
            file=sys.stderr,
            end=" ",
            flush=True,
        )

        gas = run_single_test_gas(foundry_dir, name, func)
        if gas is not None:
            results[name] = gas
            print(f"{gas:,}", file=sys.stderr)
        else:
            print("FAILED", file=sys.stderr)

    return results


def collect_gas_on_base(
    repo_dir, foundry_rel, branch, metadata
):
    """Run tests on base branch using git worktree."""
    # Load env from main repo first — worktree won't have
    # .env (gitignored)
    main_foundry = os.path.join(repo_dir, foundry_rel)
    load_dotenv(main_foundry)

    with tempfile.TemporaryDirectory(
        prefix="gas-compare-"
    ) as tmpdir:
        worktree_path = os.path.join(tmpdir, "base")
        print(
            f"  Creating worktree for '{branch}'...",
            file=sys.stderr,
        )

        result = subprocess.run(
            ["git", "worktree", "add", worktree_path, branch],
            cwd=repo_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(
                f"  Failed to create worktree: "
                f"{result.stderr}",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            print(
                "  Initializing submodules...",
                file=sys.stderr,
            )
            subprocess.run(
                [
                    "git",
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                ],
                cwd=worktree_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            wt_foundry = os.path.join(
                worktree_path, foundry_rel
            )
            return collect_gas(wt_foundry, metadata)
        finally:
            print(
                "  Cleaning up worktree...", file=sys.stderr
            )
            subprocess.run(
                [
                    "git",
                    "worktree",
                    "remove",
                    worktree_path,
                    "--force",
                ],
                cwd=repo_dir,
                capture_output=True,
            )


def format_gas(gas):
    """Format gas with thousands separator."""
    if gas is None:
        return "N/A"
    return f"{gas:,}"


def diff_str(base, curr):
    """Format a gas diff value."""
    if base is not None and curr is not None:
        return f"{curr - base:+,}"
    if base is None:
        return "NEW"
    if curr is None:
        return "REMOVED"
    return "N/A"


def generate_report(
    base_gas, current_gas, metadata, base_label, curr_label
):
    """Generate per-test comparison with summary."""
    lines = []
    lines.append(
        f"# Gas Comparison: `{curr_label}` vs "
        f"`{base_label}`\n"
    )

    tests = [
        t for t in metadata["tests"] if not t.get("skipped")
    ]

    # ── Summary: mean per router function ──────────────
    func_gas = defaultdict(
        lambda: {"base": [], "current": []}
    )
    for test in tests:
        name = test["test"]
        func = test["router_function"]
        if name in base_gas:
            func_gas[func]["base"].append(base_gas[name])
        if name in current_gas:
            func_gas[func]["current"].append(
                current_gas[name]
            )

    lines.append("## Summary (mean per router function)\n")
    lines.append(
        "| Function | Main (mean) | Branch (mean) | Diff |"
    )
    lines.append("|---|---:|---:|---:|")

    for func in sorted(func_gas.keys()):
        data = func_gas[func]
        base_mean = (
            sum(data["base"]) // len(data["base"])
            if data["base"]
            else None
        )
        curr_mean = (
            sum(data["current"]) // len(data["current"])
            if data["current"]
            else None
        )
        lines.append(
            f"| {func} | {format_gas(base_mean)} "
            f"| {format_gas(curr_mean)} "
            f"| {diff_str(base_mean, curr_mean)} |"
        )
    lines.append("")

    # ── Per-file tables ────────────────────────────────
    files_order = []
    tests_by_file = defaultdict(list)
    for test in tests:
        f = test["file"]
        if f not in files_order:
            files_order.append(f)
        tests_by_file[f].append(test)

    for f in files_order:
        lines.append(f"### {f}\n")
        lines.append(
            "| Test | Router Function | Protocols "
            "| Swaps | Main | Branch | Diff |"
        )
        lines.append("|---|---|---|---:|---:|---:|---:|")

        for test in sorted(
            tests_by_file[f], key=lambda t: t["test"]
        ):
            name = test["test"]
            func = test["router_function"]
            protocols = ", ".join(test.get("protocols", []))
            num_swaps = test.get("num_swaps", "?")
            base = base_gas.get(name)
            curr = current_gas.get(name)

            lines.append(
                f"| {name} | {func} | {protocols} "
                f"| {num_swaps} "
                f"| {format_gas(base)} "
                f"| {format_gas(curr)} "
                f"| {diff_str(base, curr)} |"
            )
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Compare per-test gas between branches"
    )
    parser.add_argument(
        "--foundry-dir",
        help="Path to foundry project (auto-detected)",
    )
    parser.add_argument(
        "--base-branch",
        default="main",
        help="Base branch (default: main)",
    )
    parser.add_argument(
        "--current",
        help="Pre-saved per-test gas JSON for current branch",
    )
    parser.add_argument(
        "--base",
        help="Pre-saved per-test gas JSON for base branch",
    )
    parser.add_argument(
        "--metadata",
        help="Path to test_metadata.json",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--save-json",
        help="Directory to save per-test gas results",
    )
    args = parser.parse_args()

    # ── Locate metadata ────────────────────────────────
    metadata_path = (
        args.metadata
        or "crates/tycho-execution/.gas-compare/test_metadata.json"
    )
    if not Path(metadata_path).exists():
        print(
            f"ERROR: {metadata_path} not found. "
            "Run /update-gas-test-metadata first.",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(metadata_path) as f:
        metadata = json.load(f)

    def resolve_foundry_dir():
        if args.foundry_dir:
            return os.path.abspath(args.foundry_dir)
        cwd = os.getcwd()
        if Path(cwd, "foundry.toml").exists():
            return cwd
        candidate = Path(
            cwd, "crates/tycho-execution/contracts"
        )
        if (candidate / "foundry.toml").exists():
            return str(candidate)
        if Path(cwd, "foundry", "foundry.toml").exists():
            return os.path.join(cwd, "foundry")
        print(
            "Could not auto-detect foundry dir. "
            "Use --foundry-dir.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Load or run current branch ─────────────────────
    if args.current:
        print(
            f"Loading current branch from {args.current}",
            file=sys.stderr,
        )
        with open(args.current) as f:
            current_gas = json.load(f)
        curr_label = Path(args.current).stem
    else:
        foundry_dir = resolve_foundry_dir()
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            cwd=foundry_dir,
        )
        curr_label = result.stdout.strip() or "HEAD"
        print(
            f"Running tests on current branch "
            f"({curr_label})...",
            file=sys.stderr,
        )
        current_gas = collect_gas(foundry_dir, metadata)

        if args.save_json:
            os.makedirs(args.save_json, exist_ok=True)
            safe = curr_label.replace("/", "_")
            path = os.path.join(args.save_json, f"{safe}.json")
            with open(path, "w") as f:
                json.dump(current_gas, f, indent=2)
            print(f"  Saved to {path}", file=sys.stderr)

    # ── Load or run base branch ────────────────────────
    if args.base:
        print(
            f"Loading base branch from {args.base}",
            file=sys.stderr,
        )
        with open(args.base) as f:
            base_gas = json.load(f)
        base_label = Path(args.base).stem
    else:
        foundry_dir = resolve_foundry_dir()
        repo_dir = find_repo_root(foundry_dir)
        if not repo_dir:
            print(
                "Could not find git repo root.",
                file=sys.stderr,
            )
            sys.exit(1)
        foundry_rel = os.path.relpath(foundry_dir, repo_dir)
        base_label = args.base_branch
        print(
            f"Running tests on base branch "
            f"({base_label})...",
            file=sys.stderr,
        )
        base_gas = collect_gas_on_base(
            repo_dir, foundry_rel, base_label, metadata
        )

        if args.save_json:
            os.makedirs(args.save_json, exist_ok=True)
            safe = base_label.replace("/", "_")
            path = os.path.join(args.save_json, f"{safe}.json")
            with open(path, "w") as f:
                json.dump(base_gas, f, indent=2)
            print(f"  Saved to {path}", file=sys.stderr)

    # ── Generate report ────────────────────────────────
    print("Generating report...", file=sys.stderr)
    report = generate_report(
        base_gas, current_gas, metadata, base_label, curr_label
    )

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(
            f"Report written to {args.output}",
            file=sys.stderr,
        )
    else:
        print(report)


if __name__ == "__main__":
    main()
