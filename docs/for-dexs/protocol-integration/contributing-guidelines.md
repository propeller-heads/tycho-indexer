# Contributing guidelines

## Local Development

### Changing Rust Code

Please make sure that the following commands pass if you have changed the code:

```sh
cargo check --all
cargo test --all --all-features
cargo +nightly fmt -- --check
cargo +nightly clippy --workspace --all-features --all-targets -- -D warnings
```

We are using the stable toolchain for building and testing, but the nightly toolchain for formatting and linting, as it allows us to use the latest features of `rustfmt` and `clippy`.

If you are working in VSCode, we recommend you install the [rust-analyzer](https://rust-analyzer.github.io/) extension, and use the following VSCode user settings:

```json
"editor.formatOnSave": true,
"rust-analyzer.rustfmt.extraArgs": ["+nightly"],
"rust-analyzer.check.overrideCommand": [
"cargo",
"+nightly",
"clippy",
"--workspace",
"--all-features",
"--all-targets",
"--message-format=json"
],
"[rust]": {
"editor.defaultFormatter": "rust-lang.rust-analyzer"
}
```

### Changing Solidity code

#### Setup <a href="#setup" id="setup"></a>

Install foudryup and foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

#### Running tests <a href="#running-tests" id="running-tests"></a>

```bash
export ETH_RPC_URL=<url>
forge test
```

#### Code formatting <a href="#code-formatting" id="code-formatting"></a>

```bash
forge fmt
```

#### Assembly

Please **minimize** use of assembly for security reasons.

#### Contract Analysis

We use [Slither](https://github.com/crytic/slither) to detect any potential vulnerabilities in our contracts.

To run locally, simply install Slither in your conda env and run it inside the foundry directory.

```bash
conda create --name tycho-execution python=3.10
conda activate tycho-execution

pip install slither-analyzer
cd foundry
slither .
```

## Creating a Pull Request

We use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) as our convention for formatting commit messages and PR titles.
