# Propeller Builder

A builder written in Rust aware of protocol logic.

## Documentation

- [Architecture charts](https://drive.google.com/file/d/1p4HgglAWowNByYQxf44EEdJ9Cc1RNCaT/view?usp=sharing)

### Local development
1. Please also make sure that the following commands pass if you have changed the code:

```sh
cargo check --all
cargo test --all --all-features
cargo +nightly fmt -- --check
cargo +nightly clippy --workspace --all-features --all-targets -- -D warnings
```

We are using the stable toolchain for building and testing, but the nightly toolchain for formatting and linting, as it allows us to use the latest features of rustfmt and clippy.

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
