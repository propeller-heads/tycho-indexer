# Coding in Solidity (Foundry)

## Commands

During development, from `crates/tycho-execution/contracts/`:

```bash
forge build                      # compile
forge test -vvv                  # run all tests (requires RPC_URL + BASE_RPC_URL)
forge test -vvv --match-test foo # run a single test
forge fmt                        # auto-format
forge fmt --check                # format check (CI)
forge snapshot                   # update gas snapshots
```

Static analysis:

```bash
slither .                        # run from contracts/
```

After a task is done, run the `/run-ci` skill. It runs the Foundry CI checks matching what
`.github/workflows/ci-rust.yaml` does.

## Coding Style

### Naming

- Private/internal state variables prefixed with underscore: `_feeCalculator`, `_ALLOWED_DUST`
- Custom errors are contract-prefixed: `TychoRouter__EmptySwaps`, `Vault__AmountZero`
- Transient storage slot constants use `keccak256` of a descriptive name string

### Formatting

- `forge fmt` enforced in CI; line length 80 chars
- Suppress Slither false positives with `// slither-disable-next-line` and a comment

### Executor conventions

When adding an executor, hardcode `TransferType`, `tokenOut`, and `outputToRouter` in
`getTransferData()` — do not make them encodable. Set `outputToRouter = true` if the protocol
sends output to `msg.sender` rather than accepting a receiver param.

`swap()` returns void and must not contain balance tracking, output transfers, or amount
validation — the Dispatcher handles all of this via balance-diff. **Never use pool return
values or callback arguments to determine transfer amounts.**

## Testing

- All tests inherit from `TychoRouterTestSetup.sol`
- Test naming: `test<Description>` in Solidity
- Fork tests require `RPC_URL` (Ethereum mainnet) and `BASE_RPC_URL` env vars

### Cross-language integration tests

Rust encoding tests call `write_calldata_to_file(test_identifier, hex_calldata)`, which appends
`name:hex` lines to `contracts/test/assets/calldata.txt`. Solidity tests read that file via
`loadCallDataFromFile(testName)` and execute the calldata against a mainnet fork. This verifies
Rust-encoded calldata end-to-end.

## Project Config

- EVM target: Cancun; `via_ir` enabled; optimizer 200 runs (default), 1000 runs (production)
- Solidity dependencies managed as git submodules under `contracts/lib/` — always clone with
  `--recursive`
