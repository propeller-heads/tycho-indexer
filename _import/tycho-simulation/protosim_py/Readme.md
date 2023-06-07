# Python bindings for Protosim EVM Simulation

`protosim_py` - a Python module, implemented as a Rust crate, that allows using Rust EVM simulation module from Python.

## Summary

`evm_simulation` module from `protosim` crate implements simulating on-chain transactions. This crate - `protosim_py` - wraps `evm_simulation` in order to allow using it in Python.

```
 Rust                                                                   Python
┌────────────────────────────────────────────────────────────────┐    ┌────────────────────────────┐
│                                                                │    │                            │
│  protosim::evm_simulation             protosim_py              │    │   protosim_py              │
│ ┌────────────────────────┐           ┌──────────────────────┐  │    │  ┌──────────────────────┐  │
│ │                        │           │                      │  │    │  │                      │  │
│ │                        │    wrap   │                      │  │    │  │                      │  │
│ │    SimulationEngine ───┼───────────┼──► SimulationEngine  │  │    │  │  SimulationEngine    │  │
│ │                        │           │                      │  │    │  │                      │  │
│ │                        │    wrap   │                      │  │    │  │                      │  │
│ │    SimulationResult ───┼───────────┼──► SimulationResult  │  │    │  │  SimulationResult    │  │
│ │                        │           │                      │  │    │  │                      │  │
│ │                        │    wrap   │                      │  │    │  │                      │  │
│ │                 ... ───┼───────────┼──► ...               │  │    │  │  ...                 │  │
│ │                        │           │                      │  │    │  │                      │  │
│ └────────────────────────┘           └───────────┬──────────┘  │    │  └───────────▲──────────┘  │
│                                                  │             │    │              │             │
└──────────────────────────────────────────────────┼─────────────┘    └──────────────┼─────────────┘
                                                   │                                 │
                                                   │   build    ┌───────┐   install  │
                                                   └───────────►│ Wheel ├────────────┘
                                                                └───────┘
```
_Editable chart [here](https://asciiflow.com/#/share/eJyrVspLzE1VslIqKMovyS%2FOzI0vqFTSUcpJrEwtAopWxyhVxChZWZpY6sQoVQJZRuamQFZJakUJkBOjpBBUWlyiQDkIqCzJyM%2BLicl7NKXn0ZSGIY4mgLxEM59MAAdTE6VBDjWCgElAaZh1sBRiZZValhsPZJTmJJZk5uehqEdKRnisw6cKah1Vg28CihVUMXgCqpeoaio8CHBGDaoUToVQpzWhs3GrJNrq8qLEAlpaHQxPX6556Zl5qQpIobSHiJCEqZm2C9MoHI7DVEdGuGDlUTFc8FhNvygJSi0uzSmhSpRAjSIYJTB1o1GC02o9PT0KogSkmxjHYaobXFEyhXrVxgwUe4gxeA0RRqJ6iwhTp20izlRy2wXomnC1DLCoA1tJxRCnLiImByDFNIk%2BIcF0YDCRHi2YEYBdDSWGJ5Vm5qRAuLjaL6C2U2ZecUliTg5F1hGT0HeBXBWekZqaA9Qwh6aBS6TrZsQo1SrVAgD%2BnnnV)_

## Building and installation

The crate should be built using [maturin](https://www.maturin.rs/) tool.

### Prepare Python environment for building

1. Create a Python virtual environment (e.g. with `conda create --name myenv`).
2. Activate your Python virtual environment (e.g. with `conda activate myenv`)
3. Install `maturin` in your venv: `pip install maturin`

### Build and install in development mode 
(faster but less optimized, according to maturin docs)

This will install the Python module to the same environment that you use for building.

1. Activate your Python venv
2. Run `maturin develop` in the crate root folder
3. Enjoy. Try running `python ./protosim_demo.py`

### Build wheel and install it
You don't need `maturin` to _use_ this crate in Python; it is only needed to _build_ it. You can install a pre-built wheel in a different target environment.

1. Activate your build Python venv where `maturin` is installed
2. Run `maturin build` in the crate root folder. You can add `--release` flag to turn on optimizations.

   This will create a wheel (`.whl`) file in `<repo root>/target/wheels/` folder*, named accordingly to the architecture it supports, e.g. `protosim_py-0.1.0-cp39-cp39-manylinux_2_34_x86_64.whl`.

   *(Note that repo root is one level above the crate root.)
3. Deactivate your build Python environment. Activate your target environment.
4. Run `pip install <path_to_wheel_file>`
5. Enjoy.

> **Warning**
> Building on macOS is not tested yet!

### See also
Maturin documentation on building: https://www.maturin.rs/distribution.html
