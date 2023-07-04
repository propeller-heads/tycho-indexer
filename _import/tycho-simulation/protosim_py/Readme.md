# Python bindings for Protosim EVM Simulation

`protosim_py` - a Python module, implemented as a Rust crate, that allows using Rust EVM simulation module from Python.

## Summary

`evm_simulation` module from `protosim` crate implements simulating on-chain transactions. This crate - `protosim_py` - wraps `evm_simulation` in order to allow using it in Python.

```
 Rust                                                                  Python
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

### Build in `manylinux` docker image

This way is recommended (necessary?) if you want to install the resulting wheel in a `defibot` Docker image.

To build a wheel, go to **repo root** and run:
```shell
sudo ./protosim_py/build_protosim_wheel.sh
```
A wheel file will be created in `protosim_py/target/wheels`. 

In the script file, there's a commented out line for pushing the wheel to S3. Execute it if you want to publish the wheel for defibot to use it. Be careful - this file will be immediately used by defibot CI!


### Build locally

The crate should be built using [maturin](https://www.maturin.rs/) tool.

#### Prepare Python environment for building

1. Create a Python virtual environment (e.g. with `conda create --name myenv`).
2. Activate your Python virtual environment (e.g. with `conda activate myenv`)
3. Install `maturin` in your venv: `pip install maturin`

#### Build and install in development mode 
(faster but less optimized, according to maturin docs)

This will install the Python module to the same environment that you use for building.

1. Activate your Python venv
2. Run `maturin develop` in the crate root folder
3. Enjoy. Try running `python ./protosim_demo.py`

#### Build wheel and install it
You don't need `maturin` to _use_ this crate in Python; it is only needed to _build_ it. You can install a pre-built wheel in a different target environment.

1. Activate your build Python venv where `maturin` is installed.  
   **IMPORTANT:** build environment must use the same Python version as the target environment.
2. Run `maturin build --release` in the crate root folder (`--release` flag is optional; it turns on optimizations).

   This will create a wheel (`.whl`) file in `protosim_py/target/wheels/` folder, named accordingly to the architecture
   it supports, e.g. `protosim_py-0.1.0-cp39-cp39-manylinux_2_34_x86_64.whl`.

3. Deactivate your build Python environment. Activate your target environment.
4. Run `pip install <path_to_wheel_file>`
5. Enjoy.

### See also

- Readme in `protosim::evm_simulation`
- Maturin documentation on building: https://www.maturin.rs/distribution.html
- Documentation on using this module to implement a `PoolState` in
  defibot: https://github.com/propeller-heads/defibot/blob/master/defibot/swaps/protosim/Readme.md

### Troubleshooting

> When I `pip install` the wheel, I get `ERROR: <wheel_name>.whl is not a supported wheel on this platform`.

1. Make sure you used the same Python version in your build environment as the one in the environment you're installing
   the wheel into.
2. Check
   out [this SO answer](https://stackoverflow.com/questions/65888506/error-wheel-whl-is-not-a-supported-wheel-on-this-platform/68295012#68295012)
   and try renaming the wheel.
3. On macOS, Try building with MACOSX_DEPLOYMENT_TARGET environment variable set.
   See [here](https://www.maturin.rs/environment-variables.html#other-environment-variables)
   and [here](https://www.maturin.rs/migration.html?highlight=MACOSX_DEPLOYMENT_TARGET#macos-deployment-target-version-defaults-what-rustc-supports).
