# Tycho Execution

TODO: add banner

Tycho Execution makes it easy to trade on different DEXs by handling the complex encoding for you. Instead of creating
custom code for each DEX, you get a simple, ready-to-use tool that generates the necessary data to execute trades. It’s
designed to be safe, straightforward, and quick to set up, so anyone can start trading without extra effort.

# Contract Analysis

We use [Slither](https://github.com/crytic/slither) to detect any potential vulnerabilities in our contracts.

To run locally, simply install Slither in your conda env and run it inside the foundry directory.

```
conda create --name tycho-execution python=3.10
conda activate tycho-execution

python3 -m pip install slither-analyzer`
cd foundry
slither .
```