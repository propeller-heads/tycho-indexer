# Tycho Adapter

This repository contains the Tycho Adapter, a tool that allows you to interact with the Tycho API.

## Installation

### Prerequisites

- Python 3.9

### Install with pip

```shell
# Create conda environment
conda create -n tycho pip python=3.9
# Activate environment
conda activate tycho
# Install packages
pip install -r requirements.txt
```

## Usage

```python
from tycho_client.tycho.decoders import ThirdPartyPoolTychoDecoder
from tycho_client.tycho.models import Blockchain
from tycho_client.tycho.tycho_adapter import TychoPoolStateStreamAdapter

decoder = ThirdPartyPoolTychoDecoder(
    "MyProtocolSwapAdapter.evm.runtime", minimum_gas=0, hard_limit=False
)
stream_adapter = TychoPoolStateStreamAdapter(
    tycho_url="0.0.0.0:4242",
    protocol="my_protocol",
    decoder=decoder,
    blockchain=Blockchain.ethereum,
)
```