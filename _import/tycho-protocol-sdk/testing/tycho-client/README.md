# Tycho Adapter

This repository contains the Tycho Adapter, a tool that allows you to interact with the Tycho API.

## Installation

### Prerequisites

- Python 3.9
- Access to PropellerHead's private PyPi repository (CodeArtifact)

### Install with pip

```shell
# Access to PropellerHead's private PyPi repository (CodeArtifact)
aws codeartifact login --tool pip --repository protosim --domain propeller
# Create conda environment
conda create -n tycho pip python=3.9
# Activate environment
conda activate tycho
# Install packages
pip install -r requirements.txt
```

## Usage

```python
from tycho_client.decoders import ThirdPartyPoolTychoDecoder
from tycho_client.models import Blockchain
from tycho_client.tycho_adapter import TychoPoolStateStreamAdapter

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