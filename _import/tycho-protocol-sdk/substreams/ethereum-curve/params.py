"""
This script could be changed to used `jq` and bash. Usage:

```bash
python params.py | substreams run -e mainnet.eth.streamingfast.io:443 substreams.yaml map_protocol_changes --start-block 11942410 --stop-block +100 -p map_components=
```
"""

import json
from typing import Any

PARAMETERS = "params.json"


def encode_json_to_query_params(params: list[dict[str, Any]]):
    encoded_params = []
    try:
        for i, param in enumerate(params):
            address: str = param["address"]
            tx_hash: str = param["tx_hash"]
            tokens: list[str] = param["tokens"]
            attributes: dict[str, str] = param["attributes"]

            encoded_address = f"address={address}"
            encoded_tx_hash = f"tx_hash={tx_hash}"
            encoded_tokens = "&".join([f"tokens[]={token}" for token in tokens])
            encoded_attributes = "&".join(
                [
                    f"attribute_keys[]={key}&attribute_vals[]={value}"
                    for key, value in attributes.items()
                ]
            )

            encoded_param = f"{encoded_address}&{encoded_tx_hash}&{encoded_tokens}&{encoded_attributes}"
            encoded_param = encoded_param.rstrip("&")
            encoded_params.append(encoded_param)

    except KeyError as err:
        raise KeyError(
            f"Missing key in {PARAMETERS}.\n"
            f"Index `{i}` object missing parameters.\n\n" + err.args[0]
        )

    return ",".join(encoded_params)


def main():
    with open(PARAMETERS, "r") as f:
        params = json.load(f)
    print('"', encode_json_to_query_params(params), '"', sep="")


if __name__ == "__main__":
    main()
