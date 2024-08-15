import json
from typing import Any

PARAMETERS = "params.json"
EMPTY = "0x0000000000000000000000000000000000000000"
INITIAL_BLOCK = 17258001


def encode_json_to_query_params(params: list[dict[str, Any]]):
    encoded_params = []
    try:
        for i, param in enumerate(params):
            address: str = param["address"]
            contracts: str = param.get("contracts", [])
            tx_hash: str = param["tx_hash"]
            tokens: list[str] = param["tokens"]
            static_attributes: dict[str, str] = param.get("static_attributes", {})
            static_attributes["name"] = param["name"]
            static_attributes["factory_name"] = "NA"
            static_attributes["factory"] = EMPTY
            attributes: dict[str, str] = param.get("attributes", {})

            encoded_address = f"address={address}"
            encoded_contracts = (
                "&" + "&".join([f"contracts[]={contract}" for contract in contracts])
                if contracts
                else ""
            )
            encoded_tx_hash = f"tx_hash={tx_hash}"
            encoded_tokens = "&".join([f"tokens[]={token}" for token in tokens])
            encoded_attributes = "&".join(
                [
                    f"attribute_keys[]={key}&attribute_vals[]={value}"
                    for key, value in attributes.items()
                ]
            )
            encoded_static_attributes = "&".join(
                [
                    f"static_attribute_keys[]={key}&static_attribute_vals[]={value}"
                    for key, value in static_attributes.items()
                ]
            )

            encoded_param = f"{encoded_address}{encoded_contracts}&{encoded_tx_hash}&{encoded_tokens}&{encoded_attributes}&{encoded_static_attributes}"
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
    print(encode_json_to_query_params(params))


if __name__ == "__main__":
    main()
