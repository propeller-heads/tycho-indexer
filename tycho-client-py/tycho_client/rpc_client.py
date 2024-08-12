import json

import requests

from .dto import (
    Chain,
    ProtocolComponent,
    ResponseProtocolState,
    ResponseAccount,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    ResponseToken,
    TokensParams,
)


class TychoRPCClient:
    """
    A client for interacting with the Tycho RPC server.
    """

    def __init__(
            self, rpc_url: str = "http://0.0.0.0:4242", chain: Chain = Chain.ethereum
    ):
        self.rpc_url = rpc_url
        self._headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        self._chain = chain

    def _post_request(
            self, endpoint: str, params: dict = None, body: dict = None
    ) -> dict:
        """Sends a POST request to the given endpoint and returns the response."""

        # Convert to JSON strings to cast booleans to strings
        if body is not None:
            body = json.dumps(body)
        if params:
            params = json.dumps(params)

        response = requests.post(
            self.rpc_url + endpoint,
            headers=self._headers,
            data=body or "{}",
            params=params or {},
        )
        return response.json()

    def get_protocol_components(
            self, params: ProtocolComponentsParams
    ) -> list[ProtocolComponent]:
        params = params.dict(exclude_none=True)

        query_params_fields = ["tvl_gt"]
        body_fields = ["protocol_system", "component_addresses"]

        query_params = {k: v for k, v in params.items() if k in query_params_fields}
        body = {k: v for k, v in params.items() if k in body_fields}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_components",
            body=body,
            params=query_params,
        )
        return [ProtocolComponent(**c) for c in res["protocol_components"]]

    def get_protocol_state(
            self, params: ProtocolStateParams
    ) -> list[ResponseProtocolState]:
        params = params.dict(exclude_none=True)

        query_params_fields = ["tvl_gt", "inertia_min_gt", "include_balances"]
        body_fields = ["protocolIds", "protocolSystem", "version"]

        query_params = {k: v for k, v in params.items() if k in query_params_fields}
        body = {k: v for k, v in params.items() if k in body_fields}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_state", params=query_params, body=body
        )
        return [ResponseProtocolState(**s) for s in res["states"]]

    def get_contract_state(self, params: ContractStateParams) -> list[ResponseAccount]:
        params = params.dict(exclude_none=True)

        query_params_fields = ["tvl_gt", "inertia_min_gt", "include_balances"]
        body_fields = ["contractIds", "version"]

        query_params = {k: v for k, v in params.items() if k in query_params_fields}
        body = {k: v for k, v in params.items() if k in body_fields}

        res = self._post_request(
            f"/v1/{self._chain}/contract_state",
            body=body,
            params=query_params,
        )
        return [ResponseAccount(**a) for a in res["accounts"]]

    def get_tokens(self, params: TokensParams) -> list[ResponseToken]:
        params = params.dict(exclude_none=True)

        body_fields = ["min_quality", "pagination", "tokenAddresses", "traded_n_days_ago"]
        body = {k: v for k, v in params.items() if k in body_fields}

        res = self._post_request(f"/v1/{self._chain}/tokens", body=body, params={})
        return [ResponseToken(**t) for t in res["tokens"]]


if __name__ == "__main__":
    client = TychoRPCClient("http://0.0.0.0:4242")
    print(client.get_protocol_components(ProtocolComponentsParams(protocol_system="test_protocol")))
    print(client.get_protocol_state(ProtocolStateParams(protocol_system="test_protocol")))
    print(client.get_contract_state(ContractStateParams()))
    print(client.get_tokens(TokensParams(min_quality=10, traded_n_days_ago=30)))
