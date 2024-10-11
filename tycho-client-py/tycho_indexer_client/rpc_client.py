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
    HexBytes,
)


class HexBytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)


class TychoRPCClient:
    """
    A client for interacting with the Tycho RPC server.
    """

    def __init__(
        self,
        rpc_url: str = "http://0.0.0.0:4242",
        auth_token: str = None,
        chain: Chain = Chain.ethereum,
    ):
        self.rpc_url = rpc_url
        self._headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        if auth_token:
            self._headers["Authorization"] = auth_token
        self._chain = chain

    def _post_request(
        self, endpoint: str, params: dict = None, body: dict = None
    ) -> dict:
        """Sends a POST request to the given endpoint and returns the response."""

        # Convert to JSON strings to cast booleans to strings
        if body is not None:
            body = json.dumps(body, cls=HexBytesEncoder)
        if params:
            params = json.dumps(params, cls=HexBytesEncoder)

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
        params["chain"] = self._chain

        res = self._post_request(f"/v1/protocol_components", body=params)
        return [ProtocolComponent(**c) for c in res["protocol_components"]]

    def get_protocol_state(
        self, params: ProtocolStateParams
    ) -> list[ResponseProtocolState]:
        params = params.dict(exclude_none=True)
        params["chain"] = self._chain

        res = self._post_request(f"/v1/protocol_state", body=params)
        return [ResponseProtocolState(**s) for s in res["states"]]

    def get_contract_state(self, params: ContractStateParams) -> list[ResponseAccount]:
        params = params.dict(exclude_none=True)
        params["chain"] = self._chain

        res = self._post_request(f"/v1/contract_state", body=params)
        return [ResponseAccount(**a) for a in res["accounts"]]

    def get_tokens(self, params: TokensParams) -> list[ResponseToken]:
        params = params.dict(exclude_none=True)
        params["chain"] = self._chain

        res = self._post_request(f"/v1/tokens", body=params)
        return [ResponseToken(**t) for t in res["tokens"]]


if __name__ == "__main__":
    client = TychoRPCClient("http://0.0.0.0:4242")
    print(
        client.get_protocol_components(
            ProtocolComponentsParams(protocol_system="test_protocol")
        )
    )
    print(
        client.get_protocol_state(ProtocolStateParams(protocol_system="test_protocol"))
    )
    print(client.get_contract_state(ContractStateParams()))
    print(client.get_tokens(TokensParams(min_quality=10, traded_n_days_ago=30)))
