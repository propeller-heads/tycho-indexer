import requests

from .dto import (
    Chain,
    ProtocolComponent,
    ResponseProtocolState,
    ResponseAccount,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
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
        response = requests.post(
            self.rpc_url + endpoint,
            headers=self._headers,
            json=body or {},
            params=params or {},
        )
        return response.json()

    def get_protocol_components(
        self, params: ProtocolComponentsParams
    ) -> list[ProtocolComponent]:
        body = {
            "protocol_system": params.protocol_system,
            "component_addresses": params.component_addresses,
        }
        body = {k: v for k, v in body.items() if v is not None}

        query_params = {"tvl_gt": params.tvl_gt}
        query_params = {k: v for k, v in query_params.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_components",
            body=body,
            params=query_params,
        )
        return [ProtocolComponent(**c) for c in res["protocol_components"]]

    def get_protocol_state(
        self, params: ProtocolStateParams
    ) -> list[ResponseProtocolState]:
        query_params = {
            "tvl_gt": params.tvl_gt,
            "inertia_min_gt": params.inertia_min_gt,
            "include_balances": params.include_balances,
        }
        query_params = {k: v for k, v in query_params.items() if v is not None}

        body = {
            "protocolIds": params.protocol_ids,
            "protocolSystem": params.protocol_system,
            "version": params.version,
        }
        body = {k: v for k, v in body.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_state", params=query_params, body=body
        )
        return [ResponseProtocolState(**s) for s in res["states"]]

    def get_contract_state(self, params: ContractStateParams) -> list[ResponseAccount]:
        query_params = {
            "tvl_gt": params.tvl_gt,
            "inertia_min_gt": params.inertia_min_gt,
            "include_balances": params.include_balances,
        }
        query_params = {k: v for k, v in query_params.items() if v is not None}

        body = {"contractIds": params.contract_ids, "version": params.version}
        body = {k: v for k, v in body.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/contract_state",
            body=body,
            params=query_params,
        )
        return [ResponseAccount(**a) for a in res["accounts"]]


if __name__ == "__main__":
    client = TychoRPCClient("http://localhost:4242")
    print(client.get_protocol_components("uniswap_v2"))
    print(client.get_protocol_state(protocol_system="vm:balancer"))
    print(client.get_contract_state(include_balances=True))
