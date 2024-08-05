from typing import Optional, Any

import requests

from .dto import Chain, ProtocolComponent, ResponseProtocolState, ResponseAccount


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
            self,
            protocol_system: Optional[str] = None,
            component_addresses: Optional[list[str]] = None,
            tvl_gt: Optional[int] = None,
    ) -> list[ProtocolComponent]:
        body = {
            "protocol_system": protocol_system,
            "component_addresses": component_addresses,
        }
        body = {k: v for k, v in body.items() if v is not None}

        params = {"tvl_gt": tvl_gt}
        params = {k: v for k, v in params.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_components",
            body=body,
            params=params,
        )
        return [ProtocolComponent(**c) for c in res["protocol_components"]]

    def get_protocol_state(
            self,
            tvl_gt: Optional[int] = None,
            inertia_min_gt: Optional[int] = None,
            include_balances: Optional[bool] = True,
            protocol_ids: Optional[list[dict[str, str]]] = None,
            protocol_system: Optional[str] = None,
            version: Optional[dict[str, Any]] = None,
    ) -> list[ResponseProtocolState]:
        params = {
            "tvl_gt": tvl_gt,
            "inertia_min_gt": inertia_min_gt,
            "include_balances": include_balances,
        }
        params = {k: v for k, v in params.items() if v is not None}

        body = {
            "protocolIds": protocol_ids,
            "protocolSystem": protocol_system,
            "version": version,
        }
        body = {k: v for k, v in body.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/protocol_state", params=params, body=body
        )
        return [ResponseProtocolState(**s) for s in res["states"]]

    def get_contract_state(
            self,
            tvl_gt: Optional[int] = None,
            inertia_min_gt: Optional[int] = None,
            include_balances: Optional[bool] = True,
            contract_ids: Optional[list[dict[str, str]]] = None,
            version: Optional[dict[str, Any]] = None,
    ) -> list[ResponseAccount]:
        params = {
            "tvl_gt": tvl_gt,
            "inertia_min_gt": inertia_min_gt,
            "include_balances": include_balances,
        }

        # Filter out None values
        params = {k: v for k, v in params.items() if v is not None}

        body = {"contractIds": contract_ids, "version": version}

        # Filter out None values
        body = {k: v for k, v in body.items() if v is not None}

        res = self._post_request(
            f"/v1/{self._chain}/contract_state",
            body=body,
            params=params,
        )
        return [ResponseAccount(**a) for a in res["accounts"]]


if __name__ == "__main__":
    client = TychoRPCClient("http://localhost:4242")
    print(client.get_protocol_components("uniswap_v2"))
    print(client.get_protocol_state(protocol_system="vm:balancer"))
    print(client.get_contract_state(include_balances=True))
