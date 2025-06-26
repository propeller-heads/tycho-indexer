import json
from typing import Optional

import requests

from .dto import (
    Chain,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    TokensParams,
    HexBytes,
    ProtocolComponentsResponse,
    ProtocolStateResponse,
    ContractStateResponse,
    TokensResponse,
)


class HexBytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)


class TychoRPCError(Exception):
    """Custom exception for Tycho RPC errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[dict] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(self.message)


class TychoRPCClient:
    """
    A client for interacting with the Tycho RPC server.

    This client provides methods to interact with all available Tycho RPC endpoints.
    """

    def __init__(
        self,
        rpc_url: str = "http://0.0.0.0:4242",
        auth_token: str = None,
        chain: Chain = Chain.ethereum,
    ):
        """
        Initialize the Tycho RPC client.

        Args:
            rpc_url: The base URL of the Tycho RPC server
            auth_token: Optional authentication token
            chain: The default chain to use for requests
        """
        self.rpc_url = rpc_url.rstrip("/")
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
        """
        Sends a POST request to the given endpoint and returns the response.

        Args:
            endpoint: The API endpoint path
            params: Optional query parameters
            body: Optional request body

        Returns:
            The JSON response from the server

        Raises:
            TychoRPCError: If the request fails or returns an error
        """
        url = f"{self.rpc_url}{endpoint}"

        # Convert to JSON strings to cast booleans to strings
        if body is not None:
            body = json.dumps(body, cls=HexBytesEncoder)
        if params:
            params = json.dumps(params, cls=HexBytesEncoder)

        try:
            response = requests.post(
                url, headers=self._headers, data=body or "{}", params=params or {}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            status_code = (
                getattr(e.response, "status_code", None)
                if hasattr(e, "response")
                else None
            )
            response_data = None
            if hasattr(e, "response") and e.response is not None:
                try:
                    response_data = e.response.json()
                except:
                    response_data = {"error": e.response.text}

            raise TychoRPCError(
                f"Request failed: {str(e)}",
                status_code=status_code,
                response_data=response_data,
            )

    def _get_request(self, endpoint: str, params: dict = None) -> dict:
        """
        Sends a GET request to the given endpoint and returns the response.

        Args:
            endpoint: The API endpoint path
            params: Optional query parameters

        Returns:
            The JSON response from the server

        Raises:
            TychoRPCError: If the request fails or returns an error
        """
        url = f"{self.rpc_url}{endpoint}"

        try:
            response = requests.get(url, headers=self._headers, params=params or {})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            status_code = (
                getattr(e.response, "status_code", None)
                if hasattr(e, "response")
                else None
            )
            response_data = None
            if hasattr(e, "response") and e.response is not None:
                try:
                    response_data = e.response.json()
                except:
                    response_data = {"error": e.response.text}

            raise TychoRPCError(
                f"Request failed: {str(e)}",
                status_code=status_code,
                response_data=response_data,
            )

    def get_protocol_components(
        self, params: ProtocolComponentsParams
    ) -> ProtocolComponentsResponse:
        """
        Get protocol components based on the provided parameters.

        Args:
            params: Parameters for filtering protocol components

        Returns:
            Protocol components response with pagination
        """
        params_dict = params.dict(exclude_none=True)
        params_dict["chain"] = self._chain

        res = self._post_request("/v1/protocol_components", body=params_dict)
        return ProtocolComponentsResponse(**res)

    def get_protocol_state(self, params: ProtocolStateParams) -> ProtocolStateResponse:
        """
        Get protocol state based on the provided parameters.

        Args:
            params: Parameters for filtering protocol state

        Returns:
            Protocol state response with pagination
        """
        params_dict = params.dict(exclude_none=True)
        params_dict["chain"] = self._chain

        res = self._post_request("/v1/protocol_state", body=params_dict)
        return ProtocolStateResponse(**res)

    def get_contract_state(self, params: ContractStateParams) -> ContractStateResponse:
        """
        Get contract state based on the provided parameters.

        Args:
            params: Parameters for filtering contract state

        Returns:
            Contract state response with pagination
        """
        params_dict = params.dict(exclude_none=True)
        params_dict["chain"] = self._chain

        res = self._post_request("/v1/contract_state", body=params_dict)
        return ContractStateResponse(**res)

    def get_tokens(self, params: TokensParams) -> TokensResponse:
        """
        Get tokens based on the provided parameters.

        Args:
            params: Parameters for filtering tokens

        Returns:
            Tokens response with pagination
        """
        params_dict = params.dict(exclude_none=True)
        params_dict["chain"] = self._chain

        res = self._post_request("/v1/tokens", body=params_dict)
        return TokensResponse(**res)

    def health(self) -> dict:
        """
        Get server health status.

        Returns:
            Health status response
        """
        return self._get_request("/v1/health")


if __name__ == "__main__":
    # Example usage
    client = TychoRPCClient("http://0.0.0.0:4242")

    try:
        # Get protocol components
        components = client.get_protocol_components(
            ProtocolComponentsParams(protocol_system="test_protocol")
        )
        print(f"Found {len(components.protocol_components)} protocol components")

        # Get protocol state
        states = client.get_protocol_state(
            ProtocolStateParams(protocol_system="test_protocol")
        )
        print(f"Found {len(states.states)} protocol states")

        # Get contract state
        contracts = client.get_contract_state(ContractStateParams())
        print(f"Found {len(contracts.accounts)} contracts")

        # Get tokens
        tokens = client.get_tokens(TokensParams(min_quality=10, traded_n_days_ago=30))
        print(f"Found {len(tokens.tokens)} tokens")

        # Get health status
        health = client.health()
        print(f"Server health: {health}")

    except TychoRPCError as e:
        print(f"RPC Error: {e.message}")
        if e.status_code:
            print(f"Status code: {e.status_code}")
        if e.response_data:
            print(f"Response data: {e.response_data}")
    except Exception as e:
        print(f"Unexpected error: {e}")
