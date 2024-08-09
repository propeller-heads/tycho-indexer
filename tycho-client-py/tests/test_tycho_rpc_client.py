import json
from unittest.mock import patch, Mock

from tycho_client.dto import (
    ProtocolComponent,
    ResponseProtocolState,
    ResponseAccount,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    TokensParams,
    ResponseToken,
)
from tycho_client.rpc_client import TychoRPCClient


@patch("requests.post")
def test_get_protocol_components_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "protocol_components.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    params = ProtocolComponentsParams(protocol_system="uniswap_v2")
    result = client.get_protocol_components(params)

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/protocol_components",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        data='{"protocol_system": "uniswap_v2"}',
        params={},
    )
    assert isinstance(result, list)
    assert isinstance(result[0], ProtocolComponent)
    assert len(result) == 2


@patch("requests.post")
def test_get_protocol_state_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "protocol_state.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    params = ProtocolStateParams()
    result = client.get_protocol_state(params)

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/protocol_state",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        data="{}",
        params='{"include_balances": true}',
    )
    assert isinstance(result, list)
    assert isinstance(result[0], ResponseProtocolState)
    assert len(result) == 1

    assert result[0].component_id == "0xe96a45f66bdda121b24f0a861372a72e8889523d"


@patch("requests.post")
def test_get_contract_state_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "contract_state.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    params = ContractStateParams(include_balances=True)
    result = client.get_contract_state(params)

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/contract_state",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        data="{}",
        params='{"include_balances": true}',
    )

    assert isinstance(result, list)
    assert isinstance(result[0], ResponseAccount)
    assert len(result[0].slots) > 0


import json
from unittest.mock import patch, Mock


@patch("requests.post")
def test_get_tokens_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "tokens.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    params = TokensParams(min_quality=10, traded_n_days_ago=30)
    result = client.get_tokens(params)

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/tokens",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        data='{"min_quality": 10, "traded_n_days_ago": 30}',
        params={},
    )
    assert isinstance(result, list)
    assert isinstance(result[0], ResponseToken)
    assert len(result) == len(data["tokens"])
