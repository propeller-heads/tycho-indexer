import json
from unittest.mock import patch, Mock

from tycho_client.rpc_client import TychoRPCClient

from . import asset_dir


@patch("requests.post")
def test_get_protocol_components_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "protocol_components.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    result = client.get_protocol_components("uniswap_v2")

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/protocol_components",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        json={"protocol_system": "uniswap_v2"},
        params={},
    )
    assert "protocol_components" in result
    assert len(result["protocol_components"]) == 2


@patch("requests.post")
def test_get_protocol_state_returns_expected_result(mock_post, asset_dir):
    with (asset_dir / "rpc" / "protocol_state.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    result = client.get_protocol_state()

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/protocol_state",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        json={},
        params={'include_balances': True},
    )
    assert "states" in result
    assert len(result["states"]) == 1
    assert result["states"][0][
               "component_id"] == "0xe96a45f66bdda121b24f0a861372a72e8889523d"


@patch("requests.post")
def test_get_contract_state_returns_expected_result(
        mock_post, asset_dir
):
    with (asset_dir / "rpc" / "contract_state.json").open("r") as fp:
        data = json.load(fp)

    mock_response = Mock()
    mock_response.json.return_value = data
    mock_post.return_value = mock_response

    client = TychoRPCClient()
    result = client.get_contract_state(include_balances=True)

    mock_post.assert_called_once_with(
        "http://0.0.0.0:4242/v1/ethereum/contract_state",
        headers={"accept": "application/json", "Content-Type": "application/json"},
        json={},
        params={"include_balances": True},
    )

    assert "accounts" in result
    assert len(result["accounts"][0]["slots"]) > 0
