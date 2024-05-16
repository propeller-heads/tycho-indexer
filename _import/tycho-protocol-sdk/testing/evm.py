from web3 import Web3


def get_token_balance(rpc_url, token_address, wallet_address, block_number):
    web3 = Web3(Web3.HTTPProvider(rpc_url))

    if not web3.isConnected():
        raise ConnectionError("Failed to connect to the Ethereum node")

    erc20_abi = [
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function",
        }
    ]

    contract = web3.eth.contract(address=token_address, abi=erc20_abi)
    balance = contract.functions.balanceOf(wallet_address).call(
        block_identifier=block_number
    )
    return balance
