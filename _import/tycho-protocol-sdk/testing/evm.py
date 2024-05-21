import os
from web3 import Web3

native_aliases = ["0x0000000000000000000000000000000000000000","0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]

erc20_abi = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    }
]

def get_token_balance(token_address, wallet_address, block_number):
    rpc_url = os.getenv("RPC_URL")

    if rpc_url is None:
        raise EnvironmentError("RPC_URL environment variable not set")

    web3 = Web3(Web3.HTTPProvider(rpc_url))

    if not web3.isConnected():
        raise ConnectionError("Failed to connect to the Ethereum node")
    
    # Check if the token_address is a native token alias
    if token_address.lower() in native_aliases:
        balance = web3.eth.get_balance(Web3.toChecksumAddress(wallet_address), block_identifier=block_number)
    else:
        contract = web3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=erc20_abi)
        balance = contract.functions.balanceOf(Web3.toChecksumAddress(wallet_address)).call(
            block_identifier=block_number
        )
    
    return balance
