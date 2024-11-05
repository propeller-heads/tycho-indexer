from tycho_simulation_py.evm import AccountInfo, StateUpdate, BlockHeader, SimulationEngine
from tycho_simulation_py.evm.constants import MAX_BALANCE
from tycho_simulation_py.evm.utils import exec_rpc_method, get_code_for_address
from tycho_simulation_py.models import Address, EVMBlock


def read_account_storage_from_rpc(
        address: Address, block_hash: str, connection_string: str = None
) -> dict[str, str]:
    """Reads complete storage of a contract from a Geth instance.

    Parameters
    ----------
    address:
        The contracts address
    block_hash:
        The block hash at which we want to retrieve storage at.
    connection_string:
        The connection string for the Geth rpc endpoint.

    Returns
    -------
    storage:
        A dictionary containing the hex encoded slots (both keys and values).
    """

    res = exec_rpc_method(
        connection_string,
        "debug_storageRangeAt",
        [block_hash, 0, address, "0x00", 0x7FFFFFFF],
    )

    storage = {}
    for i in res["storage"].values():
        try:
            if i["key"] is None:
                raise RuntimeError(
                    "Node with preimages required, found a slot without key!"
                )
            k = i["key"]
            if i["value"] is None:
                continue
            else:
                v = i["value"]
            storage[k] = v
        except (TypeError, ValueError):
            raise RuntimeError(
                "Encountered invalid storage data retrieved data from geth -> " + str(i)
            )
    return storage


def init_contract_via_rpc(
        block: EVMBlock,
        contract_address: Address,
        engine: SimulationEngine,
        connection_string: str,
):
    """Initializes a contract in the simulation engine using data fetched via RPC.

    This function retrieves the contract's bytecode and storage from an external RPC
    endpoint and uses it to initialize the contract within the simulation engine.
    Additionally, it sets up necessary default accounts and updates the contract's
    state based on the provided block.

    Parameters
    ----------
    block :
        The block at which to initialize the contract.
    contract_address :
        The address of the contract to be initialized.
    engine :
        The simulation engine instance where the contract is set up.
    connection_string :
        RPC connection string used to fetch contract data.

    Returns
    -------
    SimulationEngine
        The simulation engine with the contract initialized.
    """
    bytecode = get_code_for_address(contract_address, connection_string)
    storage = read_account_storage_from_rpc(
        contract_address, block.hash_, connection_string
    )
    engine.init_account(
        address="0x0000000000000000000000000000000000000000",
        account=AccountInfo(balance=0, nonce=0),
        mocked=False,
        permanent_storage=None,
    )
    engine.init_account(
        address="0x0000000000000000000000000000000000000004",
        account=AccountInfo(balance=0, nonce=0),
        mocked=False,
        permanent_storage=None,
    )
    engine.init_account(
        address=contract_address,
        account=AccountInfo(
            balance=MAX_BALANCE,
            nonce=0,
            code=bytecode,
        ),
        mocked=False,
        permanent_storage=None,
    )
    engine.update_state(
        {
            contract_address: StateUpdate(
                storage={
                    int.from_bytes(
                        bytes.fromhex(k[2:]), "big", signed=False
                    ): int.from_bytes(bytes.fromhex(v[2:]), "big", signed=False)
                    for k, v in storage.items()
                },
                balance=0,
            )
        },
        BlockHeader(
            number=block.id, hash=block.hash_, timestamp=int(block.ts.timestamp())
        ),
    )
    return engine
