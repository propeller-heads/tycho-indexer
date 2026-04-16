from .adapter_contract import TychoSimulationContract
from .utils import ContractCompiler, ERC20OverwriteFactory, ERC20Slots
from .constants import EXTERNAL_ACCOUNT
from . import SimulationEngine
from ..models import EVMBlock, EthereumToken

_MARKER_VALUE = 314159265358979323846264338327950288419716939937510
_SPENDER = "0x08d967bb0134F2d07f7cfb6E246680c53927DD30"


class SlotDetectionFailure(Exception):
    pass


def brute_force_slots(
        t: EthereumToken, block: EVMBlock, engine: SimulationEngine
) -> tuple[ERC20Slots, ContractCompiler]:
    """Brute-force detection of storage slots for token allowances and balances.

    This function attempts to determine the storage slots used by the token contract for
    balance and allowance values by systematically testing different storage locations.
    It uses EVM simulation to overwrite storage slots (from 0 to 19) and checks whether
    the overwritten slot produces the expected result by making VM calls to
    `balanceOf(...)` or `allowance(...)`.

    The token contract and its storage must already be set up within the engine's
    database before calling this function.

    Parameters
    ----------
    t : EthereumToken
        The token whose storage slots are being brute-forced.
    block : EVMBlock
        The block at which the simulation is executed.
    engine : SimulationEngine
        The engine used to simulate the blockchain environment.

    Returns
    -------
    tuple[tuple[int, int], ContractCompiler]
        A tuple containing a tuple containing the detected balance storage slot and the allowance
        storage slot, respectively and in what compiler was used for this contract.

    Raises
    ------
    SlotDetectionFailure
        If the function fails to detect a valid slot for either balances or allowances
        after checking all possible slots (0-19).
    """
    token_contract = TychoSimulationContract(t.address, "ERC20", engine)
    balance_slot = None
    compiler = ContractCompiler.Solidity
    for i in range(100):
        for compiler_flag in [ContractCompiler.Solidity, ContractCompiler.Vyper]:
            overwrite_factory = ERC20OverwriteFactory(t, ERC20Slots(i, 1), compiler=compiler_flag)
            overwrite_factory.set_balance(_MARKER_VALUE, EXTERNAL_ACCOUNT)
            res = token_contract.call(
                "balanceOf",
                [EXTERNAL_ACCOUNT],
                block_number=block.id,
                timestamp=int(block.ts.timestamp()),
                overrides=overwrite_factory.get_tycho_overwrites(),
                caller=EXTERNAL_ACCOUNT,
                value=0,
            )

            if res.return_value is None:
                continue
            if res.return_value[0] == _MARKER_VALUE:
                balance_slot = i
                compiler = compiler_flag
                break

    if balance_slot is None:
        raise SlotDetectionFailure(f"Failed to infer balance slot for {t.address}")

    allowance_slot = None
    for i in range(100):
            overwrite_factory = ERC20OverwriteFactory(t, ERC20Slots(0, i), compiler=compiler)
            overwrite_factory.set_allowance(_MARKER_VALUE, _SPENDER, EXTERNAL_ACCOUNT)
            res = token_contract.call(
                "allowance",
                [EXTERNAL_ACCOUNT, _SPENDER],
                block_number=block.id,
                timestamp=int(block.ts.timestamp()),
                overrides=overwrite_factory.get_tycho_overwrites(),
                caller=EXTERNAL_ACCOUNT,
                value=0,
            )
            if res.return_value is None:
                continue
            if res.return_value[0] == _MARKER_VALUE:
                allowance_slot = i
                break


    if allowance_slot is None:
        raise SlotDetectionFailure(f"Failed to infer allowance slot for {t.address}")

    return (ERC20Slots(balance_slot, allowance_slot), compiler)
