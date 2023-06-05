from typing import Optional
from protosim_py import SimulationEngine


class SimulationParameters:
    def __init__(
        self,
        caller: str,
        to: str,
        data: bytearray,
        value: str,
        overrides: Optional[dict[str, str]],
        gas_limit: Optional[int],
    ):
        self.caller = caller
        self.to = to
        self.data = data
        self.value = value
        self.overrides = overrides
        self.gas_limit = gas_limit


def test():
    print("Run test function")
    sim = SimulationEngine()
    params = SimulationParameters(
        caller="0x0000000000000000000000000000000000000000",
        to="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        # fmt: off
        data=bytearray([
            208, 108, 166, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 245, 225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 184, 105, 145,
            198, 33, 139, 54, 193, 209, 157, 74, 46, 158, 176, 206, 54, 6, 235, 72, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 42, 170, 57, 178, 35, 254, 141, 10,
            14, 92, 79, 39, 234, 217, 8, 60, 117, 108, 194
        ]),
        # fmt: on
        value="0",
        overrides=dict(),
        gas_limit=500000000000000,
    )
    print("Run test sim")
    res = sim.run_sim(params)
    print("Sim done")
    print(res)


if __name__ == "__main__":
    test()
