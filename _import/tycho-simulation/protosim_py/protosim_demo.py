"""Example of running a simulation in Rust from Python.

(Build and) install the `protosim_py` package in your Python before running this.
See the Readme.md file for instructions.
"""

from protosim_py import (
    SimulationEngine,
    SimulationParameters,
    AccountInfo,
    BlockHeader,
    StateUpdate,
)


U256MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935


def test():
    print("Run test function")
    engine = SimulationEngine()
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
        value=0,
        overrides={"0x0000000000000000000000000000000000000001": {U256MAX: U256MAX}},
        gas_limit=500000000000000,
    )
    print("Run test sim")
    res = engine.run_sim(params)
    print("Sim done")
    print(f"{res.result=}")

    # Demonstrate manually inserting and updating an account

    print("Inserting Account")
    engine.init_account(
        address="0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5",
        account=AccountInfo(
            balance=U256MAX,
            nonce=20,
            code=None,
        ),
        mocked=False,  # i.e. missing storage will be queried from a node
        permanent_storage={500: 500000, 20: 2000},
    )

    print("Clearing temp storage")
    engine.clear_temp_storage()

    print("Updating a manually-initialised account")
    engine.update_state(
        updates={
            "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5": StateUpdate(
                balance=U256MAX, storage={U256MAX: U256MAX, 500: U256MAX}
            )
        },
        block=BlockHeader(
            number=50,
            hash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            timestamp=200,
        )
    )



if __name__ == "__main__":
    test()
