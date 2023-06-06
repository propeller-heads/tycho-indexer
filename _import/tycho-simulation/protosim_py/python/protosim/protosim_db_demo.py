from protosim_py import SimulationEngine, AccountInfo, BlockHeader, StateUpdate

U256MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935


def test():
    print("Run test function")
    sim = SimulationEngine()
    
    acc_info = AccountInfo(balance=U256MAX,nonce=20, code_hash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", code= bytearray([
            208, 108, 166, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 245, 225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 184, 105, 145,
            198, 33, 139, 54, 193, 209, 157, 74, 46, 158, 176, 206, 54, 6, 235, 72, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 42, 170, 57, 178, 35, 254, 141, 10,
            14, 92, 79, 39, 234, 217, 8, 60, 117, 108, 194
        ]))
    perm_storage = {500: 500000, 20: 2000}
    print("Inserting Account")
    sim.init_account( 
        address="0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc",
        account=acc_info,
        mocked=False,
        permanent_storage=perm_storage,
    )

    print("Clear temp storage")
    sim.clear_temp_storage()

    bh = BlockHeader(    number= 50,
    hash="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    timestamp=200,)
    
    print("Attempting update")
    update = {"0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc": StateUpdate(balance= U256MAX, storage={U256MAX: U256MAX, 500: U256MAX})}
    sim.update_state(updates=update ,block=bh)




if __name__ == "__main__":
    test()