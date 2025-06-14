## [0.116.0](https://github.com/propeller-heads/tycho-simulation/compare/0.115.0...0.116.0) (2025-06-13)


### Features

* Set storage and transient storage from before swap to after swap ([d1dfd0d](https://github.com/propeller-heads/tycho-simulation/commit/d1dfd0da622d7f5460b87c004c14d6b049ee4b98))


### Bug Fixes

* Change transient storage to HashMap<Address, HashMap<U256, U256>> ([82927a4](https://github.com/propeller-heads/tycho-simulation/commit/82927a4a6549d73df9860839a2c88fd82ab19fda))
* Only pass storage values (not transient storage) ([16a72db](https://github.com/propeller-heads/tycho-simulation/commit/16a72db1f6b118a9ae9d74cce7aabfcdc4e20acf))
* Remove unnecessary bytecode of unimon hook ([390a1c1](https://github.com/propeller-heads/tycho-simulation/commit/390a1c10a0ed42f6166b229d56e4e0b0f388cb05))

## [0.115.0](https://github.com/propeller-heads/tycho-simulation/compare/0.114.0...0.115.0) (2025-06-13)


### Features

* Don't overwrite tokens in hook handler creator ([e497dcb](https://github.com/propeller-heads/tycho-simulation/commit/e497dcbce87675590d62671e0b33f9eec65c22a3))
* GenericVMHookHandlerCreator ([4cf908a](https://github.com/propeller-heads/tycho-simulation/commit/4cf908a6dd69799fd35a21006e3f3748081a2023))
* Properly mock bytecode in after_swap test ([0340ebb](https://github.com/propeller-heads/tycho-simulation/commit/0340ebbee8737e7793defd1f60316bf101a58ac5))
* Remove bytecode from hook handler input ([2265874](https://github.com/propeller-heads/tycho-simulation/commit/22658745982a8a7eb3227c9ab0e0476586abed0d))
* Use SHARED_TYCHO_DB, remove balance inits ([7497116](https://github.com/propeller-heads/tycho-simulation/commit/7497116930e4983b8d79471fe285a4114b44788b))

## [0.114.0](https://github.com/propeller-heads/tycho-simulation/compare/0.113.0...0.114.0) (2025-06-11)


### Features

* rename new_swap_adapter -> new_contract ([ccd364c](https://github.com/propeller-heads/tycho-simulation/commit/ccd364c754dfe830994a5fb899cd4a23e217321b))


### Bug Fixes

* fix after merging main ([918794b](https://github.com/propeller-heads/tycho-simulation/commit/918794b4b061136c2b595241452faec9b0ea7377))

## [0.113.0](https://github.com/propeller-heads/tycho-simulation/compare/0.112.0...0.113.0) (2025-06-11)


### Features

* instantiate_hook_handler ([d73d929](https://github.com/propeller-heads/tycho-simulation/commit/d73d929d85a2ebe99f8d6e76787d6ab470a58c41))
* register_hook_handler ([594e247](https://github.com/propeller-heads/tycho-simulation/commit/594e247dd02917163975fdfd6d4523837efe6be7))
* set_default_hook_handler ([6caedfb](https://github.com/propeller-heads/tycho-simulation/commit/6caedfbb9fa0db15f365d46871ca873c9b8d6869))

## [0.112.0](https://github.com/propeller-heads/tycho-simulation/compare/0.111.0...0.112.0) (2025-06-11)


### Features

* HookHandlerCreator struct + traits ([0a3b68b](https://github.com/propeller-heads/tycho-simulation/commit/0a3b68b555b8fd140b8784b02b3b700458efb2ca))

## [0.111.0](https://github.com/propeller-heads/tycho-simulation/compare/0.110.0...0.111.0) (2025-06-11)


### Features

* **GenericVMHookHandler:** Return errors for unimplemented methods ([8c179d6](https://github.com/propeller-heads/tycho-simulation/commit/8c179d65773bc12ee57f24c3a2bfc81eab4b5e04))

## [0.110.0](https://github.com/propeller-heads/tycho-simulation/compare/0.109.0...0.110.0) (2025-06-11)


### Features

* Implement after_swap in generic_vm_hook_handler ([8d8d89e](https://github.com/propeller-heads/tycho-simulation/commit/8d8d89ece8034847981d16fbe23661a619cd3b20))

## [0.109.0](https://github.com/propeller-heads/tycho-simulation/compare/0.108.0...0.109.0) (2025-06-09)


### Features

* GenericVMHookHandler.before_swap ([4363fc9](https://github.com/propeller-heads/tycho-simulation/commit/4363fc974627829361134d47a951203864e5ad97))

## [0.108.0](https://github.com/propeller-heads/tycho-simulation/compare/0.107.0...0.108.0) (2025-06-06)


### Features

* Add skeleton of GenericVMHookHandler ([6ee6746](https://github.com/propeller-heads/tycho-simulation/commit/6ee67466524d787fd982197dd237d90e9f2f5872))

## [0.107.0](https://github.com/propeller-heads/tycho-simulation/compare/0.106.0...0.107.0) (2025-06-06)


### Features

* Expose transient storage ([e47b584](https://github.com/propeller-heads/tycho-simulation/commit/e47b58423c4b6912678409b98b95cc5d6585b866))

## [0.106.0](https://github.com/propeller-heads/tycho-simulation/compare/0.105.0...0.106.0) (2025-06-06)


### Features

* Add HookHandler trait ([b829e8d](https://github.com/propeller-heads/tycho-simulation/commit/b829e8d4d0ca76c97dd3e42b532e23e930f562dc))

## [0.105.0](https://github.com/propeller-heads/tycho-simulation/compare/0.104.0...0.105.0) (2025-06-05)


### Features

* Change get_limits interface in ProtocolSim ([aa4cb38](https://github.com/propeller-heads/tycho-simulation/commit/aa4cb38fc8a6226e0eeb6e8f47a1b3fe51f3c392))
* Upgrade revm to 24.0.0 ([fd67011](https://github.com/propeller-heads/tycho-simulation/commit/fd6701197de968a383fa1aa666f9e4098ed584eb))
* Upgrade tycho-execution ([114cccc](https://github.com/propeller-heads/tycho-simulation/commit/114ccccdfd3c905e16abc371bdd00906e3737a71))


### Bug Fixes

* Ignore nonce and add tracer properly in simulation ([6d8cbd5](https://github.com/propeller-heads/tycho-simulation/commit/6d8cbd596cfb04ae87237e0a7ccbf3a3ab8b9b8f))

## [0.104.0](https://github.com/propeller-heads/tycho-simulation/compare/0.103.2...0.104.0) (2025-06-04)


### Features

* Add ability to bypass approvals ([4839d4e](https://github.com/propeller-heads/tycho-simulation/commit/4839d4e86a62ba6b01005f312334767510e584ee))
* Add build runtime script and fix simulation py code ([c134146](https://github.com/propeller-heads/tycho-simulation/commit/c134146d040be02b1884ff93cbe896b19dab522f))
* Add new ERC20 override contract ([177ff9e](https://github.com/propeller-heads/tycho-simulation/commit/177ff9ec8a089b285b09bd40f6e8b2a021ff89a7))
* initialize token balances for receiving accounts ([f0cb2e1](https://github.com/propeller-heads/tycho-simulation/commit/f0cb2e12114ab2efee0d16932c53ddafe06ec7a4))
* remove ERCO20.sol ([9e6b336](https://github.com/propeller-heads/tycho-simulation/commit/9e6b3362f3cc5ae097e24dec2ea4e2604d8a256d))
* update binaries ([63421d9](https://github.com/propeller-heads/tycho-simulation/commit/63421d95611b94c6a116e3a1cf66b65874486884))
* Update README, remove duplicated contract, small code improvements ([a4be124](https://github.com/propeller-heads/tycho-simulation/commit/a4be124b5c9d7d22d1cb3c7d9b0ee65e449cf0b9))


### Bug Fixes

* formatting ([ffb80c2](https://github.com/propeller-heads/tycho-simulation/commit/ffb80c2d15aea97d906142932f76c341dac9fe49))

## [0.103.2](https://github.com/propeller-heads/tycho-simulation/compare/0.103.1...0.103.2) (2025-06-04)


### Bug Fixes

* Disable maverick from the quickstart ([e82e7a2](https://github.com/propeller-heads/tycho-simulation/commit/e82e7a2ebaf9c65eca799813cbcc28ba6b4044b1))

## [0.103.1](https://github.com/propeller-heads/tycho-simulation/compare/0.103.0...0.103.1) (2025-05-29)


### Bug Fixes

* temporarily disable maverick v2 ([02694fb](https://github.com/propeller-heads/tycho-simulation/commit/02694fbb05b4ac92c7a213f55a68949b6e22f525))

## [0.103.0](https://github.com/propeller-heads/tycho-simulation/compare/0.102.0...0.103.0) (2025-05-27)


### Features

* Update quickstart to sign the permit object itself ([73a21b0](https://github.com/propeller-heads/tycho-simulation/commit/73a21b07bd94665a2de750189cd612a1e20edc96))
* Update quickstart with new encoders ([bbae67a](https://github.com/propeller-heads/tycho-simulation/commit/bbae67a18b61db75fdb79498fe0a3240fbcdcacd))
* Update tycho-execution and quickstart ([cc41536](https://github.com/propeller-heads/tycho-simulation/commit/cc415365d5c152b90dccbcb9cc7bcd343917f092))
* update tycho-execution version ([6939613](https://github.com/propeller-heads/tycho-simulation/commit/693961396d39b2d868207ee753da4e56448697db))
* Update tycho-execution version ([aa04d06](https://github.com/propeller-heads/tycho-simulation/commit/aa04d06338dbd75760ae65e92412736f43d99211))
* Update tycho-execution version, add maverick stream ([d0588f8](https://github.com/propeller-heads/tycho-simulation/commit/d0588f81d0f40ca4a7c3357636afb8bfde2ce847))
* Upgrade tycho execution ([fdf62d5](https://github.com/propeller-heads/tycho-simulation/commit/fdf62d5b37ba01d833cef01e23aa931b98613a7c))


### Bug Fixes

* Don't use encode_input from tycho-execution ([641df02](https://github.com/propeller-heads/tycho-simulation/commit/641df02539c4cb7c83335b6b023e449d2ea4f2bf))
* **quickstart:** Support checking ETH balance not only ERC20 tokens ([04cc953](https://github.com/propeller-heads/tycho-simulation/commit/04cc953a04c4517be4bf765f773b36a38552fef5))

## [0.102.0](https://github.com/propeller-heads/tycho-simulation/compare/0.101.2...0.102.0) (2025-05-27)


### Features

* Add maverickV2 runtime and include it on examples ([7b442ec](https://github.com/propeller-heads/tycho-simulation/commit/7b442ec920cc0adb6ca7f28c59ad41869857288d))
* merge main ([4d87ec3](https://github.com/propeller-heads/tycho-simulation/commit/4d87ec3ca01c2f81234e4b89cd5d62cba4f0925d))


### Bug Fixes

* formatting ([3955924](https://github.com/propeller-heads/tycho-simulation/commit/3955924b08cef4cc70bd98db68d797d00003f0cf))

## [0.101.2](https://github.com/propeller-heads/tycho-simulation/compare/0.101.1...0.101.2) (2025-05-27)


### Bug Fixes

* set base default 'last active' token filter to 1 day ([7d123d3](https://github.com/propeller-heads/tycho-simulation/commit/7d123d37bd01d1b4ff49dfd170f9e96cfb58c8ed))

## [0.101.1](https://github.com/propeller-heads/tycho-simulation/compare/0.101.0...0.101.1) (2025-05-26)


### Bug Fixes

* improve solidity utils checks and errors ([dfb19f2](https://github.com/propeller-heads/tycho-simulation/commit/dfb19f2db82896c07b328af5e1d448a153140b98))

## [0.101.0](https://github.com/propeller-heads/tycho-simulation/compare/0.100.1...0.101.0) (2025-05-19)


### Features

* add Clone to BlockUpdate ([015d36d](https://github.com/propeller-heads/tycho-simulation/commit/015d36df8ddaadf9640c975b0af1bada7cd81ed2))
* add Serialize support to ProtocolComponent ([8c6d385](https://github.com/propeller-heads/tycho-simulation/commit/8c6d38584ce4bd897257010586e201440a856723))
* add Serialize support to Token ([9b164c6](https://github.com/propeller-heads/tycho-simulation/commit/9b164c6c37e1fd647f0315dd50b3ec130802dc07))

## [0.100.1](https://github.com/propeller-heads/tycho-simulation/compare/0.100.0...0.100.1) (2025-05-16)


### Bug Fixes

* update tycho-client to version 0.70.5 ([0f75dae](https://github.com/propeller-heads/tycho-simulation/commit/0f75daeb29947a3422d8c9539303f7d1d69ba615))

## [0.100.0](https://github.com/propeller-heads/tycho-simulation/compare/0.99.2...0.100.0) (2025-05-15)


### Features

* update tycho-indexer dependencies to version 0.70.3 ([980b0fd](https://github.com/propeller-heads/tycho-simulation/commit/980b0fdb7ed6acffbe80bbd870bfeb6bdee1445b))

## [0.99.2](https://github.com/propeller-heads/tycho-simulation/compare/0.99.1...0.99.2) (2025-05-05)


### Bug Fixes

* **uniswap:** do not panic in add_liquidity_delta util function ([694873b](https://github.com/propeller-heads/tycho-simulation/commit/694873b1e67be5fafd1a4dae0b7c154dd9a2c83d))

## [0.99.1](https://github.com/propeller-heads/tycho-simulation/compare/0.99.0...0.99.1) (2025-05-01)


### Bug Fixes

* enhance curve_pool_filter to exclude additional stETH bugged pool ([ad9bc21](https://github.com/propeller-heads/tycho-simulation/commit/ad9bc212aa3b9be5da64fea5594518f977c2d6a9))

## [0.99.0](https://github.com/propeller-heads/tycho-simulation/compare/0.98.2...0.99.0) (2025-04-28)


### Features

* implement CPMMProtocol trait for UniswapV2-like protocols ([ddda73d](https://github.com/propeller-heads/tycho-simulation/commit/ddda73df7443451ee4d435f668d2b51c53a77a54))

## [0.98.2](https://github.com/propeller-heads/tycho-simulation/compare/0.98.1...0.98.2) (2025-04-21)

## [0.98.1](https://github.com/propeller-heads/tycho-simulation/compare/0.98.0...0.98.1) (2025-04-18)


### Bug Fixes

* Quickstart - only give success msg if tx succeeded ([7d627ce](https://github.com/propeller-heads/tycho-simulation/commit/7d627ce2dead888e5933551530e8c0ba7a68a521))

## [0.98.0](https://github.com/propeller-heads/tycho-simulation/compare/0.97.0...0.98.0) (2025-04-18)


### Features

* check balance, swap direction ([8176d3f](https://github.com/propeller-heads/tycho-simulation/commit/8176d3f4d46d456c4d858bb2eb853063b39719fb))

## [0.97.0](https://github.com/propeller-heads/tycho-simulation/compare/0.96.0...0.97.0) (2025-04-18)


### Features

* update tycho client to 0.66.4 ([25178ea](https://github.com/propeller-heads/tycho-simulation/commit/25178ea4a6e294a42483a2113a6a287cdb758604))

## [0.96.0](https://github.com/propeller-heads/tycho-simulation/compare/0.95.0...0.96.0) (2025-04-18)


### Features

* default tokens per chain in quickstart ([8e9bdaf](https://github.com/propeller-heads/tycho-simulation/commit/8e9bdaf9466cd434f13fc66906f140beca77b0bc))

## [0.95.0](https://github.com/propeller-heads/tycho-simulation/compare/0.94.0...0.95.0) (2025-04-15)


### Features

* Update tycho-execution tag (balancer v2 redeployment) ([a0409f1](https://github.com/propeller-heads/tycho-simulation/commit/a0409f184b861e40a3c854e864da9d37a07ca0dc))


### Bug Fixes

* Extend curve filter ([fb95870](https://github.com/propeller-heads/tycho-simulation/commit/fb958705203129b5a551f889233f739494c0a415))
* Improve warning message ([2ff5b54](https://github.com/propeller-heads/tycho-simulation/commit/2ff5b5411c7ecc5286583e7437d5b3759d0777a7))

## [0.94.0](https://github.com/propeller-heads/tycho-simulation/compare/0.93.0...0.94.0) (2025-04-14)


### Features

* Add curve in the quickstart ([9052911](https://github.com/propeller-heads/tycho-simulation/commit/905291171b950ae3271dc4e2d9ef389533027c94))


### Bug Fixes

* Update tycho-execution version to 0.79.0 ([ecfe109](https://github.com/propeller-heads/tycho-simulation/commit/ecfe109138379157f16cce3854223b036b9c1045))

## [0.93.0](https://github.com/propeller-heads/tycho-simulation/compare/0.92.1...0.93.0) (2025-04-09)


### Features

* add EkuboState exchange support in `price_printer` ([47b1c0f](https://github.com/propeller-heads/tycho-simulation/commit/47b1c0fba659c7c6fecf250605033e05bf70aaa1))


### Bug Fixes

* correctly insert balances updates ([517e442](https://github.com/propeller-heads/tycho-simulation/commit/517e442911a009ffab6dcf6506d19692cb185c12))
* filter out empty account balances in TychoStreamDecoder ([c41efe7](https://github.com/propeller-heads/tycho-simulation/commit/c41efe74fe79a71441d45d05be3ee6bc5a279f34))

## [0.92.1](https://github.com/propeller-heads/tycho-simulation/compare/0.92.0...0.92.1) (2025-04-08)

## [0.92.0](https://github.com/propeller-heads/tycho-simulation/compare/0.91.1...0.92.0) (2025-04-03)


### Features

* update tycho-execution version ([5da09da](https://github.com/propeller-heads/tycho-simulation/commit/5da09da1b6e2c9cef47b061e978d6ee1a36ca2cb))

## [0.91.1](https://github.com/propeller-heads/tycho-simulation/compare/0.91.0...0.91.1) (2025-04-02)


### Bug Fixes

* filter out empty accounts balances ([cb8a074](https://github.com/propeller-heads/tycho-simulation/commit/cb8a074b33fd030a70001c3de6dfa38f5eb4a18a))

## [0.91.0](https://github.com/propeller-heads/tycho-simulation/compare/0.90.0...0.91.0) (2025-04-02)


### Features

* add Unichain support in price printer ([bb318ab](https://github.com/propeller-heads/tycho-simulation/commit/bb318ab6e9e75624fbca06701851f26a92a95f74))

## [0.90.0](https://github.com/propeller-heads/tycho-simulation/compare/0.89.0...0.90.0) (2025-04-02)


### Features

* update tycho-execution version ([7bed198](https://github.com/propeller-heads/tycho-simulation/commit/7bed19866ca38436da5cae3a3cf36fe07d55fda3))

## [0.89.0](https://github.com/propeller-heads/tycho-simulation/compare/0.88.0...0.89.0) (2025-04-01)


### Features

* print traces on reverts ([d32e7a5](https://github.com/propeller-heads/tycho-simulation/commit/d32e7a56471773bd6b288e0039a39652672118ec))

## [0.88.0](https://github.com/propeller-heads/tycho-simulation/compare/0.87.0...0.88.0) (2025-04-01)


### Features

* Introduce ModelError for improved error handling in Token conversion ([8b1dbee](https://github.com/propeller-heads/tycho-simulation/commit/8b1dbee6a4069eeca59a8bcb689d72b8a515d04f))

## [0.87.0](https://github.com/propeller-heads/tycho-simulation/compare/0.86.1...0.87.0) (2025-03-31)


### Features

* update tycho deps ([6a11287](https://github.com/propeller-heads/tycho-simulation/commit/6a11287f3d2e4c2a291afc57b819c49000171313))

## [0.86.1](https://github.com/propeller-heads/tycho-simulation/compare/0.86.0...0.86.1) (2025-03-31)


### Bug Fixes

* Add default for new Chain enum variants ([ff49676](https://github.com/propeller-heads/tycho-simulation/commit/ff49676b456e67a81dc8ad1f2b7789113d0de31d))
* get tycho client & common deps from crates.io ([20d6ecb](https://github.com/propeller-heads/tycho-simulation/commit/20d6ecbaf644c0f40ddfd2f034540feb52f031b8))

## [0.86.0](https://github.com/propeller-heads/tycho-simulation/compare/0.85.1...0.86.0) (2025-03-25)


### Features

* move execution dependency to dev ([7655c89](https://github.com/propeller-heads/tycho-simulation/commit/7655c89e1e5657c7aca6aa4c9a2975f3d91af990))

## [0.85.1](https://github.com/propeller-heads/tycho-simulation/compare/0.85.0...0.85.1) (2025-03-25)


### Bug Fixes

* changed versions to hashes for reusible actions ([f26aca7](https://github.com/propeller-heads/tycho-simulation/commit/f26aca79bb57ac8e6bded991d6757a07758a92ae))
* lint for branch in the PR ([1edc6d1](https://github.com/propeller-heads/tycho-simulation/commit/1edc6d15e0383326c2e591db0701d16f2397ab65))
* lint for branch in the PR ([0abed2a](https://github.com/propeller-heads/tycho-simulation/commit/0abed2a1b872778c555d85a785e336f1cbe5b7b1))

## [0.85.0](https://github.com/propeller-heads/tycho-simulation/compare/0.84.0...0.85.0) (2025-03-21)


### Features

* add `get_limits` in `ProtocolSim`. ([4a607cb](https://github.com/propeller-heads/tycho-simulation/commit/4a607cbd6b9a5e1c9b9db48881015a50de671779))
* extend uniswap v3 fees to support pancakeswap v3 ([4bd07a8](https://github.com/propeller-heads/tycho-simulation/commit/4bd07a81ff575179797acbd3d9b2f465cb432472))

## [0.84.0](https://github.com/propeller-heads/tycho-simulation/compare/0.83.0...0.84.0) (2025-03-19)


### Features

* update tycho-execution version ([d6fcb05](https://github.com/propeller-heads/tycho-simulation/commit/d6fcb05ab0253b32ad964dbaab4ea2460f47c3ab))

## [0.83.0](https://github.com/propeller-heads/tycho-simulation/compare/0.82.2...0.83.0) (2025-03-13)


### Features

* add contract balances to EVMPoolState ([21e78ec](https://github.com/propeller-heads/tycho-simulation/commit/21e78ecfc3d24b1d06472d5f242bac7a1a5a11b2))
* add token balances to Account message conversion ([5a57b56](https://github.com/propeller-heads/tycho-simulation/commit/5a57b56f59a5ba573b9391a11764e9cab7fe47d5))
* allow custom account balances overwrites on Python Simulation ([c9d0650](https://github.com/propeller-heads/tycho-simulation/commit/c9d06502ea7548c7529311bc3253dc41131fadbd))
* apply account balances to decoded pool states ([61438ab](https://github.com/propeller-heads/tycho-simulation/commit/61438abf6273d76c9279ecfc5c364351f2fa169a))
* handle account balances on python decoder and poolstate ([4d5a446](https://github.com/propeller-heads/tycho-simulation/commit/4d5a4469dd4e6f541a756982ec09c056a2d86dd7))
* remove unnecessary tokens arg from get_balance_overwrites ([cf2f529](https://github.com/propeller-heads/tycho-simulation/commit/cf2f529202ea9b19d406dc1ac859be877ad4a328))
* update pool state balances on deltas ([be6d68a](https://github.com/propeller-heads/tycho-simulation/commit/be6d68acdcb349c2a443f899fa4a3f577be0f527))
* update pool states on balance updates ([5431692](https://github.com/propeller-heads/tycho-simulation/commit/54316929269715e1b1482bc0ae7699a1b41fabc0))


### Bug Fixes

* Checkout CI target branch. ([c19beea](https://github.com/propeller-heads/tycho-simulation/commit/c19beea9c7fc20e70e000563eddbc38090dc5d3c))
* do not error for pool_id not an address is account balances exist ([5bf3df1](https://github.com/propeller-heads/tycho-simulation/commit/5bf3df1dccd6678f7eb2ceb2e9dfd50deac1636e))
* error instead of panic on generating adapter contract address ([8f9b89b](https://github.com/propeller-heads/tycho-simulation/commit/8f9b89be1762f83edcee3c8302eaea7cd751d9df))
* fix broken dependencies after AccountBalances update ([b5e0705](https://github.com/propeller-heads/tycho-simulation/commit/b5e070586a0894472bc928b0c31634bac9638367))
* fix contract_balances initialization ([cc2f368](https://github.com/propeller-heads/tycho-simulation/commit/cc2f36843ed7f535f6a80725d82dc6319257bdff))
* only attempt component balance overwrites for present balances ([40ad970](https://github.com/propeller-heads/tycho-simulation/commit/40ad970f400f53e160e22453cb84c5e6ae72cc6e))
* use EthereumToken on overrides instead of address, convert amount to int ([7068ed5](https://github.com/propeller-heads/tycho-simulation/commit/7068ed5cd45eb5f535a7e83bc393564a4af850d1))

## [0.82.2](https://github.com/propeller-heads/tycho-simulation/compare/0.82.1...0.82.2) (2025-03-10)


### Bug Fixes

* **price-printer:** do not panic during amount calculation math. ([eb3f7f9](https://github.com/propeller-heads/tycho-simulation/commit/eb3f7f92902d709b3a6babffd421885afda167b5))

## [0.82.1](https://github.com/propeller-heads/tycho-simulation/compare/0.82.0...0.82.1) (2025-03-06)


### Bug Fixes

* **evm-decoder:** correctly construct the `contracts_map`. ([b8b9a61](https://github.com/propeller-heads/tycho-simulation/commit/b8b9a617be6dc8d78ec7dfb374b0c59ff30a9e82))
* **price-printer:** make amount stay >0. ([6d8cf77](https://github.com/propeller-heads/tycho-simulation/commit/6d8cf7772f9e3cb9bbf535a4a52aec1e6e18289a))

## [0.82.0](https://github.com/propeller-heads/tycho-simulation/compare/0.81.0...0.82.0) (2025-03-05)


### Features

* update tycho-execution version ([1235fe8](https://github.com/propeller-heads/tycho-simulation/commit/1235fe89f5d530a88bb255f1dbc6decd6061582d))
* update tycho-execution version ([23da794](https://github.com/propeller-heads/tycho-simulation/commit/23da79479562711f2232891ecddeb39b43e1f128))

## [0.81.0](https://github.com/propeller-heads/tycho-simulation/compare/0.80.0...0.81.0) (2025-03-04)


### Features

* **price_printer:** display the protocol name for each row in the table ([b8ad2d5](https://github.com/propeller-heads/tycho-simulation/commit/b8ad2d5dc400dfb72a9bda57c4e24027b4788d9c))


### Bug Fixes

* **quickstart:** map `ethereum` to `mainnet` when creating alloy `NamedChain`. ([2d559b3](https://github.com/propeller-heads/tycho-simulation/commit/2d559b357dbab382540a63d70704a9808eb7cc2a))

## [0.80.0](https://github.com/propeller-heads/tycho-simulation/compare/0.79.2...0.80.0) (2025-03-03)


### Features

* Configurable chain in quickstart ([9b1e03e](https://github.com/propeller-heads/tycho-simulation/commit/9b1e03e4f8e0b7d06731e395bb15738f2ca1b08a))
* Enable all Uniswap exchanges again ([518bb67](https://github.com/propeller-heads/tycho-simulation/commit/518bb67bfe0a95228ef9c39d6173aaca214a7e27))
* Rename ETH_RPC_URL -> RPC_URL ([95cbc91](https://github.com/propeller-heads/tycho-simulation/commit/95cbc91d5c38133cb9a17e4b0e1f8bd7ade870fe))

## [0.79.2](https://github.com/propeller-heads/tycho-simulation/compare/0.79.1...0.79.2) (2025-02-28)


### Bug Fixes

* Polish quickstart after Markus' changes ([c0993eb](https://github.com/propeller-heads/tycho-simulation/commit/c0993ebcbeed580831ad0b00f3b3125dc337af2e))

## [0.79.1](https://github.com/propeller-heads/tycho-simulation/compare/0.79.0...0.79.1) (2025-02-27)


### Bug Fixes

* 0.25% slippage check in quickstart ([3aedb2f](https://github.com/propeller-heads/tycho-simulation/commit/3aedb2f874aafd93b54ecddc71585e487b2925f9))

## [0.79.0](https://github.com/propeller-heads/tycho-simulation/compare/0.78.1...0.79.0) (2025-02-27)


### Features

* 1% slippage check in quickstart ([c3f5d92](https://github.com/propeller-heads/tycho-simulation/commit/c3f5d92e92c48e657f5c6677619d49128dbc69f6))

## [0.78.1](https://github.com/propeller-heads/tycho-simulation/compare/0.78.0...0.78.1) (2025-02-27)


### Bug Fixes

* Update tycho-execution tag ([bde0944](https://github.com/propeller-heads/tycho-simulation/commit/bde0944d8803579665fadfc5121853f5214b1056))

## [0.78.0](https://github.com/propeller-heads/tycho-simulation/compare/0.77.2...0.78.0) (2025-02-27)


### Features

* Add execution to quickstart ([10e3835](https://github.com/propeller-heads/tycho-simulation/commit/10e3835a41a9bf9686721a48b9101460be5e635d))
* Change tycho-execution version ([0bd8c90](https://github.com/propeller-heads/tycho-simulation/commit/0bd8c90011726d9d929a22f025ef92c3a250d330))
* **quickstart:** Simulate or execute in the quickstart ([1100c72](https://github.com/propeller-heads/tycho-simulation/commit/1100c728c192b7ade53845648625d1720eef847b))
* **quickstart:** Update rev for execution to use mainet contracts ([fdf599f](https://github.com/propeller-heads/tycho-simulation/commit/fdf599f2e3efa1647cb379601f8e968d701cdc8d))
* **quickstart:** Update version tag for tycho-execution ([f9cb85a](https://github.com/propeller-heads/tycho-simulation/commit/f9cb85a6f157a15f7483824d77ba299b4ca52c95))
* **quickstart:** Update with new EncoderBuilder from tycho-execution ([85caade](https://github.com/propeller-heads/tycho-simulation/commit/85caade3f952d288347b6f8e8eb5ad57ffdae45c))
* Refactor quickstart ([781f017](https://github.com/propeller-heads/tycho-simulation/commit/781f0171c6ead2cef69e520e57163aa95885110c))


### Bug Fixes

* **quickstart:** Make signer pk optional ([9ba2e38](https://github.com/propeller-heads/tycho-simulation/commit/9ba2e38cbb9cc67345d563b86a59b4c8306df484))
* **quickstart:** Make signer-pk a cli argument ([2f3748c](https://github.com/propeller-heads/tycho-simulation/commit/2f3748cc09eb08c29151a99a0c60c96f8e1c1566))
* Update tycho-execution tag ([81fe59a](https://github.com/propeller-heads/tycho-simulation/commit/81fe59a13b0c62a9db43d6d64f6ec52ef2197158))

## [0.77.2](https://github.com/propeller-heads/tycho-simulation/compare/0.77.1...0.77.2) (2025-02-27)

## [0.77.1](https://github.com/propeller-heads/tycho-simulation/compare/0.77.0...0.77.1) (2025-02-25)

## [0.77.0](https://github.com/propeller-heads/tycho-simulation/compare/0.76.0...0.77.0) (2025-02-20)


### Features

* update uniswap v4 decoding of lp fees ([9a6a91f](https://github.com/propeller-heads/tycho-simulation/commit/9a6a91fb35ec445c8a90860e02f78ca1968eb4ca))

## [0.76.0](https://github.com/propeller-heads/tycho-simulation/compare/0.75.0...0.76.0) (2025-02-18)


### Features

* **example:** add base into the `price-printer` example ([b414fac](https://github.com/propeller-heads/tycho-simulation/commit/b414facadc297cdf81e98031814d44bb2bf67471))

## [0.75.0](https://github.com/propeller-heads/tycho-simulation/compare/0.74.4...0.75.0) (2025-02-17)


### Features

* track contract to pool state map on tycho decoder ([1750dcf](https://github.com/propeller-heads/tycho-simulation/commit/1750dcf57e66915b7a078ca9ba32c3aa8384b089))
* trigger pool updates on related contract changes ([f19e656](https://github.com/propeller-heads/tycho-simulation/commit/f19e656b538006e0be69787d8306b931780fd66c))


### Bug Fixes

* update both new and existing pools related to the contract updated ([33284ad](https://github.com/propeller-heads/tycho-simulation/commit/33284ad3b269f7dc24265c91970128a656341489))

## [0.74.4](https://github.com/propeller-heads/tycho-simulation/compare/0.74.3...0.74.4) (2025-02-14)

## [0.74.3](https://github.com/propeller-heads/tycho-simulation/compare/0.74.2...0.74.3) (2025-02-13)


### Bug Fixes

* dummy commit to trigger release of tycho dependency update ([7514713](https://github.com/propeller-heads/tycho-simulation/commit/7514713a1159826ba49c3ff52761e5a244ad4e8f))

## [0.74.2](https://github.com/propeller-heads/tycho-simulation/compare/0.74.1...0.74.2) (2025-02-10)


### Bug Fixes

* Create a ProtocolComponent::new() that doesn't depend on tycho-core ([8f44f08](https://github.com/propeller-heads/tycho-simulation/commit/8f44f08025fe574ce80c10fea87d9ddbd909add6))

## [0.74.1](https://github.com/propeller-heads/tycho-simulation/compare/0.74.0...0.74.1) (2025-02-10)


### Bug Fixes

* make TickList public ([82a6062](https://github.com/propeller-heads/tycho-simulation/commit/82a60628feecb88f0fe26996eba7f8d7363c1028))

## [0.74.0](https://github.com/propeller-heads/tycho-simulation/compare/0.73.0...0.74.0) (2025-02-10)


### Features

* add filter args to load_all_tokens ([b1a76a8](https://github.com/propeller-heads/tycho-simulation/commit/b1a76a862714a6e33c1cb0a51b38796cab9c150c))


### Bug Fixes

* improve load_all_tokens arg names ([cfc4f51](https://github.com/propeller-heads/tycho-simulation/commit/cfc4f5193d595b6ec079886f949d8d1ef8a14df6))

## [0.73.0](https://github.com/propeller-heads/tycho-simulation/compare/0.72.0...0.73.0) (2025-02-06)


### Features

* Extend ProtocolComponent to have the attributes of the core model ([38f9cbc](https://github.com/propeller-heads/tycho-simulation/commit/38f9cbca680f5a4e617c111f9647ce7622e2adf0))

## [0.72.0](https://github.com/propeller-heads/tycho-simulation/compare/0.71.1...0.72.0) (2025-02-05)


### Features

* add chain ver to load_all_tokens ([1853916](https://github.com/propeller-heads/tycho-simulation/commit/185391671ca3a4885c1390a6a409e6d759bc9921))
* re-export shallow reimplementions of tycho core models ([1cae440](https://github.com/propeller-heads/tycho-simulation/commit/1cae4404dc5383e42cad68dbffac37baf85c2a28))
* update tycho version to a Base supported version ([cfbfeaa](https://github.com/propeller-heads/tycho-simulation/commit/cfbfeaabde77283eea83e95f11c6ef47bd9dce8d))

## [0.71.1](https://github.com/propeller-heads/tycho-simulation/compare/0.71.0...0.71.1) (2025-02-04)


### Bug Fixes

* skip decode failures on example streams ([5febdc9](https://github.com/propeller-heads/tycho-simulation/commit/5febdc9bbb1f67019354610e6a799b59d5a9f1c7))
* warn on updates for unknown pools in example instead of panic ([473feeb](https://github.com/propeller-heads/tycho-simulation/commit/473feebbfbdb856cbe9137a41e339afa4bd350ba))

## [0.71.0](https://github.com/propeller-heads/tycho-simulation/compare/0.70.0...0.71.0) (2025-01-30)


### Features

* add uniswap_v4 to examples ([54843b7](https://github.com/propeller-heads/tycho-simulation/commit/54843b79e06de97e776721bff1ed67a8568b7a16))


### Bug Fixes

* undo optimize imports formatting ([6f7a1da](https://github.com/propeller-heads/tycho-simulation/commit/6f7a1dac87a8f353093d92f96f6c97907b53b877))

## [0.70.0](https://github.com/propeller-heads/tycho-simulation/compare/0.69.0...0.70.0) (2025-01-21)


### Features

* **balancer-v3:** add a specific overwrite case for BalancerV3 vault. ([e973e68](https://github.com/propeller-heads/tycho-simulation/commit/e973e6840fb00f7a291af1c62c34ffebc6efb143))

## [0.69.0](https://github.com/propeller-heads/tycho-simulation/compare/0.68.1...0.69.0) (2025-01-10)


### Features

* **price_printer:** dynamically adapt the quote amount to the new decimals when switching row ([65acc96](https://github.com/propeller-heads/tycho-simulation/commit/65acc968e7de203eb4e7e77cccfacdb990fe44dc))

## [0.68.1](https://github.com/propeller-heads/tycho-simulation/compare/0.68.0...0.68.1) (2025-01-07)

## [0.68.0](https://github.com/propeller-heads/tycho-simulation/compare/0.67.0...0.68.0) (2024-12-23)


### Features

* **uniswap_v4:** implement delta transition ([9a0f795](https://github.com/propeller-heads/tycho-simulation/commit/9a0f79569b854236829a8cf5d1ac96e5b94dd1e5))

## [0.67.0](https://github.com/propeller-heads/tycho-simulation/compare/0.66.0...0.67.0) (2024-12-23)


### Features

* initial TryFromWithBlock impl for UniV4State ([b15aae2](https://github.com/propeller-heads/tycho-simulation/commit/b15aae27d497046e298329381f7a225d75b11288))

## [0.66.0](https://github.com/propeller-heads/tycho-simulation/compare/0.65.0...0.66.0) (2024-12-20)


### Features

* **uniswap_v4:** add filter for pools with hooks ([dd668e2](https://github.com/propeller-heads/tycho-simulation/commit/dd668e2c84248982d77770a2cb42413f27f6dab9))

## [0.65.0](https://github.com/propeller-heads/tycho-simulation/compare/0.64.0...0.65.0) (2024-12-20)


### Features

* **uniswap_v4:** implement `ProtocolSim` except `delta_transition` ([6155b4a](https://github.com/propeller-heads/tycho-simulation/commit/6155b4ad64f0ad1a371af33c08d3890694d48ad1))
* **uniswap_v4:** implement `swap()` for `UniswapV4State` ([584347c](https://github.com/propeller-heads/tycho-simulation/commit/584347cd4b40fe5a26c0395935884b10fd40f071))

## [0.64.0](https://github.com/propeller-heads/tycho-simulation/compare/0.63.0...0.64.0) (2024-12-20)


### Features

* **uniswap_v4:** implement `UniswapV4State` struct ([d1a52a0](https://github.com/propeller-heads/tycho-simulation/commit/d1a52a01d90e1789821aff1fdb44041d59305057))

## [0.63.0](https://github.com/propeller-heads/tycho-simulation/compare/0.62.3...0.63.0) (2024-12-20)


### Features

* Allow for skip_state_decode_failures in TychoStreamDecoder to be set ([6364959](https://github.com/propeller-heads/tycho-simulation/commit/6364959f89351eba89edba98903cf2d28742c6c6))

## [0.62.3](https://github.com/propeller-heads/tycho-simulation/compare/0.62.2...0.62.3) (2024-12-20)


### Bug Fixes

* Load bytecode from files with include_bytes! ([97a260d](https://github.com/propeller-heads/tycho-simulation/commit/97a260dc0a360d60bfa00078d4ca429957c2cd73))

## [0.62.2](https://github.com/propeller-heads/tycho-simulation/compare/0.62.1...0.62.2) (2024-12-19)


### Bug Fixes

* Make the ERC20.bin filepath dependent on CARGO_MANIFEST_DIR ([2d20d30](https://github.com/propeller-heads/tycho-simulation/commit/2d20d3076d4b3ff074dc7999dd62ec26c311ede0))

## [0.62.1](https://github.com/propeller-heads/tycho-simulation/compare/0.62.0...0.62.1) (2024-12-19)


### Bug Fixes

* Allow for no tls connections when getting tokens from Tycho ([7981153](https://github.com/propeller-heads/tycho-simulation/commit/79811539a59da162c51ac09ef2c9becbc05d5797))

## [0.62.0](https://github.com/propeller-heads/tycho-simulation/compare/0.61.2...0.62.0) (2024-12-17)


### Features

* Add Quickstart ([0d8abe8](https://github.com/propeller-heads/tycho-simulation/commit/0d8abe89b3b45fcdbf052c9e791c7f143272ebf9))


### Bug Fixes

* Simplify quickstart (no more tasks) ([8a09054](https://github.com/propeller-heads/tycho-simulation/commit/8a0905487205c72b85690aedc182d9178e102a64))

## [0.61.2](https://github.com/propeller-heads/tycho-simulation/compare/0.61.1...0.61.2) (2024-12-17)

## [0.61.1](https://github.com/propeller-heads/tycho-simulation/compare/0.61.0...0.61.1) (2024-12-16)


### Bug Fixes

* Include path in I/O error message ([3dc672a](https://github.com/propeller-heads/tycho-simulation/commit/3dc672a5a84261c1e42e06f27b1395dfd08834af))

## [0.61.0](https://github.com/propeller-heads/tycho-simulation/compare/0.60.2...0.61.0) (2024-12-16)


### Features

* Update tycho dependencies tag and re export them ([5ffb440](https://github.com/propeller-heads/tycho-simulation/commit/5ffb440670fd310769c51cc3b5ebdcc2d81f3d81))


### Bug Fixes

* Remove tycho_ethereum - it isn't used anywhere ([5b92c47](https://github.com/propeller-heads/tycho-simulation/commit/5b92c4732821184212911278be40e124e2e157c4))

## [0.60.2](https://github.com/propeller-heads/tycho-simulation/compare/0.60.1...0.60.2) (2024-12-13)


### Bug Fixes

* Add tokens which are not already included in state guard ([86bbb3e](https://github.com/propeller-heads/tycho-simulation/commit/86bbb3e1acde9f6a095789d54954599916acd201))

## [0.60.1](https://github.com/propeller-heads/tycho-simulation/compare/0.60.0...0.60.1) (2024-12-13)


### Bug Fixes

* Move load_all_tokens to simulation's utils ([cce65a7](https://github.com/propeller-heads/tycho-simulation/commit/cce65a7cbc5669c53bad08d6e550de4580853fdb))

## [0.60.0](https://github.com/propeller-heads/tycho-simulation/compare/0.59.3...0.60.0) (2024-12-13)


### Features

* Provide ProtocolStreamBuilder to simplify decoding ([#53](https://github.com/propeller-heads/tycho-simulation/issues/53)) ([bc82193](https://github.com/propeller-heads/tycho-simulation/commit/bc821935685abf645050c3f06422057f8e787461))

## [0.59.3](https://github.com/propeller-heads/tycho-simulation/compare/0.59.2...0.59.3) (2024-12-13)


### Bug Fixes

* Put back block lasting overwrites ([8a6743e](https://github.com/propeller-heads/tycho-simulation/commit/8a6743e09b87c9cae10bcc0ae7e63cdc3c58b717))

## [0.59.2](https://github.com/propeller-heads/tycho-simulation/compare/0.59.1...0.59.2) (2024-12-12)


### Bug Fixes

* Change tycho url to point to dev db ([b3ed2c5](https://github.com/propeller-heads/tycho-simulation/commit/b3ed2c56b041fe2c0cc0458ef9030c243211f217))

## [0.59.1](https://github.com/propeller-heads/tycho-simulation/compare/0.59.0...0.59.1) (2024-12-12)


### Bug Fixes

* Don't hardcode ADAPTER_ADDRESS, make it depend on the protocol ([58f6294](https://github.com/propeller-heads/tycho-simulation/commit/58f62940f9e70cb2223de2f778635b860b404ffe))

## [0.59.0](https://github.com/propeller-heads/tycho-simulation/compare/0.58.0...0.59.0) (2024-12-12)


### Features

* Downgrade alloy because foundry depends on alloy and we don't want to update that now ([b44c6d4](https://github.com/propeller-heads/tycho-simulation/commit/b44c6d4d9252d24e59da7e310930aaf04126206c))
* Remove ethers from utils and Cargo.toml ([0753dbd](https://github.com/propeller-heads/tycho-simulation/commit/0753dbd2f3c61e646424db52d0359dd8f1dd0eda))
* Replace ethers Middleware with Provider from alloy ([a83925d](https://github.com/propeller-heads/tycho-simulation/commit/a83925d726dd6e867b6a9e21a94bccb9e43d1ed4))
* Support setting the block and add/fix real tests ([b3725e6](https://github.com/propeller-heads/tycho-simulation/commit/b3725e6bbcf50b6fa9e69d871c85424234c1a1f7))
* Update python package to use Provider from alloy ([2851d90](https://github.com/propeller-heads/tycho-simulation/commit/2851d900dc7c3d833f4d83ddc95ce571f29a1902))


### Bug Fixes

* After rebase fixes ([b8b6112](https://github.com/propeller-heads/tycho-simulation/commit/b8b61121be917565acfdfa114cc802a29baa21e3))

## [0.58.0](https://github.com/propeller-heads/tycho-simulation/compare/0.57.1...0.58.0) (2024-12-11)


### Features

* Generalize ERC20Token class ([b023b7b](https://github.com/propeller-heads/tycho-simulation/commit/b023b7b815227bbe026141f86d44d4f9b42629aa))


### Bug Fixes

* Expect Bytes for token address in decoders... ([c5b945d](https://github.com/propeller-heads/tycho-simulation/commit/c5b945d62494c8d5b7820604f6d39a994028fc6f))
* Restrict scope of most utils to pub(crate)... ([e1fda7f](https://github.com/propeller-heads/tycho-simulation/commit/e1fda7f99b330ccd82a609762a1753f43b2f1c89))
* revert main.rs ([e1451c1](https://github.com/propeller-heads/tycho-simulation/commit/e1451c1df52f9433491969f6f2c2d69d2caf6008))

## [0.57.1](https://github.com/propeller-heads/tycho-simulation/compare/0.57.0...0.57.1) (2024-12-11)


### Bug Fixes

* Rename BalancerSwapAdapter.evm.runtime to BalancerV2SwapAdapter.evm.runtime ([d091e60](https://github.com/propeller-heads/tycho-simulation/commit/d091e60169097d135a0b6d37735d6009b2e17ff6))

## [0.57.0](https://github.com/propeller-heads/tycho-simulation/compare/0.56.1...0.57.0) (2024-12-10)


### Features

* **example:** add Curve to `explorer` example ([4840265](https://github.com/propeller-heads/tycho-simulation/commit/48402655ebb0b0e073220cfaff699635c85da493))


### Bug Fixes

* correctly initialize stateless contracts ([28d3ad3](https://github.com/propeller-heads/tycho-simulation/commit/28d3ad304f79d527717b361c7d3e952bfe062006))
* correctly overwrites balances ([b5b7f2d](https://github.com/propeller-heads/tycho-simulation/commit/b5b7f2d0065658d08678517d44c2e962b47e20e2))

## [0.56.1](https://github.com/propeller-heads/tycho-simulation/compare/0.56.0...0.56.1) (2024-12-10)


### Bug Fixes

* update default TYCHO_URL to point to beta environment ([e5406c8](https://github.com/propeller-heads/tycho-simulation/commit/e5406c8e4a26694959e7dbbb9ee37e1c53fef3f1))

## [0.56.0](https://github.com/propeller-heads/tycho-simulation/compare/0.55.0...0.56.0) (2024-12-09)


### Features

* Take generic DB trait in state builder ([f1bc2a3](https://github.com/propeller-heads/tycho-simulation/commit/f1bc2a376cf8e81415c2c0e0108e760675fd1013))

## [0.55.0](https://github.com/propeller-heads/tycho-simulation/compare/0.54.0...0.55.0) (2024-12-09)


### Features

* Replace ethers types in block hash ([62a9a3d](https://github.com/propeller-heads/tycho-simulation/commit/62a9a3d7c45b9d5137255ee3698cdd994fb0f737))
* Replace ethers types with alloy in simulation interfaces ([803d1f9](https://github.com/propeller-heads/tycho-simulation/commit/803d1f9f9a11b72a2f42def125015655f0eb4ecb))
* Update encoding and decoding to use alloy instead of ethers ([3cd1787](https://github.com/propeller-heads/tycho-simulation/commit/3cd1787de49b67425d5b9b6b0bacc09014614287))

## [0.54.0](https://github.com/propeller-heads/tycho-simulation/compare/0.53.0...0.54.0) (2024-12-05)


### Features

* Change ERC20Token address to be alloy's Address instead of H160 ([b9f55db](https://github.com/propeller-heads/tycho-simulation/commit/b9f55dbc4a33da268461c4b82f2a4152a1343011))

## [0.53.0](https://github.com/propeller-heads/tycho-simulation/compare/0.52.2...0.53.0) (2024-12-05)


### Features

* Bye bye ethers pt. 1 ([fadf85c](https://github.com/propeller-heads/tycho-simulation/commit/fadf85cce803d795a45c31f2394738c921d5907e))
* Change uniswap v3 code to use alloy instead of ethers ([8775ef9](https://github.com/propeller-heads/tycho-simulation/commit/8775ef9c5fbc7ca461c14ae80b4cfbd5be91f9c7))
* Make alloy-primitives not optional ([ee75622](https://github.com/propeller-heads/tycho-simulation/commit/ee75622cf14663db24a08cb23660e74b48e4f4b5))

## [0.52.2](https://github.com/propeller-heads/tycho-simulation/compare/0.52.1...0.52.2) (2024-12-03)


### Bug Fixes

* Remove RUST_LOG flag reference from example README ([07ca8e4](https://github.com/propeller-heads/tycho-simulation/commit/07ca8e448848c7e09bc53c82107464e174b84bd5))

## [0.52.1](https://github.com/propeller-heads/tycho-simulation/compare/0.52.0...0.52.1) (2024-12-03)


### Bug Fixes

* Remove BalancerV2 from example ([aa8732f](https://github.com/propeller-heads/tycho-simulation/commit/aa8732f36b2358e0efda3cf06555c86473c19fcd))

## [0.52.0](https://github.com/propeller-heads/tycho-simulation/compare/0.51.0...0.52.0) (2024-12-03)


### Features

* take generic constraints for EVMPoolState instead of PreCachedDB ([a95ed00](https://github.com/propeller-heads/tycho-simulation/commit/a95ed000717d3d3604b498347228d16de2e8f1b6))

## [0.51.0](https://github.com/propeller-heads/tycho-simulation/compare/0.50.0...0.51.0) (2024-12-03)


### Features

* Discontinue support for event transitioning ([d4c8346](https://github.com/propeller-heads/tycho-simulation/commit/d4c8346bdb9e85cd2a2ae0484e26ba78ed5cd6e6))
* Remove ProtocolEvent and all USV2/3 event files. ([5b4770f](https://github.com/propeller-heads/tycho-simulation/commit/5b4770f53984cd03709687989a94118077678d96))

## [0.50.0](https://github.com/propeller-heads/tycho-simulation/compare/0.49.1...0.50.0) (2024-11-29)


### Features

* move balances to init - it's now mandatory ([f9b9131](https://github.com/propeller-heads/tycho-simulation/commit/f9b9131c1b2e10a68e50ae62ad17322268425506))


### Bug Fixes

* Don't use unwrap_or_default if balance not found ([a6c0a37](https://github.com/propeller-heads/tycho-simulation/commit/a6c0a3791bdef52c8a3fcf177714175150552ff6))

## [0.49.1](https://github.com/propeller-heads/tycho-simulation/compare/0.49.0...0.49.1) (2024-11-29)


### Bug Fixes

* Use u256_to_f64 when calculating prices ([49a8a31](https://github.com/propeller-heads/tycho-simulation/commit/49a8a3121b8d9a7bd57bf6732b4b2c1341a720e2))

## [0.49.0](https://github.com/propeller-heads/tycho-simulation/compare/0.48.0...0.49.0) (2024-11-29)


### Features

* Change type of adapter_contract_path to PathBuf ([d78a761](https://github.com/propeller-heads/tycho-simulation/commit/d78a761353a1827d0a259657acd9980cffed70be))
* The adapter file path needs to be relative to this crate ([8fefefd](https://github.com/propeller-heads/tycho-simulation/commit/8fefefdcb35857b861b4b52e52e9791634ca3bbb))

## [0.48.0](https://github.com/propeller-heads/tycho-simulation/compare/0.47.3...0.48.0) (2024-11-28)


### Features

* make most VMPoolState attrs private ([4f16913](https://github.com/propeller-heads/tycho-simulation/commit/4f16913e131b6046d741dfc93bd50727f78c479c))

## [0.47.3](https://github.com/propeller-heads/tycho-simulation/compare/0.47.2...0.47.3) (2024-11-28)


### Bug Fixes

* no more address checksumming ([6f7ca5a](https://github.com/propeller-heads/tycho-simulation/commit/6f7ca5a745181b58c03c44c4dbdadbf11c4b16fe))

## [0.47.2](https://github.com/propeller-heads/tycho-simulation/compare/0.47.1...0.47.2) (2024-11-28)

## [0.47.1](https://github.com/propeller-heads/tycho-simulation/compare/0.47.0...0.47.1) (2024-11-28)

## [0.47.0](https://github.com/propeller-heads/tycho-simulation/compare/0.46.0...0.47.0) (2024-11-28)


### Features

* Add a check to without the evm feature ([70d23fd](https://github.com/propeller-heads/tycho-simulation/commit/70d23fd060d1a494a1675f27d13212d2948c773e))
* Feature gate evm dependencies ([fdfe7ed](https://github.com/propeller-heads/tycho-simulation/commit/fdfe7edfff29169701cd4ee3c7d4032165faaf07))


### Bug Fixes

* Fix Cargo.toml syntax ([fafee46](https://github.com/propeller-heads/tycho-simulation/commit/fafee46bb0d1e3f1d45ace13f20ec4e706962e57))

## [0.46.0](https://github.com/propeller-heads/tycho-simulation/compare/0.45.1...0.46.0) (2024-11-27)


### Features

* (WIP) Define better user-facing errors ([623dcd8](https://github.com/propeller-heads/tycho-simulation/commit/623dcd841d34d49e933cdf12a2c5e809b52d6c15))
* Map DecodingError -> FatalError ([0ceb13f](https://github.com/propeller-heads/tycho-simulation/commit/0ceb13f2b8605c1deb8332112598bd7de4d7e69e))
* Map Encoding -> FatalError ([2dcbf9f](https://github.com/propeller-heads/tycho-simulation/commit/2dcbf9f11679be7b9db1426d8d2ae75779a607cc))
* map InsufficientData -> RetryDifferentInput ([270ebe0](https://github.com/propeller-heads/tycho-simulation/commit/270ebe0c6daca27e8c666282a56248134e615f5c))
* Remove SimulationEngineError enum in SimulationError ([34c782f](https://github.com/propeller-heads/tycho-simulation/commit/34c782f6817f94208a7a6a4b64731eee7b9809b2))
* return optional partial result in RetryDifferentInput ([9fbbaa1](https://github.com/propeller-heads/tycho-simulation/commit/9fbbaa1d0fca80228f05a071a5d49ee5f48e5867))


### Bug Fixes

* Clearer error messages and some error type fixes ([fda6527](https://github.com/propeller-heads/tycho-simulation/commit/fda6527a0089e484c64e30c70dc4462e251136d4))
* raise FatalError if RPC_URL not set ([99dc5ab](https://github.com/propeller-heads/tycho-simulation/commit/99dc5ab8406376ce2329f866ff20236be16e5465))
* state builder test typo ([c536bbe](https://github.com/propeller-heads/tycho-simulation/commit/c536bbea946390c98e4369049637c203540df24c))

## [0.45.1](https://github.com/propeller-heads/tycho-simulation/compare/0.45.0...0.45.1) (2024-11-26)


### Bug Fixes

* fix rebase issues ([bd16d3a](https://github.com/propeller-heads/tycho-simulation/commit/bd16d3adb9f8370b7a7d6aab96a5db4143bad3c3))
* Update trait usage in explorer example ([fc1f8c5](https://github.com/propeller-heads/tycho-simulation/commit/fc1f8c5988369b15173fb65054f184ef31f2732a))

## [0.45.0](https://github.com/propeller-heads/tycho-simulation/compare/0.44.1...0.45.0) (2024-11-26)


### Features

* use tycho dev as default URL for example ([183aa46](https://github.com/propeller-heads/tycho-simulation/commit/183aa462b04836eab165d923703d65e96bdc501e))


### Bug Fixes

* re-enable uniswap_v2 & v3 and disable balancer ([ca8fca6](https://github.com/propeller-heads/tycho-simulation/commit/ca8fca6cce0d8c9a8f350c6643cfad01f2b03355))

## [0.44.1](https://github.com/propeller-heads/tycho-simulation/compare/0.44.0...0.44.1) (2024-11-26)

## [0.44.0](https://github.com/propeller-heads/tycho-simulation/compare/0.43.2...0.44.0) (2024-11-25)


### Features

* add `VMPoolStateBuilder` and refactor TychoSimulationContract to improve engine handling ([58319b6](https://github.com/propeller-heads/tycho-simulation/commit/58319b6f389455b0372bbfbb8c0606b6c3b4289d))

## [0.43.2](https://github.com/propeller-heads/tycho-simulation/compare/0.43.1...0.43.2) (2024-11-22)

## [0.43.1](https://github.com/propeller-heads/tycho-simulation/compare/0.43.0...0.43.1) (2024-11-21)


### Bug Fixes

* checksum address before converting to rAddress ([d38cec8](https://github.com/propeller-heads/tycho-simulation/commit/d38cec8d3162c8fcd9351edb6db1977013189cc2))
* Do not make accounts public ([832b873](https://github.com/propeller-heads/tycho-simulation/commit/832b87377fc84e625978f8ec8d7e3ee4afc0ea92))

## [0.43.0](https://github.com/propeller-heads/tycho-simulation/compare/0.42.1...0.43.0) (2024-11-21)


### Features

* Implement clear_all_cache ([8440caa](https://github.com/propeller-heads/tycho-simulation/commit/8440caa4e81c9a326251b4d64783f10daf846118))


### Bug Fixes

* Do not clone self in `clear_all_cache` ([0dc0e88](https://github.com/propeller-heads/tycho-simulation/commit/0dc0e8879eb3037732d504ba19901dd4faddeebb))

## [0.42.1](https://github.com/propeller-heads/tycho-simulation/compare/0.42.0...0.42.1) (2024-11-21)


### Bug Fixes

* **db:** avoid deadlocks on the `RwLock` ([b18c60c](https://github.com/propeller-heads/tycho-simulation/commit/b18c60c68e4fc289f35d68b0260719e50fff04bd))
* **simulation:** correctly handle tokio runtime for traces ([62309a6](https://github.com/propeller-heads/tycho-simulation/commit/62309a6e8726608c96e1986e594e3674c8ea1a75))

## [0.42.0](https://github.com/propeller-heads/tycho-simulation/compare/0.41.0...0.42.0) (2024-11-19)


### Features

* change usv2 from little to big endian decoding ([6192c19](https://github.com/propeller-heads/tycho-simulation/commit/6192c1957d0a5b43d9ac429a58af1698786d601d))

## [0.41.0](https://github.com/propeller-heads/tycho-simulation/compare/0.40.0...0.41.0) (2024-11-14)


### Features

* (WIP) add balancer pool filter to tycho.rs ([67647d6](https://github.com/propeller-heads/tycho-simulation/commit/67647d653e973dfa74483804646644766c31ccbd))
* Add balancer to example ([7339063](https://github.com/propeller-heads/tycho-simulation/commit/73390639171f56e9ee7af84b2705d472896f8165))
* Change H160 to Bytes ([d5f3ea5](https://github.com/propeller-heads/tycho-simulation/commit/d5f3ea565c3491b98c6f58251b15374a722bf6cf))
* Implement delta_transition for VMPoolState - it sets spot prices ([e0883da](https://github.com/propeller-heads/tycho-simulation/commit/e0883dae08d5cf7593607253dae69194255fac24))
* implement From trait from dto objs to tycho_models ([4f2a777](https://github.com/propeller-heads/tycho-simulation/commit/4f2a77745e1025628841038cf7ea5499ffde8d18))


### Bug Fixes

* (WIP) fix pool filter ([901939d](https://github.com/propeller-heads/tycho-simulation/commit/901939dfa7e5d30c53d321bfa7b7445072b579c3))
* call `update_engine` before creating pool state ([0d3b1c4](https://github.com/propeller-heads/tycho-simulation/commit/0d3b1c4b12863a9567b07ea3c029ce965b5e5c02))
* Change tag of tycho-client and indexer ([0a4a6f2](https://github.com/propeller-heads/tycho-simulation/commit/0a4a6f2105c4d0714e2a0da94fa3c487f938ab8b))
* fix pool filter call order ([cfb907c](https://github.com/propeller-heads/tycho-simulation/commit/cfb907c15a4c61df99422c3a08628486e7bb8be8))
* Use same dependency of tycho-core as quoter ([5705236](https://github.com/propeller-heads/tycho-simulation/commit/5705236994ea9a102669ce4fcfb514500399bd6d))

## [0.40.0](https://github.com/propeller-heads/tycho-simulation/compare/0.39.2...0.40.0) (2024-11-13)


### Features

* **simulation:** try to bruteforce token slots when they are unknown ([482ac49](https://github.com/propeller-heads/tycho-simulation/commit/482ac49d184b1566fcd4ec0c78e3f1fbab7d5446))
* **token:** handle bruteforcing slots for Vyper contracts. ([9902dd8](https://github.com/propeller-heads/tycho-simulation/commit/9902dd880f5c1422fc1500687eefbb4aaadd184a))

## [0.39.2](https://github.com/propeller-heads/tycho-simulation/compare/0.39.1...0.39.2) (2024-11-08)


### Bug Fixes

* do not expect VMPoolState protocol system name to start with 'vm:' ([8d08147](https://github.com/propeller-heads/tycho-simulation/commit/8d08147297714f1a43c233377bacde5e19c6475e))
* protocol name to adapter file path conversion ([79ef30b](https://github.com/propeller-heads/tycho-simulation/commit/79ef30b1d62794a2eb2c103493b4a634fe074cb9))

## [0.39.1](https://github.com/propeller-heads/tycho-simulation/compare/0.39.0...0.39.1) (2024-11-07)


### Bug Fixes

* make TryFromWithBlock trait public ([7258820](https://github.com/propeller-heads/tycho-simulation/commit/725882087d93db18b104c92a74ab8e0cce06b340))

## [0.39.0](https://github.com/propeller-heads/tycho-simulation/compare/0.38.1...0.39.0) (2024-11-07)


### Features

* Make engine public ([df4ea3a](https://github.com/propeller-heads/tycho-simulation/commit/df4ea3a60f86108d8a54d376f1896f2975603343))

## [0.38.1](https://github.com/propeller-heads/tycho-simulation/compare/0.38.0...0.38.1) (2024-11-07)


### Bug Fixes

* return new state on partially successful simulations ([8dc7c3c](https://github.com/propeller-heads/tycho-simulation/commit/8dc7c3c061c33e12a60b0e8a69b2faa8cd8056fb))

## [0.38.0](https://github.com/propeller-heads/tycho-simulation/compare/0.37.0...0.38.0) (2024-11-07)


### Features

* Get rid of extra unnecessary Arc<RwLock<>> ([eb374e7](https://github.com/propeller-heads/tycho-simulation/commit/eb374e7b41a6229c6e3bb61df56e21a6b502c427))

## [0.37.0](https://github.com/propeller-heads/tycho-simulation/compare/0.36.0...0.37.0) (2024-11-07)


### Features

* (VMPoolState) implement get_amount_out ([dd7b551](https://github.com/propeller-heads/tycho-simulation/commit/dd7b551cbea8f770e47b55f77b99601430d1d237))
* Don't make new_state optional in GetAmountOutResult ([98a078d](https://github.com/propeller-heads/tycho-simulation/commit/98a078dab9c62d14224c9dac4d74f0f4a75b0e71))
* move logic from get_amount_out to ProtocolSim trait impl ([43fad10](https://github.com/propeller-heads/tycho-simulation/commit/43fad10e32f98f6269118be8ff85ce132fe8e768))
* Remove unnecessary async methods ([a068a18](https://github.com/propeller-heads/tycho-simulation/commit/a068a18fb874d0f29e3ada4801360cfa888a0412))


### Bug Fixes

* (VMPoolState) check for hard limit in get_amount_out ([2fe7ce9](https://github.com/propeller-heads/tycho-simulation/commit/2fe7ce9322ec12a4b90f79e1905eb2f3c7f9f199))
* Adjust errors after merge with errors refactor ([5aa6dad](https://github.com/propeller-heads/tycho-simulation/commit/5aa6dad1e0fdb7b224f44b38c2453de1dca9b996))
* Fix tests (problem with not checksummed addresses) ([4892b76](https://github.com/propeller-heads/tycho-simulation/commit/4892b768661e2702ad928eb49966e1001084df9a))
* initialize token bytecode when creating engine ([17f8305](https://github.com/propeller-heads/tycho-simulation/commit/17f8305e51cbbb262d241a99da2d032a2fbf4a76))
* overwrites merging bug ([3e8a47a](https://github.com/propeller-heads/tycho-simulation/commit/3e8a47adc02075d8e5063d77916608e26d662b01))
* Return new state in `GetAmountOutResult` ([d4e3050](https://github.com/propeller-heads/tycho-simulation/commit/d4e3050271bac811241a02ee62c493d5926c2dc7))
* TEMPORARY ([7ccdee6](https://github.com/propeller-heads/tycho-simulation/commit/7ccdee664961d3d4bfe5a15c1f39202e74e839b8))
* Update spot_prices in instead of marginal_prices in get_amount_out ([d4a0d8b](https://github.com/propeller-heads/tycho-simulation/commit/d4a0d8bb5fb858549dde1b534ef9062a753e653d))

## [0.36.0](https://github.com/propeller-heads/tycho-simulation/compare/0.35.0...0.36.0) (2024-11-07)


### Features

* **simulation-py:** make token bruteforce compatible with vyper ([71519c1](https://github.com/propeller-heads/tycho-simulation/commit/71519c11278aadcb1714b664229b0c0ea7080b59))

## [0.35.0](https://github.com/propeller-heads/tycho-simulation/compare/0.34.0...0.35.0) (2024-11-06)


### Features

* Merge VMError and NativeSimulationError into Simulation Error ([3d87a80](https://github.com/propeller-heads/tycho-simulation/commit/3d87a8043b5b8ab3cec6f71e2b347e7bac30077e))
* Return Result<> on spot_prices() in ProtocolSim ([3771b55](https://github.com/propeller-heads/tycho-simulation/commit/3771b5503a67298ba40cd0a7067be9a17e93a637))


### Bug Fixes

* Address PR reviews ([ad70185](https://github.com/propeller-heads/tycho-simulation/commit/ad7018564eecc55ac311962d082e202a26472507))
* After merge fix. Update example with new spot prices result ([abf4ae3](https://github.com/propeller-heads/tycho-simulation/commit/abf4ae31ee7a1bc59435e98ce851efdc68543edf))
* Finish refactor of error messages ([4a8d7b8](https://github.com/propeller-heads/tycho-simulation/commit/4a8d7b8198d0df204dd03c25da95f434b5de6c02))
* Include functional Cargo.lock ([2b1ee58](https://github.com/propeller-heads/tycho-simulation/commit/2b1ee5836bcdaa7c8c7c7bc08cd2160547bc7e11))

## [0.34.0](https://github.com/propeller-heads/tycho-simulation/compare/0.33.0...0.34.0) (2024-11-06)


### Features

* **vm_pool:** add VMError to InvalidSnapshotError ([7f52eaa](https://github.com/propeller-heads/tycho-simulation/commit/7f52eaaaa5b063bef7746c9999c59dfb976e5108))
* **vm_pool:** configure adapter file path ([4e70f80](https://github.com/propeller-heads/tycho-simulation/commit/4e70f801023aec08dff4b36421c3893042317235))
* **vm_pool:** decode balance owner ([4d9ef93](https://github.com/propeller-heads/tycho-simulation/commit/4d9ef93738048adc7fd9f3062e974c74dec3add8))
* **vm_pool:** decode manual updates attribute ([18c8f67](https://github.com/propeller-heads/tycho-simulation/commit/18c8f6717e7966875143ed1e23e5a450350d3bd1))
* **vm_pool:** decode stateless_contracts and involved_contracts ([b8a4fc1](https://github.com/propeller-heads/tycho-simulation/commit/b8a4fc1a262f26cae549f6fb7090f6ce2c7eda41))
* **vm_pool:** initial VMPoolState decoder ([919a9ac](https://github.com/propeller-heads/tycho-simulation/commit/919a9ac88e4ccf735030c1a38c7e5d4346424e5a))
* **vm_state:** convert tokens property to String ([41d9097](https://github.com/propeller-heads/tycho-simulation/commit/41d9097708cdba973088cdfd14cb8aff476f5283))


### Bug Fixes

* fix rebase errors and improve docs ([41e86e3](https://github.com/propeller-heads/tycho-simulation/commit/41e86e32aad108473760e3b067627e918654b7b7))
* fix rebase issues and remove unnecessary constructor params ([bb822b6](https://github.com/propeller-heads/tycho-simulation/commit/bb822b681c07790408831fa54cd5cd6b9d4a1f3e))
* **protosim_py:** fix ScaledPrices capacity name ([c7138da](https://github.com/propeller-heads/tycho-simulation/commit/c7138dad3130be166a6c538be40970d8d10864e5))

## [0.33.0](https://github.com/propeller-heads/tycho-simulation/compare/0.32.0...0.33.0) (2024-11-06)


### Features

* create simple solver for tycho demo ([956b2db](https://github.com/propeller-heads/tycho-simulation/commit/956b2db61c3d8e962b508cde2d69b166a8728c0c))
* move tutorial to a separate package and make it simpler ([266616d](https://github.com/propeller-heads/tycho-simulation/commit/266616dbcf80218319e7fb986c270b72ea799c9a))
* **tutorial:** move tutorial files into tutorial directory ([2350e71](https://github.com/propeller-heads/tycho-simulation/commit/2350e7179d9d5dcf93b1ec3c58ad398fc7ebc340))


### Bug Fixes

* Update foundry and revm dependencies ([ccfbde5](https://github.com/propeller-heads/tycho-simulation/commit/ccfbde51ffb375020f662e66985b0d4d9348b9b9))
* Update python revm version ([d9f069a](https://github.com/propeller-heads/tycho-simulation/commit/d9f069aa3a16194e2ce6dcd43f85ebdf283583a4))

## [0.32.0](https://github.com/propeller-heads/protosim/compare/0.31.0...0.32.0) (2024-11-04)


### Features

* Implement ProtocolSim for VMPoolstate get_spot_prices ([241a596](https://github.com/propeller-heads/protosim/commit/241a596d4f42111882deb5021d143e8bef07d46b))

## [0.31.0](https://github.com/propeller-heads/protosim/compare/0.30.1...0.31.0) (2024-10-31)


### Features

* Add ensure_capabilities to set_spot_prices ([3cf7257](https://github.com/propeller-heads/protosim/commit/3cf7257eaf652cccd6de1265f609cac037726624))
* Add get_sell_amount_limit ([fea627a](https://github.com/propeller-heads/protosim/commit/fea627a729d56e49a56352a3c6de2725c3e95908))
* Add involved_contracts and token_storage_slots to state overwrites ([4198a67](https://github.com/propeller-heads/protosim/commit/4198a6746b37816b2973c7ec4258ef19e17ef773))
* Add overwrites to VMPoolState ([20aba87](https://github.com/propeller-heads/protosim/commit/20aba873257d35feb0873e85cf0a4f958360341a))
* Add spot prices logic to VMPoolState ([1e25aa1](https://github.com/propeller-heads/protosim/commit/1e25aa130b37e4fc18ca1c4440d3f637db4b28e1))
* Rewrite set_spot_prices to get_spot_prices ([0459516](https://github.com/propeller-heads/protosim/commit/0459516595267b210ca3f35228b493a4af3f4ca6))


### Bug Fixes

* Fix types in state.rs tests ([c197690](https://github.com/propeller-heads/protosim/commit/c197690e1c6105c801a136b0d2ec8611f6573057))
* Miscellaneous fixes ([b6d2545](https://github.com/propeller-heads/protosim/commit/b6d25453cacb175a0c16a829fb00b6b5fa221465))
* rAddress discrepancies from OverwriteFactory ([ffb4cb3](https://github.com/propeller-heads/protosim/commit/ffb4cb3ae514907bcccd3a6c5617505ff1f43d65))
* Update get_code_for_address and get_contract_bytecode to return Bytecode ([04214ba](https://github.com/propeller-heads/protosim/commit/04214bad018a6459f49adc2d6d552dbd93ceec60))

## [0.30.1](https://github.com/propeller-heads/protosim/compare/0.30.0...0.30.1) (2024-10-31)

## [0.30.0](https://github.com/propeller-heads/protosim/compare/0.29.0...0.30.0) (2024-10-30)


### Features

* (VMPoolState) set and ensure capabilities ([c4d4bd2](https://github.com/propeller-heads/protosim/commit/c4d4bd23a443ecf209c3a3d0b8c3c1389c80a80f))

## [0.29.0](https://github.com/propeller-heads/protosim/compare/0.28.0...0.29.0) (2024-10-29)


### Features

* Add adapter_contract to EVMPoolState ([345ad1b](https://github.com/propeller-heads/protosim/commit/345ad1bc038acce1886c94997df2bdb15f9f7de9))


### Bug Fixes

* Convert to capabilities correctly ([71a1e22](https://github.com/propeller-heads/protosim/commit/71a1e22304185b58133b8f83944d4b5bc6c1ac77))
* Use KECCAK_EMPTY instead of code_hash: Default::default() ([629bd76](https://github.com/propeller-heads/protosim/commit/629bd76259345cdd4392a319341c4f3a81fd9edf))

## [0.28.0](https://github.com/propeller-heads/protosim/compare/0.27.0...0.28.0) (2024-10-29)


### Features

* (WIP) Implement update_engine ([4c18c89](https://github.com/propeller-heads/protosim/commit/4c18c89fb6de66e4b6c8579d7b97e93c9f90ec74))

## [0.27.0](https://github.com/propeller-heads/protosim/compare/0.26.0...0.27.0) (2024-10-28)


### Features

* (WIP) Implement set_engine ([47a500b](https://github.com/propeller-heads/protosim/commit/47a500b3b571aa7f98baeff6e42375fdb3ff83ec))
* Implement get_address_from_call ([c488e86](https://github.com/propeller-heads/protosim/commit/c488e862aea5b327645ba2ac22264d8b8b608b68))

## [0.26.0](https://github.com/propeller-heads/protosim/compare/0.25.0...0.26.0) (2024-10-28)


### Features

* AdapterContract new and encode method ([8e1cbde](https://github.com/propeller-heads/protosim/commit/8e1cbded5d77b1183b03427ebebc7d384588823b))
* Add call and simulate ([d0fa2b8](https://github.com/propeller-heads/protosim/commit/d0fa2b8022ec514302395715a916558300bc7f57))
* Add decode_output method ([39e6832](https://github.com/propeller-heads/protosim/commit/39e68327a4d466af997af758e4bd24aa5665b5b9))
* Implement ProtosimContract for adapter contract ([be59fa0](https://github.com/propeller-heads/protosim/commit/be59fa0f2da45bd64e81e2e26f19cf4ee9c6ba1c))


### Bug Fixes

* Add adapter_contract to mod ([c8f0646](https://github.com/propeller-heads/protosim/commit/c8f0646673ebf50bab7fafecd104e097a0c448a6))

## [0.25.0](https://github.com/propeller-heads/protosim/compare/0.24.0...0.25.0) (2024-10-25)


### Features

* implement create_engine ([4c3cd0c](https://github.com/propeller-heads/protosim/commit/4c3cd0cbb10dd81498862987a62e9cf06cd03e67))

## [0.24.0](https://github.com/propeller-heads/protosim/compare/0.23.1...0.24.0) (2024-10-24)


### Features

* create ERC20OverwriteFactory utils ([86457cf](https://github.com/propeller-heads/protosim/commit/86457cff9364b8a47cf8871d27d72997ef183be3))
* Update tycho version ([39fb025](https://github.com/propeller-heads/protosim/commit/39fb025285ff1e45efdea257c82788ce5030b4ea))


### Bug Fixes

* differentiate between SolidityError and InvalidResponse ([184ff45](https://github.com/propeller-heads/protosim/commit/184ff459a4f052b85e255f97e9e77f3504070b1e))
* maybe_coerce_error - change expected input and outputs ([43e0165](https://github.com/propeller-heads/protosim/commit/43e01651bfcdb41bba9a46722b716fda230da405))
* Propagate error upwards in get_geth_overwrites ([5af81da](https://github.com/propeller-heads/protosim/commit/5af81da2cb5b2a3334d09f3903a350ea463d6b80))
* Return SimulationError from maybe_coerce_error ([1354220](https://github.com/propeller-heads/protosim/commit/1354220ce244ae79272889d5d5222365eb6cfef3))
* use expect instead of unwrap (and readability fixes) ([b033fae](https://github.com/propeller-heads/protosim/commit/b033faea4f8c7b44fb656c0f23c6880344abac44))

## [0.23.1](https://github.com/propeller-heads/protosim/compare/0.23.0...0.23.1) (2024-10-21)


### Bug Fixes

* misc bugfixes in balance handling. ([bfadcc7](https://github.com/propeller-heads/protosim/commit/bfadcc735458540b5e314cc35742c177666610d2))

## [0.23.0](https://github.com/propeller-heads/protosim/compare/0.22.0...0.23.0) (2024-10-18)


### Features

* implement load_abi util function ([ee81b3c](https://github.com/propeller-heads/protosim/commit/ee81b3c0b5a357eee1129a8093056e342a100fc2))


### Bug Fixes

* return ethers::ebi::Abi from load_swap_abi ([2c18f68](https://github.com/propeller-heads/protosim/commit/2c18f6870a0d1c1232328e83a4c19d67e81be056))
* split into load_erc20_abi and load_swap_abi ([57d3415](https://github.com/propeller-heads/protosim/commit/57d3415d662afab902969544b2059963bb5b7d00))

## [0.22.0](https://github.com/propeller-heads/protosim/compare/0.21.0...0.22.0) (2024-10-17)


### Features

* implement get_code_for_address util function ([9b5e64a](https://github.com/propeller-heads/protosim/commit/9b5e64a28701195a3f1f04810033e98166cbbf7d))
* implement maybe_coerce_error utils function ([6c75b26](https://github.com/propeller-heads/protosim/commit/6c75b264b35f3b3c017af5fb3ac107534c64ee59))

## [0.21.0](https://github.com/propeller-heads/protosim/compare/0.20.0...0.21.0) (2024-10-17)


### Features

* Add ERC20 abi. ([232b966](https://github.com/propeller-heads/protosim/commit/232b9668ce22a06588199d157f1866f56cc3a483))
* Dynamically detect token storage slots when necessary ([d2dbc26](https://github.com/propeller-heads/protosim/commit/d2dbc269d37642f2a1676cb01ed1ce5dcc58d331))

## [0.20.0](https://github.com/propeller-heads/protosim/compare/0.19.0...0.20.0) (2024-10-10)


### Features

* Move graph (Protograph) into the NTQ src directory ([95f8e83](https://github.com/propeller-heads/protosim/commit/95f8e8367a190700ef9232dbe6fb428c90260a5e))

## [0.19.0](https://github.com/propeller-heads/protosim/compare/0.18.1...0.19.0) (2024-10-10)


### Features

* Don't use enum_dispatch in ProtocolSim ([e04375a](https://github.com/propeller-heads/protosim/commit/e04375a4915c19de12ead3aaabe46fa4dab5f2f2))


### Bug Fixes

* Support clone in DodoPoolState ([96f3595](https://github.com/propeller-heads/protosim/commit/96f35959e555f4b3b7d46f0024cd678f0ecb05d9))
* Use RwLock instead of RefCell in DodoPoolState ([8aa78b6](https://github.com/propeller-heads/protosim/commit/8aa78b683b00e37eeea14bb2883944811298fc90))

## [0.18.1](https://github.com/propeller-heads/protosim/compare/0.18.0...0.18.1) (2024-10-08)


### Bug Fixes

* remove spammy otel span ([a516478](https://github.com/propeller-heads/protosim/commit/a5164781446406fae493afbc827afa2cf7228c07))

## [0.18.0](https://github.com/propeller-heads/protosim/compare/0.17.0...0.18.0) (2024-10-07)


### Features

* **ntq:** Update tycho-client. ([f8df5bd](https://github.com/propeller-heads/protosim/commit/f8df5bd550a8dd78e52fc05d26a593c335d75bc9))

## [0.17.0](https://github.com/propeller-heads/protosim/compare/0.16.12...0.17.0) (2024-10-07)


### Features

* **ntq:** Update tycho-client for smoother startups ([7d3d7ca](https://github.com/propeller-heads/protosim/commit/7d3d7caa6b1d862ad06ad77457a7fcbaa751fbcb))

## [0.16.12](https://github.com/propeller-heads/protosim/compare/0.16.11...0.16.12) (2024-10-02)

## [0.16.11](https://github.com/propeller-heads/protosim/compare/0.16.10...0.16.11) (2024-10-01)


### Bug Fixes

* update tycho client ([98dcc8b](https://github.com/propeller-heads/protosim/commit/98dcc8b8d339f8d7bd96e6767c8ea856becd71c9))

## [0.16.10](https://github.com/propeller-heads/protosim/compare/0.16.9...0.16.10) (2024-09-30)


### Bug Fixes

* set token chunk size to the max (3000) ([9bea7c4](https://github.com/propeller-heads/protosim/commit/9bea7c47adf7a8c86589abe1d3f23133121f4997))

## [0.16.9](https://github.com/propeller-heads/protosim/compare/0.16.8...0.16.9) (2024-09-23)


### Bug Fixes

* add decode failed pools to skipped pools list ([cda7d15](https://github.com/propeller-heads/protosim/commit/cda7d154b3f308e93eb295859b16bd28f0d9ebb8))

## [0.16.8](https://github.com/propeller-heads/protosim/compare/0.16.7...0.16.8) (2024-09-18)


### Bug Fixes

* improve TTP snapshot decoding error logs ([dd80ab3](https://github.com/propeller-heads/protosim/commit/dd80ab3f4450538bc05d6c2708863438f01af371))

## [0.16.7](https://github.com/propeller-heads/protosim/compare/0.16.6...0.16.7) (2024-09-18)

## [0.16.6](https://github.com/propeller-heads/protosim/compare/0.16.5...0.16.6) (2024-09-17)


### Bug Fixes

* If gas is so expensive that sell_gas_cost_eth > quote_amount, don't calculate prices ([d94aaa2](https://github.com/propeller-heads/protosim/commit/d94aaa264e53612537db7188deb5d235da5bee1d))

## [0.16.5](https://github.com/propeller-heads/protosim/compare/0.16.4...0.16.5) (2024-09-17)


### Bug Fixes

* Use safe methods when calculating prices with gas ([e18130d](https://github.com/propeller-heads/protosim/commit/e18130d16737445cdd71fd78d1ca2f8d7cbdf924))

## [0.16.4](https://github.com/propeller-heads/protosim/compare/0.16.3...0.16.4) (2024-09-11)


### Bug Fixes

* **tycho-decoder:** fix typo in `pool.manual_updates` ([15e103a](https://github.com/propeller-heads/protosim/commit/15e103a6ce87ffb9d19420b3b03d83c695cc741b))

## [0.16.3](https://github.com/propeller-heads/protosim/compare/0.16.2...0.16.3) (2024-09-11)


### Bug Fixes

* ignored pools update ([99a498b](https://github.com/propeller-heads/protosim/commit/99a498b6c27190c2796672a67b73f36f2a46cd43))

## [0.16.2](https://github.com/propeller-heads/protosim/compare/0.16.1...0.16.2) (2024-09-11)


### Bug Fixes

* improve snapshot logs ([d233bce](https://github.com/propeller-heads/protosim/commit/d233bce49486c59be412cdb2c61ddeaee30f8cb4))

## [0.16.1](https://github.com/propeller-heads/protosim/compare/0.16.0...0.16.1) (2024-09-11)


### Bug Fixes

* skip applying deltas for ignored pools ([c00ccca](https://github.com/propeller-heads/protosim/commit/c00ccca5b4055ad13dfe716d8176059381d82d98))

## [0.16.0](https://github.com/propeller-heads/protosim/compare/0.15.0...0.16.0) (2024-09-11)


### Features

* Clear redis before inserting new prices and spreads ([17acac7](https://github.com/propeller-heads/protosim/commit/17acac7f7ad4d7c15eba6ae7ab593eb6e51f1965))

## [0.15.0](https://github.com/propeller-heads/protosim/compare/0.14.0...0.15.0) (2024-09-10)


### Features

* NTQv2 deduct gas from token price calc ([aceacd7](https://github.com/propeller-heads/protosim/commit/aceacd743de77cbaa6de80d36b0839f6a7125b81))


### Bug Fixes

* improve db singleton initialize logic ([03bc07e](https://github.com/propeller-heads/protosim/commit/03bc07e5377883dbb98fba9d7845743fddce79a3))
* initialize tycho db singleton on decoder init ([d47aba8](https://github.com/propeller-heads/protosim/commit/d47aba8c1066b3b7525e2e294b6089838feb53f8))
* NTQv2 move gas application to aggregator ([e877338](https://github.com/propeller-heads/protosim/commit/e877338b71a882d13b9109f93c709e686d9b6e27))

## [0.14.0](https://github.com/propeller-heads/protosim/compare/0.13.0...0.14.0) (2024-09-05)


### Features

* Add gas prices to NTQv2 ([5b8dfa6](https://github.com/propeller-heads/protosim/commit/5b8dfa66d7f5ebec7d6d1ff3cd0a27a431884c4c))

## [0.13.0](https://github.com/propeller-heads/protosim/compare/0.12.0...0.13.0) (2024-09-04)


### Features

* NTQv2 pass gas amount to price calculation ([3ca2bdd](https://github.com/propeller-heads/protosim/commit/3ca2bdd43c190e05a4deb6cafe488d1613ea65b6))

## [0.12.0](https://github.com/propeller-heads/protosim/compare/0.11.0...0.12.0) (2024-09-02)


### Features

* (NTQ) Add gas to ERC20Token object ([af0045f](https://github.com/propeller-heads/protosim/commit/af0045fb292befde461eaf452e8ff4e658213103))


### Bug Fixes

* NTQ gas - take min value of ERC20Token array ([820d971](https://github.com/propeller-heads/protosim/commit/820d9714a68e8cd2a7db35dbeca777f70fd2080e))

## [0.11.0](https://github.com/propeller-heads/protosim/compare/0.10.0...0.11.0) (2024-08-29)


### Features

* **py:** Expose Starknet structs publicly. ([41ad8fb](https://github.com/propeller-heads/protosim/commit/41ad8fbfeae2775112ae543873e91a053c44db88))

## [0.10.0](https://github.com/propeller-heads/protosim/compare/0.9.0...0.10.0) (2024-08-28)


### Features

* Add lowest_spread aggregator function ([aea341b](https://github.com/propeller-heads/protosim/commit/aea341bb8916808a41a18ca4c9f1c61481cfe433))

## [0.9.0](https://github.com/propeller-heads/protosim/compare/0.8.1...0.9.0) (2024-08-27)


### Features

* **decoder:** Make handling vm updates public. ([fe816a6](https://github.com/propeller-heads/protosim/commit/fe816a628e9a511681b0ee04486349ebba760538))

## [0.8.1](https://github.com/propeller-heads/protosim/compare/0.8.0...0.8.1) (2024-08-26)


### Bug Fixes

* Calculate mid price only with buy and sell prices from the same route ([d26f702](https://github.com/propeller-heads/protosim/commit/d26f702840be7333f67c202fd9685dc3d76be846))

## [0.8.0](https://github.com/propeller-heads/protosim/compare/0.7.0...0.8.0) (2024-08-22)


### Features

* Add console subscriber option to run locally ([be72eba](https://github.com/propeller-heads/protosim/commit/be72ebac9f28df64932833c9b5a845ad46b888cd))
* Instrument process routes ([0b2de5a](https://github.com/propeller-heads/protosim/commit/0b2de5af72e81867769431c6c29e61b9dadc0107))
* **traces:** Add open telemetry tracing ([c5309fa](https://github.com/propeller-heads/protosim/commit/c5309fa3bb712b56c3dc384e5e6c77b623a06fc8))


### Bug Fixes

* Stale prices ([376a1b7](https://github.com/propeller-heads/protosim/commit/376a1b7f75f367cfafd7dd6b1680a34982559cb5))
* Stale prices ([b1210b6](https://github.com/propeller-heads/protosim/commit/b1210b6447247f4ff9d77b0bc659e753ccee44ae))

## [0.7.0](https://github.com/propeller-heads/protosim/compare/0.6.3...0.7.0) (2024-08-16)


### Features

* update tycho-client to version 0.9.1 ([e43fa7a](https://github.com/propeller-heads/protosim/commit/e43fa7ac1e48c29fa880469a9aa65f3089d2bdbe))

## [0.6.3](https://github.com/propeller-heads/protosim/compare/0.6.2...0.6.3) (2024-08-16)


### Bug Fixes

* **ttp:** bump `tycho-indexer-client` version ([de1b723](https://github.com/propeller-heads/protosim/commit/de1b72318ae1b9d64ebc7775c2d1946fdf554d41))

## [0.6.2](https://github.com/propeller-heads/protosim/compare/0.6.1...0.6.2) (2024-08-15)


### Bug Fixes

* **ttp:** fix tycho-client import ([d8335b0](https://github.com/propeller-heads/protosim/commit/d8335b0b53410b695cc40c325ed176bf6be84fb9))

## [0.6.1](https://github.com/propeller-heads/protosim/compare/0.6.0...0.6.1) (2024-08-15)


### Bug Fixes

* dependecies looser requirments ([31230ea](https://github.com/propeller-heads/protosim/commit/31230eab8fcb81c3a39febd05cc8cf7efbfb6253))

## [0.6.0](https://github.com/propeller-heads/protosim/compare/0.5.5...0.6.0) (2024-08-15)


### Features

* **TTP:** Add logic to pull code for stateless contracts ([160abd4](https://github.com/propeller-heads/protosim/commit/160abd4979865d853ef1139306e2bfe6d7382ed0))
