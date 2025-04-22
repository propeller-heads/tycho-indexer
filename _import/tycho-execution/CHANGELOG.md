## [0.81.0](https://github.com/propeller-heads/tycho-execution/compare/0.80.0...0.81.0) (2025-04-18)


### Features

* update tycho-common version to 0.66.4 ([134c73e](https://github.com/propeller-heads/tycho-execution/commit/134c73e82be74fb5590e19c3d9b27304043bbbd8))


### Bug Fixes

* add slither disable after slither actions update ([20573cb](https://github.com/propeller-heads/tycho-execution/commit/20573cbaf320ba99aa721e6e76a69447ab3f9694))

## [0.80.0](https://github.com/propeller-heads/tycho-execution/compare/0.79.0...0.80.0) (2025-04-14)


### Features

* Redeploy balancer with forceApprove fix for USDT ([a6b0f8d](https://github.com/propeller-heads/tycho-execution/commit/a6b0f8d1f67a49848e90d2c4102195c4ac40c5a8))

## [0.79.0](https://github.com/propeller-heads/tycho-execution/compare/0.78.1...0.79.0) (2025-04-11)


### Features

* Add new CurveExecutor address ([916c2b7](https://github.com/propeller-heads/tycho-execution/commit/916c2b7dba2c1c424efcbf884932a05427816cf8))
* Deploy Curve Executor ([5d4d6d1](https://github.com/propeller-heads/tycho-execution/commit/5d4d6d1ff891766c067e3ff6355ffbb5c50bbf16))


### Bug Fixes

* Checksum curve pool addresses ([9e68ab8](https://github.com/propeller-heads/tycho-execution/commit/9e68ab8b0127831ee9dbc1f168e8aac9e28991c0))
* Support pools that hold ETH but the coin is WETH ([2e8392a](https://github.com/propeller-heads/tycho-execution/commit/2e8392ab40c6c0e99089fae71873755dedb6e925))
* Use forceApprove instead of regular Approve ([c963f3b](https://github.com/propeller-heads/tycho-execution/commit/c963f3b2f61e9d1a6e333149b091c3df90fd857b))

## [0.78.1](https://github.com/propeller-heads/tycho-execution/compare/0.78.0...0.78.1) (2025-04-09)


### Bug Fixes

* Curve factory addresses are utf-8 encoded ([ce71894](https://github.com/propeller-heads/tycho-execution/commit/ce7189423f90881cdaf9f8682d39fc47bfd1ce39))

## [0.78.0](https://github.com/propeller-heads/tycho-execution/compare/0.77.0...0.78.0) (2025-04-08)


### Features

* Add protocol_specific_addresses.json file ([739fb46](https://github.com/propeller-heads/tycho-execution/commit/739fb46d205251e39188afe983d8ce5ff3cb5d60))
* **curve:** Add CurveEncoder ([e9bb8c5](https://github.com/propeller-heads/tycho-execution/commit/e9bb8c576a96f3e523dc4e5011d48028cbc4d599))
* **curve:** Add integration test ([1e47d0e](https://github.com/propeller-heads/tycho-execution/commit/1e47d0e25b7906d73981a26d0d8b882a5820b61a))
* Support Curve ETH ([913d677](https://github.com/propeller-heads/tycho-execution/commit/913d677ffbfba61afae066a5a3d3c1f98e2a3f0f))


### Bug Fixes

* Add empty dicts for unichain and base in config ([c0b50c0](https://github.com/propeller-heads/tycho-execution/commit/c0b50c06616cf18c55cdbedf0196cda748a1a138))
* Fix Ekubo test ([1838ccf](https://github.com/propeller-heads/tycho-execution/commit/1838ccf8a17d518e174ad926a979bc9d9c151cbd))

## [0.77.0](https://github.com/propeller-heads/tycho-execution/compare/0.76.0...0.77.0) (2025-04-07)


### Features

* add curve executor with router tests ([7cde513](https://github.com/propeller-heads/tycho-execution/commit/7cde5130d6038916dcb4a6a96c723c366b90da12))
* allow executor to do native swaps, add diff pool type tests ([93bdc86](https://github.com/propeller-heads/tycho-execution/commit/93bdc86dc665e02d877bec1b749ee5cf7a399e32))
* Refactor Curve Executor not to use the router ([9f21842](https://github.com/propeller-heads/tycho-execution/commit/9f2184258aab968f7d83df8a443c1a77b87a3e4c))


### Bug Fixes

* fix slither CI action ([42d1ab3](https://github.com/propeller-heads/tycho-execution/commit/42d1ab36fd71af7a10d17120e5f14edce9f6422a))
* Improve curve executor tests and docstrings ([f468a78](https://github.com/propeller-heads/tycho-execution/commit/f468a7831a86eef96682504bc93207f33b28cf17))
* Remove unnecessary test method ([49aefc8](https://github.com/propeller-heads/tycho-execution/commit/49aefc8c2ab25864b4056f44738a96c3905f8396))
* resolve pr comments ([9e2a9f5](https://github.com/propeller-heads/tycho-execution/commit/9e2a9f5329f798990d4dde3e7e76af4896aef6f6))

## [0.76.0](https://github.com/propeller-heads/tycho-execution/compare/0.75.1...0.76.0) (2025-04-03)


### Features

* deploy Ekubo gas optimizations ([9012d7b](https://github.com/propeller-heads/tycho-execution/commit/9012d7b4d1745a3c5315d12c7c412d6e3267e4ba))

## [0.75.1](https://github.com/propeller-heads/tycho-execution/compare/0.75.0...0.75.1) (2025-04-03)


### Bug Fixes

* Proper ekubo protocol name in GROUPABLE_PROTOCOLS ([b4c687b](https://github.com/propeller-heads/tycho-execution/commit/b4c687bc3f51167fc942b8b7b00b17df4a2bec30))

## [0.75.0](https://github.com/propeller-heads/tycho-execution/compare/0.74.0...0.75.0) (2025-04-03)


### Features

* Unichain deployment ([d05e118](https://github.com/propeller-heads/tycho-execution/commit/d05e1183d4e85eb57c139b1fd5411833efea92fc))


### Bug Fixes

* Run foundry tests on PR branch (not main) ([43f1a07](https://github.com/propeller-heads/tycho-execution/commit/43f1a0701707d2dbf5bfa4f6ccde50aea48e46a1))
* Set native and wrapped tokens for Unichain ([4878229](https://github.com/propeller-heads/tycho-execution/commit/4878229e1d60a317b0f2d97ea57886e64cc70cb5))

## [0.74.0](https://github.com/propeller-heads/tycho-execution/compare/0.73.0...0.74.0) (2025-04-02)


### Features

* Fix rollFork usage for Ekubo test ([6cdca83](https://github.com/propeller-heads/tycho-execution/commit/6cdca8381e711bc01b7573dd25cafc9aa057aac3))


### Bug Fixes

* Fix tests after cherry picking ([5336969](https://github.com/propeller-heads/tycho-execution/commit/5336969df8b06238b65a9c9f1a3458f43b89cb54))

## [0.73.0](https://github.com/propeller-heads/tycho-execution/compare/0.72.0...0.73.0) (2025-04-02)


### Features

* Add router_address to cli ([1f6f1a4](https://github.com/propeller-heads/tycho-execution/commit/1f6f1a4236d577e57f50d063a81e9a1ed801a6dd))

## [0.72.0](https://github.com/propeller-heads/tycho-execution/compare/0.71.0...0.72.0) (2025-04-02)


### Features

* Make EncodingContext.router_address optional ([8865e22](https://github.com/propeller-heads/tycho-execution/commit/8865e22116dcb8c291caa745de78b4e6241315c8))
* Remove router_address from Solution, set default ([d5c589d](https://github.com/propeller-heads/tycho-execution/commit/d5c589d2c09da8e7f22b40be6e5b236e0eb16645))
* Support manual router address setting in builder ([c336a28](https://github.com/propeller-heads/tycho-execution/commit/c336a28905a1829da78997ea2126849fdabbcfc6))


### Bug Fixes

* fix Solution.router_address for Ekubo ([b397ddd](https://github.com/propeller-heads/tycho-execution/commit/b397ddd2beb007d0bed378949d35a9ce5c5b76c9))

## [0.71.0](https://github.com/propeller-heads/tycho-execution/compare/0.70.0...0.71.0) (2025-04-01)


### Features

* Update ekubo router address ([e3d25fc](https://github.com/propeller-heads/tycho-execution/commit/e3d25fcd5ed4e160fff10d5c346b12f0cb3328c6))


### Bug Fixes

* update ekubo_v2 executor ([57aa1c3](https://github.com/propeller-heads/tycho-execution/commit/57aa1c3402da976cfed38db2b46c584162cdbb69))

## [0.70.0](https://github.com/propeller-heads/tycho-execution/compare/0.69.0...0.70.0) (2025-03-31)


### Features

* Support Ekubo callback in TychoRouter ([b3078f9](https://github.com/propeller-heads/tycho-execution/commit/b3078f9c7b99b3c0c9f0008b97855b48483f06dc))


### Bug Fixes

* ekubo -> ekubo_v2 ([18fa0cc](https://github.com/propeller-heads/tycho-execution/commit/18fa0cc7adfaa46879aa3637c03563c770582b0d))
* ekubo -> ekubo_v2 ([6c35f11](https://github.com/propeller-heads/tycho-execution/commit/6c35f114e383b7ba93cb44d314a05f69ab15fadd))
* Finalize ekubo executor address ([c0068d4](https://github.com/propeller-heads/tycho-execution/commit/c0068d456bbd271d1c74797577e0fe514be0fcc7))
* support payCallback method for Ekubo ([7551612](https://github.com/propeller-heads/tycho-execution/commit/75516122e1a084f86c34e6eaaf43fe5f53a30d96))
* Take address for EkuboExecutor init ([c678f40](https://github.com/propeller-heads/tycho-execution/commit/c678f400571d1b001c98595f68d9a99e0cf4900d))
* test setup fix after rebase ([28f9f24](https://github.com/propeller-heads/tycho-execution/commit/28f9f244e6343393a96020a85f5e202012d7ca26))

## [0.69.0](https://github.com/propeller-heads/tycho-execution/compare/0.68.2...0.69.0) (2025-03-31)


### Features

* Add PancakeSwapV3 support to encoding ([fa024a4](https://github.com/propeller-heads/tycho-execution/commit/fa024a4a6702c7809af31a6ba392338d9368c6d2))
* Pancakeswap V3 support ([d582543](https://github.com/propeller-heads/tycho-execution/commit/d582543057665b737cc0aab5243ccc22db1f0a13))

## [0.68.2](https://github.com/propeller-heads/tycho-execution/compare/0.68.1...0.68.2) (2025-03-28)


### Bug Fixes

* fix for foundry tests external contributors ([a9ddb0e](https://github.com/propeller-heads/tycho-execution/commit/a9ddb0e6e9ef546f6e851c3056df5a55ee4dfa76))

## [0.68.1](https://github.com/propeller-heads/tycho-execution/compare/0.68.0...0.68.1) (2025-03-27)


### Bug Fixes

* Add crate metadata ([7e7fabf](https://github.com/propeller-heads/tycho-execution/commit/7e7fabf51bff842ab20c2f512e4f3a609a266e79))

## [0.68.0](https://github.com/propeller-heads/tycho-execution/compare/0.67.2...0.68.0) (2025-03-27)


### Features

* switch to tycho_commons ([0836bf7](https://github.com/propeller-heads/tycho-execution/commit/0836bf7d530f18a6c0f112542bcad16050e88afa))


### Bug Fixes

* Handle unichain chain id ([379858b](https://github.com/propeller-heads/tycho-execution/commit/379858bfca27eb5e8180a32351337779e625e0b5))

## [0.67.2](https://github.com/propeller-heads/tycho-execution/compare/0.67.1...0.67.2) (2025-03-27)


### Bug Fixes

* prepared lint workflow for external contributors ([9896f48](https://github.com/propeller-heads/tycho-execution/commit/9896f4882940517d61852300420c7c580138406f))
* prepared lint workflow for external contributors ([5162b9e](https://github.com/propeller-heads/tycho-execution/commit/5162b9e19efcaa5a2137f71a94f6f9e7f7d14da0))

## [0.67.1](https://github.com/propeller-heads/tycho-execution/compare/0.67.0...0.67.1) (2025-03-27)


### Bug Fixes

* added empty line ([b3c4dbc](https://github.com/propeller-heads/tycho-execution/commit/b3c4dbc293df758ff4cff949298a819436d83c38))
* fixed git checkout for codelint ([58e2ddd](https://github.com/propeller-heads/tycho-execution/commit/58e2ddd50e131c484ad53a6dca0b09e1d221d0e5))
* prepared lint workflow for external contributors ([9f7d605](https://github.com/propeller-heads/tycho-execution/commit/9f7d605ea5e76d230b5946c618ece76365fb4f02))
* removed empty line ([ae5d7de](https://github.com/propeller-heads/tycho-execution/commit/ae5d7deaccfc1ac527f88371bb3f055b01689801))
* test run outside a PR ([af01972](https://github.com/propeller-heads/tycho-execution/commit/af0197205adb3220673022b690f1d8aa6f6734aa))

## [0.67.0](https://github.com/propeller-heads/tycho-execution/compare/0.66.1...0.67.0) (2025-03-20)


### Features

* Set v2/v3 executor addresses on ethereum ([783712b](https://github.com/propeller-heads/tycho-execution/commit/783712be5d8dae626c735193416ba03701d3a616))
* Support Pancakeswap v3 on ethereum ([2a4ee88](https://github.com/propeller-heads/tycho-execution/commit/2a4ee88cad46dfeb068809bdd885e63094020bcd))
* Support sushiswap v2 and pancakeswap v2 on ethereum ([0a8a34b](https://github.com/propeller-heads/tycho-execution/commit/0a8a34be035588d45e6b72a42f4dd691e3c98d2f))


### Bug Fixes

* proper exchange name when deploying executors ([39bd9df](https://github.com/propeller-heads/tycho-execution/commit/39bd9df4b6ca8db78bb4d6757c93b30cce29f360))
* Remove pancakeswap V3 from approved executor addresses ([1ed149a](https://github.com/propeller-heads/tycho-execution/commit/1ed149a9b8ffd41b9cc702c77e146fa234176af0))

## [0.66.1](https://github.com/propeller-heads/tycho-execution/compare/0.66.0...0.66.1) (2025-03-19)


### Bug Fixes

* Slippage precision calculation ([d644b63](https://github.com/propeller-heads/tycho-execution/commit/d644b63851a63babadfb909af97c5bf80dd03376))

## [0.66.0](https://github.com/propeller-heads/tycho-execution/compare/0.65.1...0.66.0) (2025-03-14)


### Features

* Add check to don't support cyclical swaps with native actions ([27c9c53](https://github.com/propeller-heads/tycho-execution/commit/27c9c53889687b890bb4e4e01329f6a67ae7957c))
* Add validation for cyclical trades ([f62a9d2](https://github.com/propeller-heads/tycho-execution/commit/f62a9d28c0683490d841439d6a0543370d238387))


### Bug Fixes

* Add individual tests for each case ([e96bcdf](https://github.com/propeller-heads/tycho-execution/commit/e96bcdfd0f7f1951ef711efe8a3e45c5bb18fc8b))
* In test asset, use 0 for the last split, and not 0.5 ([0aba7ed](https://github.com/propeller-heads/tycho-execution/commit/0aba7edf830da0f0efaa465c8069484b62fb7a4d))

## [0.65.1](https://github.com/propeller-heads/tycho-execution/compare/0.65.0...0.65.1) (2025-03-13)


### Reverts

* Revert "feat: Add validation for cyclical trades" ([3d7dcef](https://github.com/propeller-heads/tycho-execution/commit/3d7dcef1bd01db283d787f0bc86b4e9cfc28bbaa))

## [0.65.0](https://github.com/propeller-heads/tycho-execution/compare/0.64.0...0.65.0) (2025-03-13)


### Features

* Add validation for cyclical trades ([55ffa4e](https://github.com/propeller-heads/tycho-execution/commit/55ffa4eb457ea8dd1ed57cdaac01f45880d34b0f))

## [0.64.0](https://github.com/propeller-heads/tycho-execution/compare/0.63.0...0.64.0) (2025-03-13)


### Features

* update tycho-core to 0.61.1 ([53b8c6a](https://github.com/propeller-heads/tycho-execution/commit/53b8c6afee6efdb2a878e2535a8daadfb29d91be))

## [0.63.0](https://github.com/propeller-heads/tycho-execution/compare/0.62.0...0.63.0) (2025-03-10)


### Features

* add cyclicSwapAmountOut tracker in _swap, add split cylic tests ([4d67df4](https://github.com/propeller-heads/tycho-execution/commit/4d67df40965414caff94f8660c70f4acad51482f))


### Bug Fixes

* amountConsumed check in _swapChecked for cyclic swap ([91f36fe](https://github.com/propeller-heads/tycho-execution/commit/91f36fe3285ae4e3e010b9138e8226e257f8499c))
* remove amountIn addition to amountOut in _swap for cyclic swaps, add testCyclicSwapWithTwoPools test to verify ([57acbd5](https://github.com/propeller-heads/tycho-execution/commit/57acbd58c5146c88098e9bc274ec702ef25add32))

## [0.62.0](https://github.com/propeller-heads/tycho-execution/compare/0.61.0...0.62.0) (2025-03-06)


### Features

* enforce checked amount when encoding to router ([a4476e0](https://github.com/propeller-heads/tycho-execution/commit/a4476e0a17179205e795236368c2ffe3959f56e2))

## [0.61.0](https://github.com/propeller-heads/tycho-execution/compare/0.60.0...0.61.0) (2025-03-05)


### Features

* Rename Etherscan in deployment verification ([bc54eac](https://github.com/propeller-heads/tycho-execution/commit/bc54eac110c6777d48dede7d0f91d7f580412ebf))

## [0.60.0](https://github.com/propeller-heads/tycho-execution/compare/0.59.0...0.60.0) (2025-03-05)


### Features

* Check min amount out is not zero ([5c28d77](https://github.com/propeller-heads/tycho-execution/commit/5c28d77f1d92bb7fba5fa7495e77fcbb5e077eb8))

## [0.59.0](https://github.com/propeller-heads/tycho-execution/compare/0.58.2...0.59.0) (2025-03-05)


### Features

* add transferFrom in swap and move core swap logic inside _swapChecked ([f853739](https://github.com/propeller-heads/tycho-execution/commit/f853739a3dafb57dc12c77d97a30703a6d65445a))


### Bug Fixes

* TychoRouter swap check test naming and docs ([7833086](https://github.com/propeller-heads/tycho-execution/commit/783308642524cf917b9870188707318959407a10))

## [0.58.2](https://github.com/propeller-heads/tycho-execution/compare/0.58.1...0.58.2) (2025-03-05)


### Bug Fixes

* Make permit2 permit an action in the universal router ([db9c8cd](https://github.com/propeller-heads/tycho-execution/commit/db9c8cde5aaa6cb32dbe74df228fb65d358687a3))

## [0.58.1](https://github.com/propeller-heads/tycho-execution/compare/0.58.0...0.58.1) (2025-03-04)


### Bug Fixes

* add amountIn in error TychoRouter__AmountInDiffersFromConsumed ([a3bffd4](https://github.com/propeller-heads/tycho-execution/commit/a3bffd4f75e8644997970a45c6a8f2b896a30394))
* inequality check for amountConsumed and amountIn ([6f421eb](https://github.com/propeller-heads/tycho-execution/commit/6f421eb374b798e9521a2a345558fae53f77dae3))

## [0.58.0](https://github.com/propeller-heads/tycho-execution/compare/0.57.0...0.58.0) (2025-03-03)


### Features

* Rename ETH_RPC_URL -> RPC_URL ([9bb0d9b](https://github.com/propeller-heads/tycho-execution/commit/9bb0d9bc8495f4fff9006d9ed7e353042c023c9c))

## [0.57.0](https://github.com/propeller-heads/tycho-execution/compare/0.56.0...0.57.0) (2025-03-03)


### Features

* Rename shortcut methods of encoder builder ([6f572ee](https://github.com/propeller-heads/tycho-execution/commit/6f572eed01552f4a43181187cfef0c49d0fd9d80))

## [0.56.0](https://github.com/propeller-heads/tycho-execution/compare/0.55.0...0.56.0) (2025-02-28)


### Features

* update base executor addresses ([bc47c12](https://github.com/propeller-heads/tycho-execution/commit/bc47c12a1a8cae0b9464b4899b52369e5036c9f7))


### Bug Fixes

* make USV2 factory configurable in Executor ([33973a6](https://github.com/propeller-heads/tycho-execution/commit/33973a65b8486c2c78e68c6a35374bd35775a7e5))

## [0.55.0](https://github.com/propeller-heads/tycho-execution/compare/0.54.0...0.55.0) (2025-02-27)


### Features

* Change license to SPDX-License-Identifier: UNLICENSED everywhere ([59eb219](https://github.com/propeller-heads/tycho-execution/commit/59eb2195b60280bfba9f07b55bf0d7bc973ad23f))
* Deploy to mainnet (again) ([fedc504](https://github.com/propeller-heads/tycho-execution/commit/fedc5043db71cbe77fc5222124072eaecf8e5119))
* Deploy to mainnet. Update all addresses ([3d65ac8](https://github.com/propeller-heads/tycho-execution/commit/3d65ac8cd95cd8b63427d10ae660925c18adb7fa))
* Verify contracts on etherscan ([79045e2](https://github.com/propeller-heads/tycho-execution/commit/79045e26897f067cf5e573a61643f4271f9a664b))

## [0.54.0](https://github.com/propeller-heads/tycho-execution/compare/0.53.1...0.54.0) (2025-02-27)


### Features

* Deploy all executors ([f95c74f](https://github.com/propeller-heads/tycho-execution/commit/f95c74fbc67b32e65617691fc07f015878be324b))


### Bug Fixes

* Add a value to the Transaction if token in is ETH ([05a1843](https://github.com/propeller-heads/tycho-execution/commit/05a1843f9c3f916d4af8fbf67cccf3b3b94aeab8))
* Get correct runtime everywhere ([6a6f2d3](https://github.com/propeller-heads/tycho-execution/commit/6a6f2d322102c71a13f3fab5b9b1ef406af1fbbc))
* the key for univ4 fee is key_lp_fee ([9eb4299](https://github.com/propeller-heads/tycho-execution/commit/9eb4299ffe4561f7f9d24e8a09a78b376b62889b))

## [0.53.1](https://github.com/propeller-heads/tycho-execution/compare/0.53.0...0.53.1) (2025-02-27)


### Bug Fixes

* remove 0 amount check in _unwrapEth ([0273f58](https://github.com/propeller-heads/tycho-execution/commit/0273f5827462f6f6cadb5b7e78ae7c1d0bfd2e29))

## [0.53.0](https://github.com/propeller-heads/tycho-execution/compare/0.52.2...0.53.0) (2025-02-26)


### Features

* support base deployment ([7ca9120](https://github.com/propeller-heads/tycho-execution/commit/7ca9120b7b1feb4704b625077a6be34ea1c1a8f1))


### Bug Fixes

* (deployment) add tenderly keys to json files ([1bdcbb8](https://github.com/propeller-heads/tycho-execution/commit/1bdcbb83e089c012dde3a33f159653a004c43c1d))
* proper executor address json after merge ([adfcb3d](https://github.com/propeller-heads/tycho-execution/commit/adfcb3da82564282e5eb311a1504be9f64ce1237))
* rename mainnet -> ethereum ([ac35256](https://github.com/propeller-heads/tycho-execution/commit/ac35256c6961b8f8783b8461302594aaeb0eaa95))
* TENDERLY_RPC_URL -> RPC_URL ([e5759b9](https://github.com/propeller-heads/tycho-execution/commit/e5759b94984772078d9324dcce2eaced0d6cc377))

## [0.52.2](https://github.com/propeller-heads/tycho-execution/compare/0.52.1...0.52.2) (2025-02-26)

## [0.52.1](https://github.com/propeller-heads/tycho-execution/compare/0.52.0...0.52.1) (2025-02-26)

## [0.52.0](https://github.com/propeller-heads/tycho-execution/compare/0.51.2...0.52.0) (2025-02-26)


### Features

* Add deployment and fund wallet scripts ([cbea0bd](https://github.com/propeller-heads/tycho-execution/commit/cbea0bdab380ef92b7cf170f7734b0039f21725c))
* Deploy executors and set them in router ([02a9da1](https://github.com/propeller-heads/tycho-execution/commit/02a9da183e74fe0d5e20e4cf9493398931c2735e))
* Deploy on mainnet ([34563c3](https://github.com/propeller-heads/tycho-execution/commit/34563c3eb7f353391344bf36de5e8ee6bc766a3c))
* Set roles script ([90cf194](https://github.com/propeller-heads/tycho-execution/commit/90cf19486967752bed0775d524034f499a03baf6))
* Verify router contract on tenderly ([77ba949](https://github.com/propeller-heads/tycho-execution/commit/77ba9498a75b9724ed5f4bdfb22626d8e62e04e4))


### Bug Fixes

* Unify both executor addresses in one file ([57789a4](https://github.com/propeller-heads/tycho-execution/commit/57789a40e43f3a4092a4754704a8798e4d06c060))

## [0.51.2](https://github.com/propeller-heads/tycho-execution/compare/0.51.1...0.51.2) (2025-02-26)


### Bug Fixes

* Restrict receive callers to have code ([801976f](https://github.com/propeller-heads/tycho-execution/commit/801976fafab6d28395f738ba7971e927a3743e9d))

## [0.51.1](https://github.com/propeller-heads/tycho-execution/compare/0.51.0...0.51.1) (2025-02-25)

## [0.51.0](https://github.com/propeller-heads/tycho-execution/compare/0.50.0...0.51.0) (2025-02-24)


### Features

* hardcode callback and swap selection in dispatcher ([58116e0](https://github.com/propeller-heads/tycho-execution/commit/58116e074acbe5830771eb6491becff58cc9f5a7))
* rm selector from usv3, usv4, update tests, and rename dispatcher file ([69745b1](https://github.com/propeller-heads/tycho-execution/commit/69745b18fdbb4cab8a8fce1d4cf872720358db92))


### Bug Fixes

* usv4 integration tests and remove selector from swap/strategy encoder ([18efe03](https://github.com/propeller-heads/tycho-execution/commit/18efe0305b763b1ea5037536cd54734b58778fd2))

## [0.50.0](https://github.com/propeller-heads/tycho-execution/compare/0.49.0...0.50.0) (2025-02-22)


### Features

* add target verification for usv2 and usv3  using _computePairAddress ([7936ba1](https://github.com/propeller-heads/tycho-execution/commit/7936ba1c943a616a143dc6f8ecb1da61073b05a8))

## [0.49.0](https://github.com/propeller-heads/tycho-execution/compare/0.48.1...0.49.0) (2025-02-21)


### Features

* Use openzepplin's sendValue instead of send for ETH transfers ([0ba5d02](https://github.com/propeller-heads/tycho-execution/commit/0ba5d02268e42e10ab9a7d4390eb87dfd7099f07))

## [0.48.1](https://github.com/propeller-heads/tycho-execution/compare/0.48.0...0.48.1) (2025-02-21)


### Bug Fixes

* Native ETH input/output integration tests/fixes ([a7aa4d7](https://github.com/propeller-heads/tycho-execution/commit/a7aa4d7ebb956ec290b5853245f0e1f0077d708a))

## [0.48.0](https://github.com/propeller-heads/tycho-execution/compare/0.47.0...0.48.0) (2025-02-21)


### Features

* Adapt SplitSwapStrategyEncoder to have optional permit2 logic ([20e6419](https://github.com/propeller-heads/tycho-execution/commit/20e6419a208965e4d80e3d36455bd39078fe613b))
* Implement Clone for EVMTychoEncoder ([8b2af4f](https://github.com/propeller-heads/tycho-execution/commit/8b2af4f5775a14fd508c6660e43c541e9faeeb0d))
* Update tycho-core ([c6c734d](https://github.com/propeller-heads/tycho-execution/commit/c6c734d4940303f862b7b0275d57a87e4ef81d56))

## [0.47.0](https://github.com/propeller-heads/tycho-execution/compare/0.46.1...0.47.0) (2025-02-20)


### Features

* Don't encode min amount for USV4 ([d65d575](https://github.com/propeller-heads/tycho-execution/commit/d65d575003f67347110c70e2dabe6a9cc83fd712))
* UniswapV4 integration test and fixes ([45fdfc7](https://github.com/propeller-heads/tycho-execution/commit/45fdfc708d87ca81f9d92c649b4a7e58c254bc4e))


### Bug Fixes

* Pass proper group tokens in EncodingContext... ([81c8a04](https://github.com/propeller-heads/tycho-execution/commit/81c8a04cbb4f6f4c758ca782349d6ac2f6b79355))

## [0.46.1](https://github.com/propeller-heads/tycho-execution/compare/0.46.0...0.46.1) (2025-02-20)

## [0.46.0](https://github.com/propeller-heads/tycho-execution/compare/0.45.0...0.46.0) (2025-02-20)


### Features

* add native and weth addresses for supported networks ([83f1955](https://github.com/propeller-heads/tycho-execution/commit/83f1955094693420cd6bf94ff47f145d25ff6624))


### Bug Fixes

* add decode_hex to models ([7dd59db](https://github.com/propeller-heads/tycho-execution/commit/7dd59dbe3450ad15b4dc7eb4478b0422c18a6575))

## [0.45.0](https://github.com/propeller-heads/tycho-execution/compare/0.44.0...0.45.0) (2025-02-20)


### Features

* TychoRouter swap method not requiring Permit2 ([c3482a5](https://github.com/propeller-heads/tycho-execution/commit/c3482a509a52be7b7e0c9c9f4bc0a08a16f98728))

## [0.44.0](https://github.com/propeller-heads/tycho-execution/compare/0.43.0...0.44.0) (2025-02-19)


### Features

* add integration test for complex swaps ([5e9b388](https://github.com/propeller-heads/tycho-execution/commit/5e9b38876e974aa9f2e62ebf754237a57fca28eb))
* add new attributes in encoding context, update usv4 swap encoder and tests ([1bfe656](https://github.com/propeller-heads/tycho-execution/commit/1bfe656e6b1279482116be5ffddd81f83c0c381e))
* add single swap integration test for usv4 executor ([529456f](https://github.com/propeller-heads/tycho-execution/commit/529456f40cee3e555090d7defdf50c9c341e6c50))
* add usv4 swap encoder with single swap test ([789416b](https://github.com/propeller-heads/tycho-execution/commit/789416b2cd8f3cd9844bf2848768ea5bd7f3f6e3))
* add util fns, change callback_selector to string, update first_swap check ([9219dd3](https://github.com/propeller-heads/tycho-execution/commit/9219dd329d5d38b8c51b40aa5664e5120c3b6dcd))
* early return in usv4 swap encoder for second swap, add utils ([f7ddace](https://github.com/propeller-heads/tycho-execution/commit/f7ddace5591fcee3425c138b031de321fb8336ef))
* update test_encode_uniswap_v4_grouped ([baeebb9](https://github.com/propeller-heads/tycho-execution/commit/baeebb9fe4d1df4db06aa3ce9606a59f6b12552d))


### Bug Fixes

* update EncodingContext in strategy_encoder ([7f3aca9](https://github.com/propeller-heads/tycho-execution/commit/7f3aca90ba20ec68fa6f3ba3267aa87cb2540d70))

## [0.43.0](https://github.com/propeller-heads/tycho-execution/compare/0.42.0...0.43.0) (2025-02-19)


### Features

* Add methods to builder to set chain and strategy independently ([684de4f](https://github.com/propeller-heads/tycho-execution/commit/684de4fa6006400c2511f58fbd407758cbda7b52))
* Create a EVMEncoderBuilder ([03506fa](https://github.com/propeller-heads/tycho-execution/commit/03506fabe90c00f1518e42243fd650fb561e2a39))
* Remove direct_execution from Solution ([8537d27](https://github.com/propeller-heads/tycho-execution/commit/8537d274692aabf45a1ce79ded6c40998ba6fc50))


### Bug Fixes

* After rebase fixes ([4f29022](https://github.com/propeller-heads/tycho-execution/commit/4f29022c42af0b598916df6af80ec9c64a09f6c9))
* After rebase fixes ([30b5ab9](https://github.com/propeller-heads/tycho-execution/commit/30b5ab9025ae3292e4977f1ed10ceac4850d7669))

## [0.42.0](https://github.com/propeller-heads/tycho-execution/compare/0.41.0...0.42.0) (2025-02-19)


### Features

* Support swap grouping for executor strategy ([ac83117](https://github.com/propeller-heads/tycho-execution/commit/ac831176d461221d0bb0ae6e9145d8ccfc27761f))

## [0.41.0](https://github.com/propeller-heads/tycho-execution/compare/0.40.0...0.41.0) (2025-02-18)


### Features

* add back uniswapV3SwapCallback in router ([260f9d8](https://github.com/propeller-heads/tycho-execution/commit/260f9d866f9cd58d0739e24e6abcd08cb3ad4a45))
* add uniswapV3SwapCallback in USV3 executor ([9d3b96f](https://github.com/propeller-heads/tycho-execution/commit/9d3b96f997d3295c14fd356211b66b4c308f0288))
* Change signature of _handleCallback to take only bytes calldata ([2aa63d7](https://github.com/propeller-heads/tycho-execution/commit/2aa63d7ec0f9a74e70f258d2861b84825b35dcfd))
* fix input decoding in usv3 executor and execution dispatcher ([80500e6](https://github.com/propeller-heads/tycho-execution/commit/80500e615eedbd3a2b075104787e817b1a1ec42f))
* move callback testing to usv3 executor ([5853de6](https://github.com/propeller-heads/tycho-execution/commit/5853de679ad0182ce75467245054d28b916d518f))
* rename execution dispatcher to dispatcher and use dispatcher for USV4 callback ([ad91e48](https://github.com/propeller-heads/tycho-execution/commit/ad91e485d3a7b125f4db39cb84bb504f2d6064cf))
* update _handleCallback, add verifyCallback with docs ([076586d](https://github.com/propeller-heads/tycho-execution/commit/076586d77672faf1a02b20c69ea1de4ec8e6ae55))
* update handleCallback in USV3 to do verification ([cccb252](https://github.com/propeller-heads/tycho-execution/commit/cccb252bf2194af55b983f73815edb0cf1782776))
* update new interface in codebase ([bd19713](https://github.com/propeller-heads/tycho-execution/commit/bd1971334e61a128f8454d96df48889374749203))

## [0.40.0](https://github.com/propeller-heads/tycho-execution/compare/0.39.0...0.40.0) (2025-02-18)


### Features

* (WIP) UniswapV4 encoding ([f32210b](https://github.com/propeller-heads/tycho-execution/commit/f32210bb1f6103a1775975604415295260de9107))
* Generalize group_swaps method ([47b6180](https://github.com/propeller-heads/tycho-execution/commit/47b61802eef58068d1188c25db86974c7e03f3a8))
* Merge USV4 strategy back into split strategy ([44aabf1](https://github.com/propeller-heads/tycho-execution/commit/44aabf17612994fa126cfdfa4ef7f043b825aeee))


### Bug Fixes

* Do not count intermediary tokens in indices ([e94154b](https://github.com/propeller-heads/tycho-execution/commit/e94154bc2d72c312d07eb1aa73a0fd96214ad288))
* Do not group split swaps ([957bf89](https://github.com/propeller-heads/tycho-execution/commit/957bf898f28a23dd451d8a0ab07eb221dec1dc11))

## [0.39.0](https://github.com/propeller-heads/tycho-execution/compare/0.38.0...0.39.0) (2025-02-14)


### Features

* **univ4:** Implement swapping with multiple hops ([21a8c1a](https://github.com/propeller-heads/tycho-execution/commit/21a8c1a27a8370bf7471b206e78b6a2fcf38ce00))
* **univ4:** Refactor input and handle single swap case ([be7883a](https://github.com/propeller-heads/tycho-execution/commit/be7883affc2e481fce76dcd762215efb83905478))


### Bug Fixes

* Fix PLE tests that break after foundry update ([69d03f0](https://github.com/propeller-heads/tycho-execution/commit/69d03f060872bf9cce313f2420dc95c6d7554dec))
* **univ4:** Append callback data instead of prepending ([4d0f5ce](https://github.com/propeller-heads/tycho-execution/commit/4d0f5cec64af9c65f5a03685d4c89bb0dd0a897c))
* **univ4:** Make slither happy ([8a8bc69](https://github.com/propeller-heads/tycho-execution/commit/8a8bc697eb68308aedf74bd605d2f555328df99c))

## [0.38.0](https://github.com/propeller-heads/tycho-execution/compare/0.37.0...0.38.0) (2025-02-13)


### Features

* Add a production foundry profile ([dae38ce](https://github.com/propeller-heads/tycho-execution/commit/dae38ceaf9b407d3ee93535ea0032804cbca9d59))
* Support uniswap v4 callback in TychoRouter ([591d73b](https://github.com/propeller-heads/tycho-execution/commit/591d73ba717deb1773f5c10f9085cc1175df2536))


### Bug Fixes

* Verify that the executor exists in the uni v4 callback ([4c5e3bf](https://github.com/propeller-heads/tycho-execution/commit/4c5e3bf6a9070878c684ae8d029451178201d428))

## [0.37.0](https://github.com/propeller-heads/tycho-execution/compare/0.36.2...0.37.0) (2025-02-12)


### Features

* add callback ([ed90cb4](https://github.com/propeller-heads/tycho-execution/commit/ed90cb4ef1d43e09a7cd6f824ef4214598851b9f))
* add new pair test ([7ca647f](https://github.com/propeller-heads/tycho-execution/commit/7ca647f009ad8cb71c6e8a08e64ee02285c9ae08))
* add router params ([e62c332](https://github.com/propeller-heads/tycho-execution/commit/e62c332451d7cf0d2fc471faa7af7b26fd1a000d))
* add test for UniswapV4Executor ([4599f07](https://github.com/propeller-heads/tycho-execution/commit/4599f07df0d4c4131f87cd41ec7bcb8b1dd47bde))
* add univ4 executor ([cb4c8f4](https://github.com/propeller-heads/tycho-execution/commit/cb4c8f4e51d4f1900149288339c6a6fc75a515b1))
* handle amounts in unlockCallback ([b2097ca](https://github.com/propeller-heads/tycho-execution/commit/b2097ca4a5600161166636c7f2b58f845540ed9a))
* move encoding to test ([c264084](https://github.com/propeller-heads/tycho-execution/commit/c264084783561b3de4eeac413ed6155076ff11d5))
* support multi swap decoding ([d998c88](https://github.com/propeller-heads/tycho-execution/commit/d998c88cfef300e41714c6c3c6164e761d14e2de))
* update solc and add V4Router into UniswapV4Executor ([bdd3daf](https://github.com/propeller-heads/tycho-execution/commit/bdd3daffba3853ad084f7d3454e3c72fd6a1679c))


### Bug Fixes

* _pay and msgSender ([d790682](https://github.com/propeller-heads/tycho-execution/commit/d79068282aebd1e65ae32e79ec3127da25f091af))
* add equality check, amountInOrOut check, update _decodeData ([b47cff3](https://github.com/propeller-heads/tycho-execution/commit/b47cff3fc915b8146d62b085a7a5239d85d9d993))
* git submodules and strict equality check in v4 executor ([a8cc84d](https://github.com/propeller-heads/tycho-execution/commit/a8cc84ddce7c90aa40d69090577ef15cc95d8edf))
* handle native token balance changes ([0c40e9e](https://github.com/propeller-heads/tycho-execution/commit/0c40e9e97923d5bad61aa812ba739c2fe4260cf8))
* reciever issue ([ae0b07b](https://github.com/propeller-heads/tycho-execution/commit/ae0b07b2a47b93430841ce8bf437215d2f94e3bb))
* remove executeActions wrapper, strict equality checks and rename swap return ([2371ab2](https://github.com/propeller-heads/tycho-execution/commit/2371ab2a1fb96164a54c796cb0557d64e50c2350))
* remove extra _receiver and redundant asserts ([ff3209b](https://github.com/propeller-heads/tycho-execution/commit/ff3209b1c861c015568c3daa691f74d95ef0c978))
* rm callback fn ([1a36c33](https://github.com/propeller-heads/tycho-execution/commit/1a36c33bc614d744cfa161dd85d6cccc671e592e))
* rm redundant transfer ([24d4e76](https://github.com/propeller-heads/tycho-execution/commit/24d4e762a2841909245d7a4434c13f37398ae482))

## [0.36.2](https://github.com/propeller-heads/tycho-execution/compare/0.36.1...0.36.2) (2025-02-12)


### Bug Fixes

* Miscellaneous audit remarks ([582533f](https://github.com/propeller-heads/tycho-execution/commit/582533fa31b1c2096566df00b7e07350f677a647))

## [0.36.1](https://github.com/propeller-heads/tycho-execution/compare/0.36.0...0.36.1) (2025-02-11)

## [0.36.0](https://github.com/propeller-heads/tycho-execution/compare/0.35.1...0.36.0) (2025-02-11)


### Features

* Add selector to Transaction ([dd7ecac](https://github.com/propeller-heads/tycho-execution/commit/dd7ecac324f272385acb3717ef12a163f4958ac2))

## [0.35.1](https://github.com/propeller-heads/tycho-execution/compare/0.35.0...0.35.1) (2025-02-11)


### Bug Fixes

* (TychoRouter) Revert if empty swaps ([37efe52](https://github.com/propeller-heads/tycho-execution/commit/37efe52c10ea9028f735c3cfc15af0bc9c57a745))

## [0.35.0](https://github.com/propeller-heads/tycho-execution/compare/0.34.0...0.35.0) (2025-02-07)


### Features

* Add clone to EVMTychoEncoder ([b333d60](https://github.com/propeller-heads/tycho-execution/commit/b333d60d69ffc37d45d065494902161462e52ada))
* Add uniswap v3 to swap encoders list ([c791c93](https://github.com/propeller-heads/tycho-execution/commit/c791c93cb5ea0c39de46338c45f5575f30215189))
* Get current runtime if there is any ([12f85cc](https://github.com/propeller-heads/tycho-execution/commit/12f85ccc0a4e5e30f06a4dd3db514c5cf5f91ba0))
* Increase tycho-core version ([6bbb6da](https://github.com/propeller-heads/tycho-execution/commit/6bbb6da1cdb24e8e1c280aa176941cb01c467219))
* Make executors_file_path optional and use a default value if None ([4680a4b](https://github.com/propeller-heads/tycho-execution/commit/4680a4be2429ab90bcb440fb1f57105f4f244360))
* Read default executors at compile time into a json ([f5232f4](https://github.com/propeller-heads/tycho-execution/commit/f5232f403ee8f09c3bf83be865e326540b781740))
* Remove router_address from TychoEncoder ([a234ff7](https://github.com/propeller-heads/tycho-execution/commit/a234ff701f8be8a3ad28630035cfe474a4702ad5))
* The execution structs should receiver tycho_core Chain ([cad9f39](https://github.com/propeller-heads/tycho-execution/commit/cad9f394cdbd22850417b09a1f590ee41245946a))
* Use block_in_place instead of block_on ([d4af59d](https://github.com/propeller-heads/tycho-execution/commit/d4af59d4dca83547d208e8d87ddc56b16153e64b))


### Bug Fixes

* After rebase fixes ([bef4740](https://github.com/propeller-heads/tycho-execution/commit/bef4740a1d22312ed5745ce5e0199f919c784962))
* Change version of serde to match tycho-simulation ([3116fef](https://github.com/propeller-heads/tycho-execution/commit/3116fef0d785ecae3cbd2b6c747036cd11ca331e))
* Don't have a DEFAULT_CONFIG_PATH in bin ([d7f20aa](https://github.com/propeller-heads/tycho-execution/commit/d7f20aa74fdae67b096aebb376ca8d11cb72c930))
* Uniswap v3 pool fee is big endian, not little endian ([0c9050c](https://github.com/propeller-heads/tycho-execution/commit/0c9050cf79e78d26ca098d945f3380e73f689455))
* **univ3:** The fee keyword is just "fee" and not "pool_fee" ([164d062](https://github.com/propeller-heads/tycho-execution/commit/164d062ad9ceb9ceb7ec26e0253d62972fc967cc))

## [0.34.0](https://github.com/propeller-heads/tycho-execution/compare/0.33.0...0.34.0) (2025-02-06)


### Features

* add default private key ([d3ad0ba](https://github.com/propeller-heads/tycho-execution/commit/d3ad0ba5bfd50cc3db50b8d341fca2c1c5fcdad3))
* add encoder bin ([4f7fe3b](https://github.com/propeller-heads/tycho-execution/commit/4f7fe3b96d767c5df3757607777f3caec0d61d5b))
* add md ([d3be9d1](https://github.com/propeller-heads/tycho-execution/commit/d3be9d1489121522333253ce9f420865f59fdf6a))
* add serde primitive, update command ([b938560](https://github.com/propeller-heads/tycho-execution/commit/b93856073cad79564190a43007f33a2cf4f3dbd7))
* default native action ([80f1ca9](https://github.com/propeller-heads/tycho-execution/commit/80f1ca913b9ca74f6dd3739d9472533dcda59892))
* remove direct execution hardcode ([ae6b1ed](https://github.com/propeller-heads/tycho-execution/commit/ae6b1ed658721a067d55e5b64e3a93b15f2b66af))
* remove manual parsing ([fd4045e](https://github.com/propeller-heads/tycho-execution/commit/fd4045e6fe9c2379df2c278282db1e26e4b83c20))
* simplify ([8d97f73](https://github.com/propeller-heads/tycho-execution/commit/8d97f73ec7f034fa84908eec41087f3212520b33))
* update cli params and docs ([32c3bd2](https://github.com/propeller-heads/tycho-execution/commit/32c3bd22202c250d9c7de4d971e39ef7169c02a6))
* use clap for cli and resolve pr comments ([a5166f2](https://github.com/propeller-heads/tycho-execution/commit/a5166f282dfbcd6c161a84dee7b9dac0efe01ba3))


### Bug Fixes

* chain.into() ([520bee5](https://github.com/propeller-heads/tycho-execution/commit/520bee5a5d8d383cdca99c96d41022183827ffb0))
* ci ([a3cf443](https://github.com/propeller-heads/tycho-execution/commit/a3cf4430563f88490a62a7e7a0051c3c64ea6d81))
* ci ([6cec83f](https://github.com/propeller-heads/tycho-execution/commit/6cec83fde57e64405499e2343179bf4bd2a40820))
* fmt ([3bb5b0c](https://github.com/propeller-heads/tycho-execution/commit/3bb5b0c7c69179c8b087bc42bbd722bda5cc89a7))
* fmt ([7df1995](https://github.com/propeller-heads/tycho-execution/commit/7df1995655e55f1ad62a32c265ba1fd7174562db))
* remove redundant parse checks ([c4f9fd0](https://github.com/propeller-heads/tycho-execution/commit/c4f9fd0fa6e1ee4d32ec0cd7e4d833f18681eec1))
* rm v4-core ([1dad36d](https://github.com/propeller-heads/tycho-execution/commit/1dad36d7a84120aecfcb0867c9733c12efb72fe6))

## [0.33.0](https://github.com/propeller-heads/tycho-execution/compare/0.32.0...0.33.0) (2025-02-06)


### Features

* Get native/wrapped addresses from chain ([8cd7d9f](https://github.com/propeller-heads/tycho-execution/commit/8cd7d9f76e0b68bbf71f61bc56ab60a5e5693327))
* Take Chain object containing native/wrapped addresses ([e83b8d9](https://github.com/propeller-heads/tycho-execution/commit/e83b8d9aef130839dd88355e110172e1377bad80))


### Bug Fixes

* Do not let user specify the native/wrapped token ([1a07c7d](https://github.com/propeller-heads/tycho-execution/commit/1a07c7dc61ff7f86739ba7fbde2e7a42ebdf284f))

## [0.32.0](https://github.com/propeller-heads/tycho-execution/compare/0.31.0...0.32.0) (2025-02-06)


### Features

* Accept any struct that implements Into<ProtocolComponent> in Swap ([cb14022](https://github.com/propeller-heads/tycho-execution/commit/cb140226814add4f8141f3ad36784379a80d656c))

## [0.31.0](https://github.com/propeller-heads/tycho-execution/compare/0.30.1...0.31.0) (2025-02-05)


### Features

* add tests for split swap validations ([b69aef9](https://github.com/propeller-heads/tycho-execution/commit/b69aef9b8f1d253bb465a39669bd18aa5f355aa5))
* add tests for wrap unwrap case ([4d97c3f](https://github.com/propeller-heads/tycho-execution/commit/4d97c3f16d263c975f1f42bebae9666af789eb10))
* add validation for split swap ([f80ffa9](https://github.com/propeller-heads/tycho-execution/commit/f80ffa924f1da626bef0751c92c09fb133d2ba85))


### Bug Fixes

* checks in validations ([95edd5b](https://github.com/propeller-heads/tycho-execution/commit/95edd5b1fe99fd96163dcf74c2a570a7c8a480a1))
* get_mock_split_swap_strategy_encoder ([7b72263](https://github.com/propeller-heads/tycho-execution/commit/7b7226356d3bde61da987946dbc10ae3eec33722))
* use native action to validate path ([c787f5e](https://github.com/propeller-heads/tycho-execution/commit/c787f5e722ad8a9f9a24e6ea09f59dfcf5f82239))

## [0.30.1](https://github.com/propeller-heads/tycho-execution/compare/0.30.0...0.30.1) (2025-02-04)


### Bug Fixes

* deprecated signature ([576f89d](https://github.com/propeller-heads/tycho-execution/commit/576f89d24ca25ab37ae59b4db97cbff946d6da58))

## [0.30.0](https://github.com/propeller-heads/tycho-execution/compare/0.29.1...0.30.0) (2025-02-04)


### Features

* Refactor Registries ([23875b8](https://github.com/propeller-heads/tycho-execution/commit/23875b8b02396690b3f028c7696ea5b95e17e40e))

## [0.29.1](https://github.com/propeller-heads/tycho-execution/compare/0.29.0...0.29.1) (2025-02-04)


### Bug Fixes

* Fix bug with token indexing when wrapping/unwrapping ([3f4e27a](https://github.com/propeller-heads/tycho-execution/commit/3f4e27a34890b8865d59956d009bd4a44aa7fe54))
* test fixes after merge ([ff283bc](https://github.com/propeller-heads/tycho-execution/commit/ff283bc33383aa38ddeca7891795c0bcac1164fc))

## [0.29.0](https://github.com/propeller-heads/tycho-execution/compare/0.28.0...0.29.0) (2025-02-04)


### Features

* add swap encoder test in balancer v2 executor ([6333072](https://github.com/propeller-heads/tycho-execution/commit/6333072178b77bdc9a7950ed0ab84f30695d1b72))


### Bug Fixes

* executor test naming ([e6310d6](https://github.com/propeller-heads/tycho-execution/commit/e6310d65d1cb1c37ef0cef55090bf4abbe1fb275))

## [0.28.0](https://github.com/propeller-heads/tycho-execution/compare/0.27.0...0.28.0) (2025-02-04)


### Features

* Tycho encoder validation ([4bc6159](https://github.com/propeller-heads/tycho-execution/commit/4bc615913ecb41a551a8b970ba5d96f0fc20ca42))


### Bug Fixes

* test_validate_fails_for_unwrap_wrong_last_swap ([0660321](https://github.com/propeller-heads/tycho-execution/commit/06603210bcd567ce50ec79344024ea2b722ebcd3))

## [0.27.0](https://github.com/propeller-heads/tycho-execution/compare/0.26.0...0.27.0) (2025-02-04)


### Features

* Add complex swap to quickstart example ([80454f0](https://github.com/propeller-heads/tycho-execution/commit/80454f012d1d6c9a79aed02ab95c8290c02ceaba))
* Add simple quickstart example ([84d162d](https://github.com/propeller-heads/tycho-execution/commit/84d162d418f383bb9dee56ba281f24f686bff19d))


### Bug Fixes

* bring back one #[allow(dead_code)] ([ae315b4](https://github.com/propeller-heads/tycho-execution/commit/ae315b452aa231d63529aca5834ef80d7eb1f320))
* Calculate min_amount_out correctly and extend test to prove this ([de1c782](https://github.com/propeller-heads/tycho-execution/commit/de1c782bc1184f8437226986fc148ebf3995ece9))

## [0.26.0](https://github.com/propeller-heads/tycho-execution/compare/0.25.3...0.26.0) (2025-02-03)


### Features

* Verify that no amount in is left in the router ([0860d67](https://github.com/propeller-heads/tycho-execution/commit/0860d67d7a339a0fcc2533be856b64b1db394764))

## [0.25.3](https://github.com/propeller-heads/tycho-execution/compare/0.25.2...0.25.3) (2025-01-31)


### Bug Fixes

* transfer ETH if tokenOut is ETH ([3245ea7](https://github.com/propeller-heads/tycho-execution/commit/3245ea7295d6659a427fe09d23da720fa9cfe5d6))

## [0.25.2](https://github.com/propeller-heads/tycho-execution/compare/0.25.1...0.25.2) (2025-01-31)


### Bug Fixes

* Accidentally changed wrong test's calldata ([faacd3f](https://github.com/propeller-heads/tycho-execution/commit/faacd3f25cdfbc808acdf90aa50b2a86de7af62d))
* Expect decimal during encoding, add assert to test ([5a81ed6](https://github.com/propeller-heads/tycho-execution/commit/5a81ed6be51be568233a610e2be92f466c482410))

## [0.25.1](https://github.com/propeller-heads/tycho-execution/compare/0.25.0...0.25.1) (2025-01-31)


### Bug Fixes

* Fix selector - shouldn't contain spaces ([5d6f0c1](https://github.com/propeller-heads/tycho-execution/commit/5d6f0c1673932e55c1ba64b25a02a51426328e3e))
* Fix token index order in strategy encoding. ([c85c353](https://github.com/propeller-heads/tycho-execution/commit/c85c353e344a1fec4a2fbcd5b460b37f2edfc91e))

## [0.25.0](https://github.com/propeller-heads/tycho-execution/compare/0.24.0...0.25.0) (2025-01-31)


### Features

* Add ChainId model ([089e7d2](https://github.com/propeller-heads/tycho-execution/commit/089e7d2e0f7fcd60c591ff0d1e5e56a7d7ae93dd))
* Implement SplitSwapStrategyEncoder ([feb91cc](https://github.com/propeller-heads/tycho-execution/commit/feb91cc639aaf9e5056662158f2cbbbb61f9021e))
* Remove generalisation on user approvals manager ([3a69bbf](https://github.com/propeller-heads/tycho-execution/commit/3a69bbf6035df123a076f1f91011300e1c672527))
* Simplify router encoder ([6e8d2ed](https://github.com/propeller-heads/tycho-execution/commit/6e8d2ede595ecafe42cd1025f67ed4ab0083360d))


### Bug Fixes

* Don't leak evm specific code to interfaces(PrivateKeySigner, Chain) ([7a8872c](https://github.com/propeller-heads/tycho-execution/commit/7a8872cc415cf99f0122dcc92e87b6e09932d465))
* Post merge's fixes ([a28b548](https://github.com/propeller-heads/tycho-execution/commit/a28b54888e08fe23ed20ef8b0a385f094bca3c28))
* replace all unwraps with proper error handling ([5f3d440](https://github.com/propeller-heads/tycho-execution/commit/5f3d4406bdfed1d20df5614e74efeb7fcd5cffc1))
* Use abi_encode_packed in ple_encode() ([82e671d](https://github.com/propeller-heads/tycho-execution/commit/82e671df395477e800afc6b6bc94d5a07d78ec04))
* Use max instead of min to get the min_amount_out ([575c5be](https://github.com/propeller-heads/tycho-execution/commit/575c5bea5ec9c07f3bc729d140ad14a2a779b184))

## [0.24.0](https://github.com/propeller-heads/tycho-execution/compare/0.23.0...0.24.0) (2025-01-30)


### Features

* rename batchSetExecutor to setExecutors ([c653062](https://github.com/propeller-heads/tycho-execution/commit/c65306202783ec80e8086423a4cec4261728da03))
* replace setExecutor with batchSetExecutor ([ea504fa](https://github.com/propeller-heads/tycho-execution/commit/ea504faca12bdf19f4c98946a4173167a73fba2d))


### Bug Fixes

* rm redundant test ([24e95b1](https://github.com/propeller-heads/tycho-execution/commit/24e95b1206d403a9c7b2c82b12bd14c3fc7ee6c4))

## [0.23.0](https://github.com/propeller-heads/tycho-execution/compare/0.22.0...0.23.0) (2025-01-30)


### Features

* add executor encoder test ([ad70a0d](https://github.com/propeller-heads/tycho-execution/commit/ad70a0d5a87f2a89d78de7f4ae783f6c80097407))
* add swap test with hex for univ2 executor ([0196767](https://github.com/propeller-heads/tycho-execution/commit/0196767eff1d18481e3154defd92514bd45d74b9))
* add univ2 executor test with hex ([c482e21](https://github.com/propeller-heads/tycho-execution/commit/c482e21a5f7b254a19cca53c5a86b97830a90932))
* remove exact_out from USV2 ([8cb95f0](https://github.com/propeller-heads/tycho-execution/commit/8cb95f0950e3b57ae0c6ecc3f4c0950005ae75e7))
* resolve pr comments ([1b8bf56](https://github.com/propeller-heads/tycho-execution/commit/1b8bf56c754254dc74233e28f3ae3a3992bbf0d3))
* update ExecutorEncoder interface and relevant types ([5c39651](https://github.com/propeller-heads/tycho-execution/commit/5c396512cf695dab3b0d0fec16f71b916661d54d))

## [0.22.0](https://github.com/propeller-heads/tycho-execution/compare/0.21.0...0.22.0) (2025-01-30)


### Features

* fixed USV3 Verification ([96af542](https://github.com/propeller-heads/tycho-execution/commit/96af5429232a851a7e7144b8a30843a3e6dc980e))
* Implement generic callback ([fafeba9](https://github.com/propeller-heads/tycho-execution/commit/fafeba924848f107e1a00a00cfe94347fde3d919))
* UniswapV3Executor and integration tests ([ca32446](https://github.com/propeller-heads/tycho-execution/commit/ca32446a9ee28118d8857c02abefd24389485b7e))
* USV3 verification ([7822c4f](https://github.com/propeller-heads/tycho-execution/commit/7822c4f9132b6d64a1281f6e54a8515cb0d242d3))


### Bug Fixes

* Remove amountReceived and dataOffset from the callback verification ([63b94b5](https://github.com/propeller-heads/tycho-execution/commit/63b94b55849f2087dab78ec951c459d3811409eb))
* Remove amountReceived, dataOffset from ICallbackVerifier interface ([33ada0c](https://github.com/propeller-heads/tycho-execution/commit/33ada0cf26209cd626c75e26fc6d56943988e0b1))
* Remove exactOut from USV3 encoding ([d8b44f6](https://github.com/propeller-heads/tycho-execution/commit/d8b44f623b8175f4759f8a8cbd42c46e5abad3b4))

## [0.21.0](https://github.com/propeller-heads/tycho-execution/compare/0.20.0...0.21.0) (2025-01-28)


### Features

* add balancer v2 executor ([a700189](https://github.com/propeller-heads/tycho-execution/commit/a700189aaf8364a55e9625c807191232663eeff8))
* add node.js workflow ([25756ff](https://github.com/propeller-heads/tycho-execution/commit/25756fffdde57ba49985006702eee219cddeb262))
* add tests for Balancer V2 executor ([a4e405f](https://github.com/propeller-heads/tycho-execution/commit/a4e405fb7541c96445e820db4bd48110801ad940))
* approve max ([cb6d165](https://github.com/propeller-heads/tycho-execution/commit/cb6d165e7f901ee16a8848361a22bcb613b83c69))
* update remappings and remove node modules ([b65b682](https://github.com/propeller-heads/tycho-execution/commit/b65b682e8db4950fc9886dc00f2d76f6239447a8))


### Bug Fixes

* balancer v2 encoder bug ([a6a624b](https://github.com/propeller-heads/tycho-execution/commit/a6a624b740c8260f63caa46707d3ffb04cc6fca2))
* build ([5dc5e23](https://github.com/propeller-heads/tycho-execution/commit/5dc5e23239dd01c5cde5740c1d8f7a914103d54b))
* ci ([b1ca478](https://github.com/propeller-heads/tycho-execution/commit/b1ca4782941699c548c0d6c2b3aa60711598780f))
* clippy ([877f625](https://github.com/propeller-heads/tycho-execution/commit/877f625efc307eb902f65fcf2e1b9a052204d8f3))
* exclude node modules from slither ([4b3c5c5](https://github.com/propeller-heads/tycho-execution/commit/4b3c5c5005e52f53b4a21f28c80b46f7c409ee01))
* filter paths slither ([6c30cf8](https://github.com/propeller-heads/tycho-execution/commit/6c30cf8f66c7e5b95f3d216c2a3408e34886a852))
* rm exactOut ([44db2e5](https://github.com/propeller-heads/tycho-execution/commit/44db2e52b31bbc208325e99f86b7ebad05be65ce))
* slither ([b854282](https://github.com/propeller-heads/tycho-execution/commit/b85428212a40b7cb0d31fb57027675f7e6a5cf6f))
* slither ([7a83edd](https://github.com/propeller-heads/tycho-execution/commit/7a83eddc92333638247a61acd1154eb65a510467))

## [0.20.0](https://github.com/propeller-heads/tycho-execution/compare/0.19.0...0.20.0) (2025-01-28)


### Features

* Add executor and selector to Swap ([c2347ac](https://github.com/propeller-heads/tycho-execution/commit/c2347ac79ec670615de5f6b90982670d9bb739ed))
* Add swap method (first attempt) ([a8f6fc1](https://github.com/propeller-heads/tycho-execution/commit/a8f6fc1eeca8b3fcb0a5786ea538bf3fb087c111))
* Add swap method with tests ([50429ad](https://github.com/propeller-heads/tycho-execution/commit/50429ad05cc86bf3816fe2e4b67725cec72519f8))
* Assume that funds will never go straight from a pool to the receiver ([655cf91](https://github.com/propeller-heads/tycho-execution/commit/655cf91984fb568c5ff02efd498d093155c4e33d))
* Smother slither and add a reentrancy guard in swap() ([dfa7033](https://github.com/propeller-heads/tycho-execution/commit/dfa7033d2e1aa2f2845335d29d6142cc9a7ac5f1))
* Wrap and unwrap ETH ([3b2d9fc](https://github.com/propeller-heads/tycho-execution/commit/3b2d9fcbdff00be8015c1c70a20687677bf4b22c))


### Bug Fixes

* fix submodules ([0a1f522](https://github.com/propeller-heads/tycho-execution/commit/0a1f5222076f20496b520aee64999507a343b0b3))
* Remove checkMinAmount ([d8de65a](https://github.com/propeller-heads/tycho-execution/commit/d8de65aedf459e34911f80da4dc6e44da93aa807))

## [0.19.0](https://github.com/propeller-heads/tycho-execution/compare/0.18.0...0.19.0) (2025-01-28)


### Features

* UniswapV3SwapEncoder ([9c63e09](https://github.com/propeller-heads/tycho-execution/commit/9c63e099a9ba90b46768a6dfd192bcdd651f7f22)), closes [/github.com/propeller-heads/tycho-protocol-sdk/blob/3c08359cf112e15c137dd5256b8dc8e9cd6c1626/substreams/ethereum-uniswap-v3/src/modules/1_map_pool_created.rs#L64](https://github.com/propeller-heads//github.com/propeller-heads/tycho-protocol-sdk/blob/3c08359cf112e15c137dd5256b8dc8e9cd6c1626/substreams/ethereum-uniswap-v3/src/modules/1_map_pool_created.rs/issues/L64)

## [0.18.0](https://github.com/propeller-heads/tycho-execution/compare/0.17.0...0.18.0) (2025-01-27)


### Features

* Perform staticcall to CallbackVerifier ([ad0748e](https://github.com/propeller-heads/tycho-execution/commit/ad0748e9c3b2431ae29be8477534853029efa27d))

## [0.17.0](https://github.com/propeller-heads/tycho-execution/compare/0.16.0...0.17.0) (2025-01-27)


### Features

* add pause/unpause methods ([c982ed9](https://github.com/propeller-heads/tycho-execution/commit/c982ed99e8bd1a01ec637aa1b9cd2c5ae69ddac4))


### Bug Fixes

* ci ([4ee337d](https://github.com/propeller-heads/tycho-execution/commit/4ee337d1ee3fa5cda7bbec64b760e39028165a60))
* test pauser ([5734b53](https://github.com/propeller-heads/tycho-execution/commit/5734b535548338adcd3a738feb559b5b16105766))

## [0.16.0](https://github.com/propeller-heads/tycho-execution/compare/0.15.0...0.16.0) (2025-01-27)


### Features

* add balance v2 encoder test ([9cecea8](https://github.com/propeller-heads/tycho-execution/commit/9cecea896833b27ec855f1ea4d981dde64f869ac))


### Bug Fixes

* async ([7c198ff](https://github.com/propeller-heads/tycho-execution/commit/7c198fff92bb6bb8858912008d0bb40364d8bcd6))

## [0.15.0](https://github.com/propeller-heads/tycho-execution/compare/0.14.0...0.15.0) (2025-01-24)


### Features

* UniswapV2 SwapExecutor ([5627a19](https://github.com/propeller-heads/tycho-execution/commit/5627a1902b74ace7eccce9888b4505f77b827d43))


### Bug Fixes

* Add input validation size in Uniswapv2SwapExecutor ([ed44f4e](https://github.com/propeller-heads/tycho-execution/commit/ed44f4e993f3856dbeb14cae04acffec72c25524))
* Remove exactOut logic from Uniswapv2SwapExecutor ([b9f4451](https://github.com/propeller-heads/tycho-execution/commit/b9f445176924e7f52d5e130f96038cfe8c44ea18))

## [0.14.0](https://github.com/propeller-heads/tycho-execution/compare/0.13.0...0.14.0) (2025-01-24)


### Features

* delegatecall to executor in SwapExecutionDispatcher ([e91ee96](https://github.com/propeller-heads/tycho-execution/commit/e91ee9612995eb038fb0f0c837438976cedc9a9a))
* Emit event when removing executor ([1fabff1](https://github.com/propeller-heads/tycho-execution/commit/1fabff19c4427caee0a758e2f89336ea784462cb))


### Bug Fixes

* ISwapExecutor shouldn't be payable ([3df17e8](https://github.com/propeller-heads/tycho-execution/commit/3df17e892491fbb47bf6ed03680b0fb7fbb68140))
* Silence slither warnings ([b616e11](https://github.com/propeller-heads/tycho-execution/commit/b616e11354ee325dcbecff70caf4e7daf4d144d0))

## [0.13.0](https://github.com/propeller-heads/tycho-execution/compare/0.12.0...0.13.0) (2025-01-23)


### Features

* Implement Permit2 ([ce9ae49](https://github.com/propeller-heads/tycho-execution/commit/ce9ae49e6f14e3cc8c7a17ca0e9267083c97cf9d))


### Bug Fixes

* Correct encoding of the approvals ([04e925f](https://github.com/propeller-heads/tycho-execution/commit/04e925fe81a585f60bc4fbd9caf7d31e8e7422ef))
* Small improvements ([b9cfc4a](https://github.com/propeller-heads/tycho-execution/commit/b9cfc4a35b95ec1c431200c5d83ee0081ee8326a))

## [0.12.0](https://github.com/propeller-heads/tycho-execution/compare/0.11.0...0.12.0) (2025-01-23)


### Features

* add tests for withdraw, fee and make it DRY ([056582c](https://github.com/propeller-heads/tycho-execution/commit/056582ca2f5d792d60027574c313be2ca8ac649c))


### Bug Fixes

* pr comments ([9c99b73](https://github.com/propeller-heads/tycho-execution/commit/9c99b738841cb0dacf37bf95aec8cedebc69c5d3))

## [0.11.0](https://github.com/propeller-heads/tycho-execution/compare/0.10.0...0.11.0) (2025-01-23)


### Features

* add LibPrefixLengthEncodedByteArray with tests ([f25da21](https://github.com/propeller-heads/tycho-execution/commit/f25da218d7b40878a61f6feb09f39c7fb06433f5))
* keep assembly ([ae662d0](https://github.com/propeller-heads/tycho-execution/commit/ae662d002608c97b8e350241c5992b3659753c76))

## [0.10.0](https://github.com/propeller-heads/tycho-execution/compare/0.9.0...0.10.0) (2025-01-23)


### Features

* add fee methods ([0dc7edc](https://github.com/propeller-heads/tycho-execution/commit/0dc7edccfac4524209c40caede6ac052c9b575c0))


### Bug Fixes

* use FEE_SETTER_ROLE for setFeeReceiver ([15d3bec](https://github.com/propeller-heads/tycho-execution/commit/15d3becf603b127e3d450c71bf7458b72f670a40))

## [0.9.0](https://github.com/propeller-heads/tycho-execution/compare/0.8.0...0.9.0) (2025-01-22)


### Features

* Emit events when setting executors/verifiers ([59950a7](https://github.com/propeller-heads/tycho-execution/commit/59950a7575d2a388cfc040ff8da63d98de544ac0))
* Set swap executors and verifiers ([4cb3286](https://github.com/propeller-heads/tycho-execution/commit/4cb3286c9425a72e58c44c29d17b31261b1dd94e))

## [0.8.0](https://github.com/propeller-heads/tycho-execution/compare/0.7.0...0.8.0) (2025-01-22)


### Features

* add receiver in event ([2c3af0f](https://github.com/propeller-heads/tycho-execution/commit/2c3af0ff314b449b418285f5b6622aec1cb5039b))
* add withdraw methods ([78fa890](https://github.com/propeller-heads/tycho-execution/commit/78fa890cd36c506bbf80b6e35e1d4aed2314e23e))


### Bug Fixes

* ci ([0c05874](https://github.com/propeller-heads/tycho-execution/commit/0c05874477e90b659e12ae9ca7ec5ee3d8f03b58))
* disable slither for native withdraw ([f3363a2](https://github.com/propeller-heads/tycho-execution/commit/f3363a24f4fc8b73e4e98868db8368e915da59d0))
* undo rm lib ([a1e7b55](https://github.com/propeller-heads/tycho-execution/commit/a1e7b552b66a2200c25a1c74c7381b2991a24fa6))
* use send for native transfer ([c6c0ddd](https://github.com/propeller-heads/tycho-execution/commit/c6c0ddd498ee2c3aabde8d9d81174dd197078b9f))

## [0.7.0](https://github.com/propeller-heads/tycho-execution/compare/0.6.0...0.7.0) (2025-01-22)


### Features

* UniswapV2 Swap Encoder ([7b4bf02](https://github.com/propeller-heads/tycho-execution/commit/7b4bf0205d52354ffde4a88bd344a6df7d92cca5))

## [0.6.0](https://github.com/propeller-heads/tycho-execution/compare/0.5.0...0.6.0) (2025-01-21)


### Features

* Add openzeppelin lib for access control ([a8f62ee](https://github.com/propeller-heads/tycho-execution/commit/a8f62ee837bb9bbc258d2e142204cff579355714))
* Add permit2 lib for approval management ([cb9053b](https://github.com/propeller-heads/tycho-execution/commit/cb9053bd885ad8963abd74e1ffb1929fb0bd10e5))
* initial TychoRouter skeleton ([ab28a47](https://github.com/propeller-heads/tycho-execution/commit/ab28a4730dbdd9d2eb5523b0cadfffdb18569618)), closes [lib/openzeppelin-contracts/contracts/access/AccessControl.sol#4](https://github.com/lib/openzeppelin-contracts/contracts/access/AccessControl.sol/issues/4) [lib/openzeppelin-contracts/contracts/access/IAccessControl.sol#4](https://github.com/lib/openzeppelin-contracts/contracts/access/IAccessControl.sol/issues/4) [lib/openzeppelin-contracts/contracts/utils/Context.sol#4](https://github.com/lib/openzeppelin-contracts/contracts/utils/Context.sol/issues/4) [lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol#4](https://github.com/lib/openzeppelin-contracts/contracts/utils/introspection/ERC165.sol/issues/4) [lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol#4](https://github.com/lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol/issues/4) [lib/permit2/src/interfaces/IAllowanceTransfer.sol#2](https://github.com/lib/permit2/src/interfaces/IAllowanceTransfer.sol/issues/2) [lib/permit2/src/interfaces/IEIP712.sol#2](https://github.com/lib/permit2/src/interfaces/IEIP712.sol/issues/2)


### Bug Fixes

* Filter paths when running slither in CI ([96809d4](https://github.com/propeller-heads/tycho-execution/commit/96809d4801d52270c622650cff16f19906520ec6))

## [0.5.0](https://github.com/propeller-heads/tycho-execution/compare/0.4.0...0.5.0) (2025-01-20)


### Features

* Implement ProtocolApprovalsManager ([cbf2b4d](https://github.com/propeller-heads/tycho-execution/commit/cbf2b4de5a68d98f37182b26f8872f4f512b356f))

## [0.4.0](https://github.com/propeller-heads/tycho-execution/compare/0.3.0...0.4.0) (2025-01-20)


### Features

* Add Slither to CI ([f0620bd](https://github.com/propeller-heads/tycho-execution/commit/f0620bd18043d7d53daf5660493955e131f27e5a))
* Add Slither to README.md and include contract file to test ([2998bb3](https://github.com/propeller-heads/tycho-execution/commit/2998bb3fb15709cac0f844ae662d4e20db9371fc))


### Bug Fixes

* Bump to latest Solidity version (0.8.28) ([f987125](https://github.com/propeller-heads/tycho-execution/commit/f987125489ce1e31d1046009c0fee6f728cfe359)), closes [src/Counter.sol#2](https://github.com/src/Counter.sol/issues/2)
* Specify foundry subdir when running slither in CI ([40f0a2a](https://github.com/propeller-heads/tycho-execution/commit/40f0a2a2b7c06003a20a6b7c81ce8887b8ddc10a))

## [0.3.0](https://github.com/propeller-heads/tycho-execution/compare/0.2.0...0.3.0) (2025-01-17)


### Features

* Add EncodingError ([bab5caa](https://github.com/propeller-heads/tycho-execution/commit/bab5caa6f8c248dbc0cce8cf9bdc82b73b89e92c))


### Bug Fixes

* Add RecoverableError ([af6d73a](https://github.com/propeller-heads/tycho-execution/commit/af6d73a54068d63973c01d65371e1d0c663b81fc))

## [0.2.0](https://github.com/propeller-heads/tycho-execution/compare/0.1.0...0.2.0) (2025-01-17)


### Features

* Simplify StrategyEncoders and RouterEncoder ([38b8bb0](https://github.com/propeller-heads/tycho-execution/commit/38b8bb0e782d25a4d88fb250c6d1f0e050b76313))

## [0.1.0](https://github.com/propeller-heads/tycho-execution/compare/0.0.1...0.1.0) (2025-01-17)


### Features

* Add chain in config.json for the executor addresses ([f5df1bb](https://github.com/propeller-heads/tycho-execution/commit/f5df1bbd87fb38f686c1aa14c741c8676ecf0c4b))
* Add evm feature gate ([6c6ba21](https://github.com/propeller-heads/tycho-execution/commit/6c6ba218946b1fda1fd1f5545a21338d8cfa6699))


### Bug Fixes

* Make executor_address a String instead of Address ([1d3ac22](https://github.com/propeller-heads/tycho-execution/commit/1d3ac2208718ea19d8459d7463be2835cef64cd6))

## [0.0.1](https://github.com/propeller-heads/tycho-execution/compare/0.0.0...0.0.1) (2025-01-17)


### Bug Fixes

* change release version ([d584e0a](https://github.com/propeller-heads/tycho-execution/commit/d584e0a1e51f43fc0d4c02c82acc88ed63374ecf))

## [0.0.0](https://github.com/propeller-heads/tycho-execution/compare/0.0.0...0.0.0) (2025-01-17)
