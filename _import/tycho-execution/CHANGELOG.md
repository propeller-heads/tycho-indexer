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
