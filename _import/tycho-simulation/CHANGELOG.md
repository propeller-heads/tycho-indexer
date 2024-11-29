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
