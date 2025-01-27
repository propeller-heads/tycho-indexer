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
