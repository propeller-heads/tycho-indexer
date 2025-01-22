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
