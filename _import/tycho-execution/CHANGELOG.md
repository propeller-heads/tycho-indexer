## [1.2.0](https://github.com/propeller-heads/tycho-execution/compare/1.1.0...1.2.0) (2025-01-17)


### Features

* Add foundry environment and CI ([e16d7cc](https://github.com/propeller-heads/tycho-execution/commit/e16d7ccb8ef978dd2abe3993ea0981c2dae8d7e0))

## [1.1.0](https://github.com/propeller-heads/tycho-execution/compare/1.0.0...1.1.0) (2025-01-16)


### Features

* Add builder pattern and registry for SwapEncoders ([6d8cbcd](https://github.com/propeller-heads/tycho-execution/commit/6d8cbcd80ca7b3b57128a96ba9ede6ac8927103e))
* Add permit2 draft ([5d79da4](https://github.com/propeller-heads/tycho-execution/commit/5d79da44f393826e7c85b9340a44e82d79a91400))
* Add StrategySelector ([6e67875](https://github.com/propeller-heads/tycho-execution/commit/6e6787582169aa99d9530f35dee69ce7218172b9))
* Add Transaction as output of encoding ([5a661ab](https://github.com/propeller-heads/tycho-execution/commit/5a661ab6caa0ee19fed0fbac470476927ac26a2d))
* ApprovalsManager trait ([4991883](https://github.com/propeller-heads/tycho-execution/commit/4991883fc81e83c9be955df9fe82f84555d41d7c))
* Handle native actions ([fa462ee](https://github.com/propeller-heads/tycho-execution/commit/fa462ee9f3cce3d339f0bc1645b7ce8bd6d42cf0))
* Initial draft of encoding module ([36fe8f4](https://github.com/propeller-heads/tycho-execution/commit/36fe8f4b763ffb336ae3eac739b2d00e1796b7d9))
* Make check amount optional ([6f8bbd8](https://github.com/propeller-heads/tycho-execution/commit/6f8bbd89a54266af61670467c7b2b1125a635c8c))
* Remove batch execute logic from StrategyEncoder ([68c5a91](https://github.com/propeller-heads/tycho-execution/commit/68c5a914ebf7eef086c7fbeb8464e83f31670048))
* Support encoding only the pool swap ([3e609c7](https://github.com/propeller-heads/tycho-execution/commit/3e609c75aefaff7c4627c39c9d328961b656658c))


### Bug Fixes

* Add expected_amount to Solution ([f9f83b4](https://github.com/propeller-heads/tycho-execution/commit/f9f83b439f5ecf0ea9186a21a4a1fe3591173c03))
* Add new to SwapEncoder trait ([30f2ac9](https://github.com/propeller-heads/tycho-execution/commit/30f2ac9f6b1d71bcadce06ff22722cb231e16799))
* Constrain new in SwapEncoder so it does not apply to trait objects ([e93bf11](https://github.com/propeller-heads/tycho-execution/commit/e93bf11a85514a2bda2ebf123f56db29b4c37070))
* Simplify models. Delete Solution and rename Order->Solution ([a25c56e](https://github.com/propeller-heads/tycho-execution/commit/a25c56e66727290b4d573a368f2f2ff4eab3ccb2))
* TokenApprovalsManager should not implement ApprovalsManager ([93410b4](https://github.com/propeller-heads/tycho-execution/commit/93410b4fe2d0f6b59fc8c7049a151fa73faaf393))

## 1.0.0 (2025-01-16)


### Features

* Add Cargo files, CI, configs and README ([c27b253](https://github.com/propeller-heads/tycho-execution/commit/c27b253ef5182fd44d58a743d618929ed364adeb))


### Bug Fixes

* Add temporary main function to lib.rs ([1e54ea0](https://github.com/propeller-heads/tycho-execution/commit/1e54ea045ee8448da45a273683fb3b608ed741d8))
