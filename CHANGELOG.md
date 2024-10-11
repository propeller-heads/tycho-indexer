## [0.32.0](https://github.com/propeller-heads/tycho-indexer/compare/0.31.3...0.32.0) (2024-10-09)


### Features

* **tycho-client:** publicly expose snapshot vm storage ([55e7875](https://github.com/propeller-heads/tycho-indexer/commit/55e78752627dc1ee36f45eeaf7f56797b704f2ee))
* **tycho-client:** publicly expose snapshot vm storage ([#413](https://github.com/propeller-heads/tycho-indexer/issues/413)) ([ca2a3e7](https://github.com/propeller-heads/tycho-indexer/commit/ca2a3e7aef90a4aeee5c4b5d96741fc0aeb6db50))

## [0.31.3](https://github.com/propeller-heads/tycho-indexer/compare/0.31.2...0.31.3) (2024-10-07)

## [0.31.2](https://github.com/propeller-heads/tycho-indexer/compare/0.31.1...0.31.2) (2024-10-07)


### Bug Fixes

* **substreams:** output type in Substreams modules ([7d62512](https://github.com/propeller-heads/tycho-indexer/commit/7d625128d5242f2e7b589bff19e863af06070580))
* **uniswap-v2-substreams:** use correct strucs in store pools module. ([16bbfc3](https://github.com/propeller-heads/tycho-indexer/commit/16bbfc3ce4805b8e5c6fce74c43d0e7f09eb266b))

## [0.31.1](https://github.com/propeller-heads/tycho-indexer/compare/0.31.0...0.31.1) (2024-10-07)


### Bug Fixes

* exit build_wheel script on failed internal command ([47c30c7](https://github.com/propeller-heads/tycho-indexer/commit/47c30c7c66d0d32b4a8a2922e8e9bf06a37acb11))

## [0.31.0](https://github.com/propeller-heads/tycho-indexer/compare/0.30.2...0.31.0) (2024-10-07)


### Features

* Add auth token support to tycho python client ([#406](https://github.com/propeller-heads/tycho-indexer/issues/406)) ([85376a6](https://github.com/propeller-heads/tycho-indexer/commit/85376a624da4d91eef52c584602727cf2a7bf44e))
* add auth token to tycho python client rpc ([1033802](https://github.com/propeller-heads/tycho-indexer/commit/1033802b1c852b87d0e9b0761ad08be79855a8ce))
* add auth token to tycho python client stream constructor ([d1f21bc](https://github.com/propeller-heads/tycho-indexer/commit/d1f21bc18af60e309f289b9f652a031a9d7c9f47))

## [0.30.2](https://github.com/propeller-heads/tycho-indexer/compare/0.30.1...0.30.2) (2024-10-07)


### Bug Fixes

* also cache component requests for specified components ([ce0f559](https://github.com/propeller-heads/tycho-indexer/commit/ce0f55937dc4eda18d5c74df0a2f6aa50d253ee3))
* Also cache component requests for specified components ([#404](https://github.com/propeller-heads/tycho-indexer/issues/404)) ([ff49333](https://github.com/propeller-heads/tycho-indexer/commit/ff49333416299b5b2c58976236baab08d29cee0e))

## [0.30.1](https://github.com/propeller-heads/tycho-indexer/compare/0.30.0...0.30.1) (2024-10-07)


### Bug Fixes

* **tycho-indexer:** correctly `buffered_range` to the span ([761eb72](https://github.com/propeller-heads/tycho-indexer/commit/761eb722a048dc93817e0db6f323d7e7cf5c1de7))
* **tycho-indexer:** correctly `buffered_range` to the span ([#405](https://github.com/propeller-heads/tycho-indexer/issues/405)) ([9adfcf7](https://github.com/propeller-heads/tycho-indexer/commit/9adfcf71f11dd4790c0b557772d60544a88b0fdf))

## [0.30.0](https://github.com/propeller-heads/tycho-indexer/compare/0.29.1...0.30.0) (2024-10-07)


### Features

* **tycho-indexer:** add span for `get_block_range` ([40d3c30](https://github.com/propeller-heads/tycho-indexer/commit/40d3c30b07f52719a64b7906a670e680af9cc8a8))
* **tycho-indexer:** add span for `get_block_range` ([#403](https://github.com/propeller-heads/tycho-indexer/issues/403)) ([a3df5b4](https://github.com/propeller-heads/tycho-indexer/commit/a3df5b416623dc1329375cbe1e4d03c6e7250375))

## [0.29.1](https://github.com/propeller-heads/tycho-indexer/compare/0.29.0...0.29.1) (2024-10-07)


### Bug Fixes

* increase component cache capacity ([4c2c611](https://github.com/propeller-heads/tycho-indexer/commit/4c2c611cbe4176b0d8797ad57a6b19587c5e16d4))
* increase component cache capacity ([#402](https://github.com/propeller-heads/tycho-indexer/issues/402)) ([501afbc](https://github.com/propeller-heads/tycho-indexer/commit/501afbc9303ff9e06af7beb222a561b8c5d8a16c))

## [0.29.0](https://github.com/propeller-heads/tycho-indexer/compare/0.28.0...0.29.0) (2024-10-04)


### Features

* **rpc:** add events in delta buffer ([9047b7c](https://github.com/propeller-heads/tycho-indexer/commit/9047b7ce473478ee6cad50a584bcc0c96b972729))
* **rpc:** add events in delta buffer ([#398](https://github.com/propeller-heads/tycho-indexer/issues/398)) ([8bbe273](https://github.com/propeller-heads/tycho-indexer/commit/8bbe273697b6f760db645a7e3695b0eb55ca512b))

## [0.28.0](https://github.com/propeller-heads/tycho-indexer/compare/0.27.0...0.28.0) (2024-10-04)


### Features

* improve rpc spans ([#397](https://github.com/propeller-heads/tycho-indexer/issues/397)) ([296b71c](https://github.com/propeller-heads/tycho-indexer/commit/296b71c09f37222aed7b54756e7098c0af212099))
* **rpc:** Add pagination and protocol attributes to rpc spans. ([5119d44](https://github.com/propeller-heads/tycho-indexer/commit/5119d446417612684547d9bbc7d90378effca0f3))
* **rpc:** Improve cache tracing spans. ([9241119](https://github.com/propeller-heads/tycho-indexer/commit/9241119353bb4c6c50aa65d8088002a32fc75afd))

## [0.27.0](https://github.com/propeller-heads/tycho-indexer/compare/0.26.0...0.27.0) (2024-10-03)


### Features

* **rpc:** Implement per-key sharded locking in RpcCache ([ef68ca2](https://github.com/propeller-heads/tycho-indexer/commit/ef68ca2491e5fb7c1be58148b8b7e19bb092100b))
* **rpc:** Implement per-key sharded locking in RpcCache ([#396](https://github.com/propeller-heads/tycho-indexer/issues/396)) ([f0337bf](https://github.com/propeller-heads/tycho-indexer/commit/f0337bf2fb01aab478eb7f41c47c9d3f8718b8f6))

## [0.26.0](https://github.com/propeller-heads/tycho-indexer/compare/0.25.1...0.26.0) (2024-10-03)


### Features

* **client:** Ensure StateSynchronizer waits for initialization ([a378483](https://github.com/propeller-heads/tycho-indexer/commit/a378483a73b70d184f25e1093fe256ef0f383437))
* **client:** Ensure StateSynchronizer waits for initialization ([#393](https://github.com/propeller-heads/tycho-indexer/issues/393)) ([7852e43](https://github.com/propeller-heads/tycho-indexer/commit/7852e432f77a41dac6dc6dacba64e4bab9e68153))

## [0.25.1](https://github.com/propeller-heads/tycho-indexer/compare/0.25.0...0.25.1) (2024-10-03)


### Bug Fixes

* avoid concurrent requests for empty pages ([a881bba](https://github.com/propeller-heads/tycho-indexer/commit/a881bba3f780d86928d5b119acf9f973f2fb7513))
* avoid concurrent requests for empty pages ([#392](https://github.com/propeller-heads/tycho-indexer/issues/392)) ([681ae7e](https://github.com/propeller-heads/tycho-indexer/commit/681ae7e145403fc7e876d2216ff215f466ecd075))
* cache condition was reversed ([6f45a26](https://github.com/propeller-heads/tycho-indexer/commit/6f45a2639ca23c8f0447c8d263c02dde58e32f17))
* **client:** only apply concurrency once total is known ([82a65f1](https://github.com/propeller-heads/tycho-indexer/commit/82a65f13c5551ac6061fc38008c1c898e036789c))
* skip caching last page of components response ([7eff7bf](https://github.com/propeller-heads/tycho-indexer/commit/7eff7bfa91fc0229daaf86e158c82f2a7e9caddf))

## [0.25.0](https://github.com/propeller-heads/tycho-indexer/compare/0.24.1...0.25.0) (2024-10-03)


### Features

* **rpc:** add spans and event around the delta buffer and components query ([fe1a1f4](https://github.com/propeller-heads/tycho-indexer/commit/fe1a1f48e1a9d6ece1a540dc440847e71be5af54))
* **rpc:** add spans for cache, tokens and components requests ([e7112b0](https://github.com/propeller-heads/tycho-indexer/commit/e7112b0ebea8533b0ed9c3cc78741734e57a61e9))
* **rpc:** add spans for cache, tokens and components requests ([#394](https://github.com/propeller-heads/tycho-indexer/issues/394)) ([0c67a3d](https://github.com/propeller-heads/tycho-indexer/commit/0c67a3d329a19cb62953a31e9032d3da66bc2836))

## [0.24.1](https://github.com/propeller-heads/tycho-indexer/compare/0.24.0...0.24.1) (2024-10-02)


### Bug Fixes

* add order by to paginated queries ([b198f07](https://github.com/propeller-heads/tycho-indexer/commit/b198f07a3a05af4376c056b1925bbf80c38b63e6))
* add order by to paginated queries ([#391](https://github.com/propeller-heads/tycho-indexer/issues/391)) ([1db42b1](https://github.com/propeller-heads/tycho-indexer/commit/1db42b187daaee72d9a4be278b05270c523a6414))

## [0.24.0](https://github.com/propeller-heads/tycho-indexer/compare/0.23.1...0.24.0) (2024-10-02)


### Features

* Add component cache to rpc ([#390](https://github.com/propeller-heads/tycho-indexer/issues/390)) ([8dfc004](https://github.com/propeller-heads/tycho-indexer/commit/8dfc00430f4a8c0bb0cd4f152c640f91ef58b6b8))
* **rpc:** add component cache ([c7a1894](https://github.com/propeller-heads/tycho-indexer/commit/c7a189430df09aa1c8d517e0fe0a2468f0127cb9))


### Bug Fixes

* order components before pagination ([9eee0af](https://github.com/propeller-heads/tycho-indexer/commit/9eee0afd36706cae0c6a70679491d935664f6327))

## [0.23.1](https://github.com/propeller-heads/tycho-indexer/compare/0.23.0...0.23.1) (2024-10-02)


### Bug Fixes

* increase protocol component pagination page size ([2565c05](https://github.com/propeller-heads/tycho-indexer/commit/2565c051eb971aa697128c41a64a9e45913c1b13))
* increase protocol component pagination page size ([#389](https://github.com/propeller-heads/tycho-indexer/issues/389)) ([a90cad6](https://github.com/propeller-heads/tycho-indexer/commit/a90cad6998a357a259e115e4265b4759bc82699f))

## [0.23.0](https://github.com/propeller-heads/tycho-indexer/compare/0.22.5...0.23.0) (2024-10-02)


### Features

* **tycho-indexer:** make number of worker parametrable ([fc6e334](https://github.com/propeller-heads/tycho-indexer/commit/fc6e334b7b81d9e37076127038ff45c5fcb7518c))
* **tycho-indexer:** make number of worker parametrable ([#388](https://github.com/propeller-heads/tycho-indexer/issues/388)) ([f59397a](https://github.com/propeller-heads/tycho-indexer/commit/f59397a6ad0833ce67d2cc40e80a8746bad21b95))

## [0.22.5](https://github.com/propeller-heads/tycho-indexer/compare/0.22.4...0.22.5) (2024-10-01)


### Bug Fixes

* **otel:** create tracing subscriber inside the runtime ([65c3a02](https://github.com/propeller-heads/tycho-indexer/commit/65c3a02601b8b2cba53ecb8b70c905da2841f87a))
* Tokio runtime issue ([#387](https://github.com/propeller-heads/tycho-indexer/issues/387)) ([40ec9b2](https://github.com/propeller-heads/tycho-indexer/commit/40ec9b2ad29f7fe3f4ee98533fc5dac261b9d669))

## [0.22.4](https://github.com/propeller-heads/tycho-indexer/compare/0.22.3...0.22.4) (2024-10-01)

## [0.22.3](https://github.com/propeller-heads/tycho-indexer/compare/0.22.2...0.22.3) (2024-10-01)


### Bug Fixes

* **client:** populating python client error log bug ([#386](https://github.com/propeller-heads/tycho-indexer/issues/386)) ([87bcae5](https://github.com/propeller-heads/tycho-indexer/commit/87bcae5c37ef5c1d2a422ebbee53e64ed0d3d2e4))
* populating python client error log bug ([e6d9682](https://github.com/propeller-heads/tycho-indexer/commit/e6d9682704bae29e04d4dc4bac356866a4e42d1d))

## [0.22.2](https://github.com/propeller-heads/tycho-indexer/compare/0.22.1...0.22.2) (2024-10-01)


### Bug Fixes

* **client:** improve python client stream error logging ([#385](https://github.com/propeller-heads/tycho-indexer/issues/385)) ([5a243de](https://github.com/propeller-heads/tycho-indexer/commit/5a243dec32f9fda31cdb3cc3cf6d97e12897d63e))
* **client:** make python client error logs more readable ([baa1fa2](https://github.com/propeller-heads/tycho-indexer/commit/baa1fa20175d6a8b53b64aeec75e71c107d7889a))

## [0.22.1](https://github.com/propeller-heads/tycho-indexer/compare/0.22.0...0.22.1) (2024-09-30)


### Bug Fixes

* **client:** use new tokens endpoint ([02fb389](https://github.com/propeller-heads/tycho-indexer/commit/02fb389a648e46eb26199d2108c844934a6c9271))
* **client:** use new tokens endpoint ([#384](https://github.com/propeller-heads/tycho-indexer/issues/384)) ([5d568cd](https://github.com/propeller-heads/tycho-indexer/commit/5d568cd8bd55cac7fa787c0f3c8f68db09400d07))

## [0.22.0](https://github.com/propeller-heads/tycho-indexer/compare/0.21.0...0.22.0) (2024-09-30)


### Features

* **cache:** add tracing spans for every read methods ([be40f4c](https://github.com/propeller-heads/tycho-indexer/commit/be40f4cc1d2c5614d5ecd0a59ee4617edbfec894))
* **cache:** add tracing spans for every write methods on the 'CachedGateway' ([88ac98e](https://github.com/propeller-heads/tycho-indexer/commit/88ac98e61e895a6ac0c3fd3e566cb672c0761e87))
* **extractor:** improve database commits ([4a431df](https://github.com/propeller-heads/tycho-indexer/commit/4a431dfe3e88a3e642cf76455bc3e974dafa5cdd))
* **indexing:** Improve database commits logic ([#380](https://github.com/propeller-heads/tycho-indexer/issues/380)) ([55d40b9](https://github.com/propeller-heads/tycho-indexer/commit/55d40b9df1e315e77b4ea44647ba550412fb4582))

## [0.21.0](https://github.com/propeller-heads/tycho-indexer/compare/0.20.0...0.21.0) (2024-09-30)


### Features

* add method to get protocol components paginated ([7ce3cbe](https://github.com/propeller-heads/tycho-indexer/commit/7ce3cbe56305de3b821cf9b615718182997b3fc3))
* limit the page size for paginated endpoints ([26e8767](https://github.com/propeller-heads/tycho-indexer/commit/26e876767292a8d2751dfd651ff6f018d4c3fec5))
* more fixes ([29f1117](https://github.com/propeller-heads/tycho-indexer/commit/29f1117cb392b6b3cb113d0dd240ac0708828913))
* Return total count to pagination responses, get_contract_state ([d780212](https://github.com/propeller-heads/tycho-indexer/commit/d780212739025d6cda52b55fda82d9e04332857e))
* Return total count to pagination responses, get_protocol_components ([8115c9b](https://github.com/propeller-heads/tycho-indexer/commit/8115c9b41e7ff0e38c568cecb6ddeb5adcc1da1b))
* Return total count to pagination responses, get_protocol_state ([cfafb70](https://github.com/propeller-heads/tycho-indexer/commit/cfafb70c2ce38da01203c5f4a90d62c4815e2413))
* Return total count to pagination responses, get_tokens ([69ab6f7](https://github.com/propeller-heads/tycho-indexer/commit/69ab6f758f5be67c4f0007230ce43bbb5c2cf242))
* **rpc:** add pagination to all rpc endpoints ([39107f3](https://github.com/propeller-heads/tycho-indexer/commit/39107f36ffbd0c47609cb72977a67c3e68acf813))
* **rpc:** add pagination to all rpc endpoints ([#345](https://github.com/propeller-heads/tycho-indexer/issues/345)) ([f945d75](https://github.com/propeller-heads/tycho-indexer/commit/f945d753ed6da04a1b643e517db4949b981a9550))
* use pagination on rpc sync ([fd10192](https://github.com/propeller-heads/tycho-indexer/commit/fd1019207ab391c50f678afc1aefd35c2f2d269a))


### Bug Fixes

* bug with page and page_size swapped ([0aa2afd](https://github.com/propeller-heads/tycho-indexer/commit/0aa2afdd6e8079ee87422529d7c563d7a3891f87))
* correctly handle buffered components in pagination ([9f7bdbc](https://github.com/propeller-heads/tycho-indexer/commit/9f7bdbc01350627aebf0e5d2fdf49d856929c51f))
* correctly handle buffered contract states in pagination ([57209aa](https://github.com/propeller-heads/tycho-indexer/commit/57209aa9250790e6e126ff4c3a17be946dbfdb91))
* correctly handle buffered protocol states in pagination ([6afcc63](https://github.com/propeller-heads/tycho-indexer/commit/6afcc63bfd5c7779de8aa83787b80c3fe748f8a1))
* correctly pass state request ids chunk ([d5282cb](https://github.com/propeller-heads/tycho-indexer/commit/d5282cb9575c202b7353a63f20436c26bb01012c))
* fix pagination for contract_state ([22c8497](https://github.com/propeller-heads/tycho-indexer/commit/22c8497a0e9d1266102997f3bb44f617ac389977))
* fix pagination for contract_state by chain ([3e543e4](https://github.com/propeller-heads/tycho-indexer/commit/3e543e4fc99d1bb3518eee63e6e44a8a9e5d7639))
* fix pagination for fetching ProtocolState, add tests ([0ba95d9](https://github.com/propeller-heads/tycho-indexer/commit/0ba95d9bbbada13db9ccde5617e47383ab8f90a4))
* paginate contract_state using chunked ids ([87e702e](https://github.com/propeller-heads/tycho-indexer/commit/87e702e3ebcaff14633772ec210c9c276ebe6989))
* post rebase fixes, use Bytes instead of contractId ([ae57952](https://github.com/propeller-heads/tycho-indexer/commit/ae57952f6409923001222469eecf536617df4aef))
* rebased contract struct name change ([d04a519](https://github.com/propeller-heads/tycho-indexer/commit/d04a5192354dd5e14754bbaa2ed96bcc16e655a3))
* remove unnecessary filters ([c94be3f](https://github.com/propeller-heads/tycho-indexer/commit/c94be3fc650ce7e104b4d7221eabcbd588fac940))
* remove unnecessary uniqueness constraints ([7187f70](https://github.com/propeller-heads/tycho-indexer/commit/7187f70c8f42a09f178ef6b6bc91c543d9252661))
* undo formatting errors and typos ([dc68a61](https://github.com/propeller-heads/tycho-indexer/commit/dc68a6103e31eb3451a375f526f76bda531679b3))
* use total from pagination response to end pagination looping ([c763f96](https://github.com/propeller-heads/tycho-indexer/commit/c763f96c9cb599844178e3900b2954b84c4c1307))

## [0.20.0](https://github.com/propeller-heads/tycho-indexer/compare/0.19.0...0.20.0) (2024-09-26)


### Features

* **rpc:** Add a cache for contract storage. ([8e9c6d3](https://github.com/propeller-heads/tycho-indexer/commit/8e9c6d3c2c6a2ed5f3d54e572b93979b63e14817))
* **rpc:** Add a cache for protocol state. ([e020b08](https://github.com/propeller-heads/tycho-indexer/commit/e020b081f6102f97c40e3efea938af7e2aca81c5))
* **rpc:** Generalize RPC caching strategy. ([e4e4226](https://github.com/propeller-heads/tycho-indexer/commit/e4e4226b44a5c9dda881a4627831e4c10391f18c))
* **rpc:** Protocol state and contract storage rpc caching ([#378](https://github.com/propeller-heads/tycho-indexer/issues/378)) ([9cccd5d](https://github.com/propeller-heads/tycho-indexer/commit/9cccd5d0abf19d53d74ea07ad0ba6051f53a1d3c))

## [0.19.0](https://github.com/propeller-heads/tycho-indexer/compare/0.18.4...0.19.0) (2024-09-26)


### Features

* **tycho-client-py:** add no-tls flag to `TychoStream` ([68a184e](https://github.com/propeller-heads/tycho-indexer/commit/68a184e4f03654692444a93fa72bc22fed4757d8))
* **tycho-client:** add `no-tls` flag to allow using unsecured transports ([2f56780](https://github.com/propeller-heads/tycho-indexer/commit/2f5678025418ee0066d079d531b790d0ea1075d0))
* **tycho-client:** add `user-agent` to websocket connection requests ([008ab20](https://github.com/propeller-heads/tycho-indexer/commit/008ab20676b5021c5257988d076db547ffb9da5f))
* **tycho-client:** add auth key and support for https ([#379](https://github.com/propeller-heads/tycho-indexer/issues/379)) ([c37c9ad](https://github.com/propeller-heads/tycho-indexer/commit/c37c9adc21c81ee241cd1affe0e7e3425272f485))
* **tycho-client:** add Auth to websocket client ([e2e6ade](https://github.com/propeller-heads/tycho-indexer/commit/e2e6adefcb3e926111f3e0ab3fc75f1f603a7a5f))
* **tycho-client:** enable HTTPS and add auth key ([bbd0eee](https://github.com/propeller-heads/tycho-indexer/commit/bbd0eee1af932ba84e913f5e173e08a3f43010c6))
* **tycho-client:** get `auth-key` from env or cli ([37d02a0](https://github.com/propeller-heads/tycho-indexer/commit/37d02a0ce085eea1b32d7abc84800bdf0143937d))

## [0.18.4](https://github.com/propeller-heads/tycho-indexer/compare/0.18.3...0.18.4) (2024-09-26)


### Bug Fixes

* fix delete protocol script bug ([450e6c0](https://github.com/propeller-heads/tycho-indexer/commit/450e6c048337e40c65f40ef2eee0d91426f3611d))
* remove deleted attributes from default table ([aab9a76](https://github.com/propeller-heads/tycho-indexer/commit/aab9a76ecdd3d87379e5caff80ae587aa0dd9d53))
* Remove deleted attributes from default table ([#374](https://github.com/propeller-heads/tycho-indexer/issues/374)) ([a6b15b6](https://github.com/propeller-heads/tycho-indexer/commit/a6b15b63ca7e851300dde9a382ce66278c271ebc))
* skip deleted attributes delete query if no attr are deleted ([0e7bb6c](https://github.com/propeller-heads/tycho-indexer/commit/0e7bb6cb5c6bbf4d1bd913e9848f81c8034c90ee))

## [0.18.3](https://github.com/propeller-heads/tycho-indexer/compare/0.18.2...0.18.3) (2024-09-23)


### Bug Fixes

* add chain awareness to extraction state block migration ([ef92989](https://github.com/propeller-heads/tycho-indexer/commit/ef92989ee682003a6add6900a397f11cb0e7a9da))
* add chain awareness to extraction state block migration ([#361](https://github.com/propeller-heads/tycho-indexer/issues/361)) ([7a509e1](https://github.com/propeller-heads/tycho-indexer/commit/7a509e10a5d708141d801c65b4c608b0b7a94f40))

## [0.18.2](https://github.com/propeller-heads/tycho-indexer/compare/0.18.1...0.18.2) (2024-09-23)

## [0.18.1](https://github.com/propeller-heads/tycho-indexer/compare/0.18.0...0.18.1) (2024-09-20)

## [0.18.0](https://github.com/propeller-heads/tycho-indexer/compare/0.17.5...0.18.0) (2024-09-19)


### Features

* automate removal of orphaned transactions ([d0939a5](https://github.com/propeller-heads/tycho-indexer/commit/d0939a59bf2b1e05fe48ddec0d0a2af73980f79d))
* Automate removal of orphaned transactions from the DB ([#349](https://github.com/propeller-heads/tycho-indexer/issues/349)) ([898460d](https://github.com/propeller-heads/tycho-indexer/commit/898460dfaf10d40f2f1c714d7deec6ca9fc73ae5))


### Bug Fixes

* delete transactions in batches ([fd128fd](https://github.com/propeller-heads/tycho-indexer/commit/fd128fd2a8bd600a7ae21ca9f0842d0ac38125f9))
* improve transaction clean up script to minimise db locks ([fffe9cc](https://github.com/propeller-heads/tycho-indexer/commit/fffe9cc7d085a1f9633806ebe1664eb3d122600a))
* skip batching on search phase ([ceb5376](https://github.com/propeller-heads/tycho-indexer/commit/ceb5376ed4da853ae80f00410e7c442f59a1cd4d))
* speed up deletions with indexes ([ebea183](https://github.com/propeller-heads/tycho-indexer/commit/ebea1837a051bf36ac2252d6ecaadbc28beb0c23))

## [0.17.5](https://github.com/propeller-heads/tycho-indexer/compare/0.17.4...0.17.5) (2024-09-19)


### Bug Fixes

* fetch contracts from deltas buffer if not in db yet ([1321cbd](https://github.com/propeller-heads/tycho-indexer/commit/1321cbd0da60b732043bb570050d59d164a135d0))
* fetch contracts from deltas buffer if not in db yet ([#370](https://github.com/propeller-heads/tycho-indexer/issues/370)) ([b12538d](https://github.com/propeller-heads/tycho-indexer/commit/b12538d62f912641b81ee006662cdbbde6a7a0c3))
* rebase and fix subsequent changes ([6a2b3e3](https://github.com/propeller-heads/tycho-indexer/commit/6a2b3e32718af7f960d3d4388a519cd00c1ddd9e))

## [0.17.4](https://github.com/propeller-heads/tycho-indexer/compare/0.17.3...0.17.4) (2024-09-19)


### Bug Fixes

* adapt tycho-client-py to work with `Bytes` ([562e45a](https://github.com/propeller-heads/tycho-indexer/commit/562e45ac9d9b13aad358a3fc603b23fc9b42dc41))
* release config wrong crate name ([a024672](https://github.com/propeller-heads/tycho-indexer/commit/a024672489f6944349deba0b3a574135ae3223fd))
* release config wrong crate name ([#371](https://github.com/propeller-heads/tycho-indexer/issues/371)) ([452f88a](https://github.com/propeller-heads/tycho-indexer/commit/452f88a4637a0af7a15199bfe6339efc66d29dae))
* rename tycho analyzer in release config ([0a2a168](https://github.com/propeller-heads/tycho-indexer/commit/0a2a1683d5fdb250b0483a4f0427898fa10ce33b))

## [0.17.3](https://github.com/propeller-heads/tycho-indexer/compare/0.17.2...0.17.3) (2024-09-17)


### Bug Fixes

* protocol system delete script ([#365](https://github.com/propeller-heads/tycho-indexer/issues/365)) ([e3c3313](https://github.com/propeller-heads/tycho-indexer/commit/e3c3313afd76387c274fe39209ea6b6c0c978c1c))
* skip deleting accounts also linked to tokens used by other systems ([baefd07](https://github.com/propeller-heads/tycho-indexer/commit/baefd0713aeee1d45fa8edd0ee6c4b0b51c81c18))

## [0.17.2](https://github.com/propeller-heads/tycho-indexer/compare/0.17.1...0.17.2) (2024-09-16)

## [0.17.1](https://github.com/propeller-heads/tycho-indexer/compare/0.17.0...0.17.1) (2024-09-13)

## [0.17.0](https://github.com/propeller-heads/tycho-indexer/compare/0.16.4...0.17.0) (2024-09-11)


### Features

* expose `items()` directly on `TokenBalances` ([e5eb17e](https://github.com/propeller-heads/tycho-indexer/commit/e5eb17ec6b3c704574c07b97562d953942ff286f))

## [0.16.4](https://github.com/propeller-heads/tycho-indexer/compare/0.16.3...0.16.4) (2024-09-06)

## [0.16.3](https://github.com/propeller-heads/tycho-indexer/compare/0.16.2...0.16.3) (2024-09-06)


### Bug Fixes

* **rpc:** fi handling of default version ts ([9d60af2](https://github.com/propeller-heads/tycho-indexer/commit/9d60af2e3902a9817b5ad9cac91567a788ec9e24))
* **rpc:** Fix handling of default version ts ([#352](https://github.com/propeller-heads/tycho-indexer/issues/352)) ([2820a42](https://github.com/propeller-heads/tycho-indexer/commit/2820a42c8dd33f6d4d62816ceafad605ff493f8f))

## [0.16.2](https://github.com/propeller-heads/tycho-indexer/compare/0.16.1...0.16.2) (2024-09-06)


### Bug Fixes

* Improve protocol system deletion script ([#358](https://github.com/propeller-heads/tycho-indexer/issues/358)) ([6f20892](https://github.com/propeller-heads/tycho-indexer/commit/6f2089251a054d563785817adb7c46dbb8e5e82a))
* remove unnecessary queries from deletion script ([9c6f7a4](https://github.com/propeller-heads/tycho-indexer/commit/9c6f7a453879d5add16b5e00a8796fab590f4d95))

## [0.16.1](https://github.com/propeller-heads/tycho-indexer/compare/0.16.0...0.16.1) (2024-09-05)


### Bug Fixes

* Delete protocol system script to delete tokens as necessary ([#356](https://github.com/propeller-heads/tycho-indexer/issues/356)) ([3e1138b](https://github.com/propeller-heads/tycho-indexer/commit/3e1138ba25d5d8b6cb10c7b43c2cf99d0a9ee1df))
* delete token's account entries too ([0862e39](https://github.com/propeller-heads/tycho-indexer/commit/0862e39ca4165c3053f18d0b21a79c85e1789a3e))
* delete tokens that belong solely to the protocol system ([2289173](https://github.com/propeller-heads/tycho-indexer/commit/2289173bbe93f7bc7116647b5089b1f4bf617d24))
* remove unnecessary count check ([9b40290](https://github.com/propeller-heads/tycho-indexer/commit/9b40290f28d6dd3db322d3ce8319c1ed58d3d846))

## [0.16.0](https://github.com/propeller-heads/tycho-indexer/compare/0.15.2...0.16.0) (2024-09-04)


### Features

* Create remove protocol script ([#311](https://github.com/propeller-heads/tycho-indexer/issues/311)) ([b6b818b](https://github.com/propeller-heads/tycho-indexer/commit/b6b818b3809b05f54a2017f241ae45872b688ce4))
* **db:** add cascade deletes to protocol_system related tables ([f8326e2](https://github.com/propeller-heads/tycho-indexer/commit/f8326e27aab5a1b88fd85f4cc3aece5b12ba4271))
* **db:** add script to delete protocol system from db ([07ffa77](https://github.com/propeller-heads/tycho-indexer/commit/07ffa779c4d4f10fdb1625ecaedeaf298d3c8afa))
* skip deleting shared accounts ([37b17d2](https://github.com/propeller-heads/tycho-indexer/commit/37b17d2c19337b4bae2e05cc1e7aefa0d17ed48c))


### Bug Fixes

* delete substreams cursor too ([be9ebfa](https://github.com/propeller-heads/tycho-indexer/commit/be9ebfa5f0fee568abe089af878d276f3a5de542))
* typo in name of sushiswap configs ([3489aab](https://github.com/propeller-heads/tycho-indexer/commit/3489aab1374a8ca925a737c62d2f45da55899005))
* update protocol delete script to be more configurable ([a76e5db](https://github.com/propeller-heads/tycho-indexer/commit/a76e5db51f7b102c7e29a25fbf36af4633e9d68b))

## [0.15.2](https://github.com/propeller-heads/tycho-indexer/compare/0.15.1...0.15.2) (2024-09-04)


### Bug Fixes

* **tycho-client-py:** backward compatibility of `ContractStateParams` ([c5373a1](https://github.com/propeller-heads/tycho-indexer/commit/c5373a1cfb56a7ef8a9421424410e84a74809d46))
* **tycho-client-py:** backward compatibility of `ContractStateParams` ([#354](https://github.com/propeller-heads/tycho-indexer/issues/354)) ([81f0afc](https://github.com/propeller-heads/tycho-indexer/commit/81f0afcc0e898c7d156c53ebc91cffb2fa745290))

## [0.15.1](https://github.com/propeller-heads/tycho-indexer/compare/0.15.0...0.15.1) (2024-09-03)

## [0.15.0](https://github.com/propeller-heads/tycho-indexer/compare/0.14.0...0.15.0) (2024-09-02)


### Features

* Add block_id column to extraction_state table ([78514f5](https://github.com/propeller-heads/tycho-indexer/commit/78514f58607f851f7e29b0f4085f054189f07072))
* Add block_id column to extraction_state table ([#287](https://github.com/propeller-heads/tycho-indexer/issues/287)) ([ea7434a](https://github.com/propeller-heads/tycho-indexer/commit/ea7434a8cdf727654c8c03658f5552a2ac71cd63))
* add block_id to extraction_state db table ([e0c4f35](https://github.com/propeller-heads/tycho-indexer/commit/e0c4f350f1e0334f37f928d5eb09494223283ad1))


### Bug Fixes

* remove Block from get_state return ([563de75](https://github.com/propeller-heads/tycho-indexer/commit/563de758ce44e1a3e5e60cd63586a65e0a73e699))

## [0.14.0](https://github.com/propeller-heads/tycho-indexer/compare/0.13.0...0.14.0) (2024-09-02)


### Features

* Remove chain from contract id param ([#346](https://github.com/propeller-heads/tycho-indexer/issues/346)) ([3bb61a4](https://github.com/propeller-heads/tycho-indexer/commit/3bb61a49f695dad6e010e831a8e38a2e4d8defe9))
* **rpc:** remove chain from contract id param ([8092a1e](https://github.com/propeller-heads/tycho-indexer/commit/8092a1ef6e53edb3262bdd6d307c0efe78844c14))

## [0.13.0](https://github.com/propeller-heads/tycho-indexer/compare/0.12.0...0.13.0) (2024-08-30)


### Features

* add autodeletion to partition tables ([6302ae8](https://github.com/propeller-heads/tycho-indexer/commit/6302ae8c68368ca1af99c1aab939adfd993b24a7))
* Add autodeletion to partition tables ([#347](https://github.com/propeller-heads/tycho-indexer/issues/347)) ([e482522](https://github.com/propeller-heads/tycho-indexer/commit/e482522cda1ca7df8733c6a7bc41f486ca0c403c))

## [0.12.0](https://github.com/propeller-heads/tycho-indexer/compare/0.11.1...0.12.0) (2024-08-29)


### Features

* Move rpc endpoint params to request body ([#344](https://github.com/propeller-heads/tycho-indexer/issues/344)) ([c6ff178](https://github.com/propeller-heads/tycho-indexer/commit/c6ff17817b330957eff8250bc22e9fb6faff9f92))
* move rpc endpoints url params to request body ([4ad2a90](https://github.com/propeller-heads/tycho-indexer/commit/4ad2a908202e1411958770b739c09510a854cffb))
* **tycho-client-py:** update rpc client to use new endpoints ([f934269](https://github.com/propeller-heads/tycho-indexer/commit/f934269727f8521b8113994ef171878ba64de3f4))
* **tycho-client:** update rpc to use new endpoints ([6e79ed1](https://github.com/propeller-heads/tycho-indexer/commit/6e79ed113fb86b8d2064092fdd75e9728dd84fe8))

## [0.11.1](https://github.com/propeller-heads/tycho-indexer/compare/0.11.0...0.11.1) (2024-08-27)


### Bug Fixes

* **dto:** Use capitalize enum values. ([0707bde](https://github.com/propeller-heads/tycho-indexer/commit/0707bde431ea4da6b1ca5e76677e8e958e13abea))
* **dto:** Use capitalize enum values. ([#339](https://github.com/propeller-heads/tycho-indexer/issues/339)) ([1989d0c](https://github.com/propeller-heads/tycho-indexer/commit/1989d0c960b01cd2391e1364dc571922b0728d27))

## [0.11.0](https://github.com/propeller-heads/tycho-indexer/compare/0.10.0...0.11.0) (2024-08-26)


### Features

* add non-SIP protected binary directory option ([b4d3d69](https://github.com/propeller-heads/tycho-indexer/commit/b4d3d694e0c9c6601ab04dcd74da0aa75383f818))


### Bug Fixes

* support range tvl threshold on client stream creation ([fbbd8cf](https://github.com/propeller-heads/tycho-indexer/commit/fbbd8cf9404e74002f87ea80af9bba83d26e1dd4))
* **tycho-client:** remove hardcoded versioning on cli ([5a721f4](https://github.com/propeller-heads/tycho-indexer/commit/5a721f44c423330c18ba17874f2434b956c77a7b))
* update contract request body to include protocol_system ([b2858e9](https://github.com/propeller-heads/tycho-indexer/commit/b2858e9c61f66017fd6feb3f396758216eea94f9))
* Update python client ([#338](https://github.com/propeller-heads/tycho-indexer/issues/338)) ([0b3e59d](https://github.com/propeller-heads/tycho-indexer/commit/0b3e59dfcb967eb65e92fbeeb7cba64b701e5c61))

## [0.10.0](https://github.com/propeller-heads/tycho-indexer/compare/0.9.1...0.10.0) (2024-08-19)


### Features

* **tycho-client:** Add tvl range as a component filter ([6a197b7](https://github.com/propeller-heads/tycho-indexer/commit/6a197b745aaf7219f4b25fb3409dbcca704e70f1))
* **tycho-client:** Add tvl range as a component filter ([#328](https://github.com/propeller-heads/tycho-indexer/issues/328)) ([a33fb5c](https://github.com/propeller-heads/tycho-indexer/commit/a33fb5c518977add7f3ade77125cf408fe930c0f))
* **tycho-client:** update cli to accept min tvl range input ([78873c9](https://github.com/propeller-heads/tycho-indexer/commit/78873c9dedd185a9feae8198b4e3312d74709e82))

## [0.9.1](https://github.com/propeller-heads/tycho-indexer/compare/0.9.0...0.9.1) (2024-08-16)


### Bug Fixes

* deserialise WebSocketMessage workaround ([8021493](https://github.com/propeller-heads/tycho-indexer/commit/80214933c76d228a67ab4420df0642bd2f7821a4))
* improve deserialisation error messages ([d9e56b1](https://github.com/propeller-heads/tycho-indexer/commit/d9e56b1cbef1bb874fa401f1df6d40a10028e690))
* WebSocketMessage deserialisation bug ([#327](https://github.com/propeller-heads/tycho-indexer/issues/327)) ([6dfebb0](https://github.com/propeller-heads/tycho-indexer/commit/6dfebb0e5718979023cb2bb8890566cc740647f1))

## [0.9.0](https://github.com/propeller-heads/tycho-indexer/compare/0.8.3...0.9.0) (2024-08-15)


### Features

* **rpc:** make serde error if unknown field in bodies ([2aaaf0e](https://github.com/propeller-heads/tycho-indexer/commit/2aaaf0edbc814d26a8a89c965c2d3800e82dc0c9))

## [0.8.3](https://github.com/propeller-heads/tycho-indexer/compare/0.8.2...0.8.3) (2024-08-15)


### Bug Fixes

* **client-py:** fix hexbytes decoding and remove camelCase aliases ([4a0432e](https://github.com/propeller-heads/tycho-indexer/commit/4a0432e4446c6b0595168d0c99663f894d490694))
* **client-py:** fix hexbytes encoding and remove camelCase aliases ([#322](https://github.com/propeller-heads/tycho-indexer/issues/322)) ([10272a4](https://github.com/propeller-heads/tycho-indexer/commit/10272a4a2d35ece95713bf983efd5978a7587ca4))

## [0.8.2](https://github.com/propeller-heads/tycho-indexer/compare/0.8.1...0.8.2) (2024-08-14)


### Bug Fixes

* skip buggy clippy warning ([feeb6a1](https://github.com/propeller-heads/tycho-indexer/commit/feeb6a11692d6fabd171cff8cc0bd9be46ad4461))
* specify extractor on rpc requests ([98d57d2](https://github.com/propeller-heads/tycho-indexer/commit/98d57d281c32edcf0790e1d33fadcca0ca13a613))
* Specify extractor on rpc requests ([#323](https://github.com/propeller-heads/tycho-indexer/issues/323)) ([a45df90](https://github.com/propeller-heads/tycho-indexer/commit/a45df90fe5010a965404e368febca4dc414fe0f0))

## [0.8.1](https://github.com/propeller-heads/tycho-indexer/compare/0.8.0...0.8.1) (2024-08-09)


### Bug Fixes

* Hanging client on max connection attempts reached ([#317](https://github.com/propeller-heads/tycho-indexer/issues/317)) ([f9ca57a](https://github.com/propeller-heads/tycho-indexer/commit/f9ca57a1ad9af8af3d5b8e136abc5ea85641ef16))
* hanging client when max connection attempts reached ([feddb47](https://github.com/propeller-heads/tycho-indexer/commit/feddb4725143bde9cb0c99a8b7ca9c4d60ec741f))
* propagate max connection attempts error correctly ([6f7f35f](https://github.com/propeller-heads/tycho-indexer/commit/6f7f35fa9d56a8efe2ed2538b7f02543a5300b4a))
* **tycho-client:** reconnection error handling ([4829f97](https://github.com/propeller-heads/tycho-indexer/commit/4829f976e092da5ef0fdb96e353fb6157557f825))

## [0.8.0](https://github.com/propeller-heads/tycho-indexer/compare/0.7.5...0.8.0) (2024-08-09)


### Features

* change workflow behaviour ([61f7517](https://github.com/propeller-heads/tycho-indexer/commit/61f7517b64cb62468160a88eb485c2a91bceef49))
* change workflow behaviour ([#316](https://github.com/propeller-heads/tycho-indexer/issues/316)) ([3ca195b](https://github.com/propeller-heads/tycho-indexer/commit/3ca195b9f1a7ce76f857e3b7ad76d39d2a374a60))

## [0.7.5](https://github.com/propeller-heads/tycho-indexer/compare/0.7.4...0.7.5) (2024-08-07)


### chore

* black format code ([7dcb55a](https://github.com/propeller-heads/tycho-indexer/commit/7dcb55af3eea7c807e3c9491bd9d0574533ff8df))
* Remove unneeded new method and outdated comment ([d402acb](https://github.com/propeller-heads/tycho-indexer/commit/d402acb6c2e52f537f27b82d8b6dfd8449627a4a))

### fix

* Add missing requests dependency ([d64764c](https://github.com/propeller-heads/tycho-indexer/commit/d64764ca07cadc8f312c6d1c26f00da367d06447))
* Add property aliases to ResponseAccount. ([298c688](https://github.com/propeller-heads/tycho-indexer/commit/298c688fd8acca21da8c3cf45be953fbf1153b8e))

## [0.7.4](https://github.com/propeller-heads/tycho-indexer/compare/0.7.3...0.7.4) (2024-08-07)


### fix

* fix usv2 substreams merge bug ([88ce6c6](https://github.com/propeller-heads/tycho-indexer/commit/88ce6c6f7a440681113e442342e877cb6091656d))

## [0.7.3](https://github.com/propeller-heads/tycho-indexer/compare/0.7.2...0.7.3) (2024-08-06)


### chore

* Add trace logging for tokens queries ([01a5bbc](https://github.com/propeller-heads/tycho-indexer/commit/01a5bbcca61d8dde3620790ab11529e635b07cce))

### fix

* add defaults for initialized_accounts configs ([2becb5e](https://github.com/propeller-heads/tycho-indexer/commit/2becb5ea60a24f51fee9a49ce5b2b1b2edd213f9))
* changed tag format ([764d9e6](https://github.com/propeller-heads/tycho-indexer/commit/764d9e6bb33e623780f58c4be4628ba6985e0d58))
* ci-cd-templates path ([1c21f79](https://github.com/propeller-heads/tycho-indexer/commit/1c21f793bfabfdd233efa1c58af6cf0c686d2a8e))
* clean up defaults and spkg name ([eac825c](https://github.com/propeller-heads/tycho-indexer/commit/eac825c2d5d29586d53ba773c8f3695504a4298b))
* dockerfile restore quotes ([1d73485](https://github.com/propeller-heads/tycho-indexer/commit/1d73485f97b4dbe7dba188b8bd1b772b3107a01d))
* revert sushiswap config change ([b10921e](https://github.com/propeller-heads/tycho-indexer/commit/b10921e7510b229990c767d10795041a138e7a9f))

### update

* Cargo.lock ([9b129ef](https://github.com/propeller-heads/tycho-indexer/commit/9b129efa09bcd1956b56fa4c2ad1724d3a1dda12))
