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