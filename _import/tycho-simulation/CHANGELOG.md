## [1.1.0](https://github.com/propeller-heads/protosim/compare/1.0.0...1.1.0) (2024-10-17)


### Features

* implement get_contract_bytecode util function ([a4bce5d](https://github.com/propeller-heads/protosim/commit/a4bce5d8100c5ecbfcdfc39a2af47284c8412edf))


### Bug Fixes

* make get_contract_bytecote pub ([50fd8e7](https://github.com/propeller-heads/protosim/commit/50fd8e7413863a1208fc7bf9d38e3bfb99163c29))

## 1.0.0 (2024-10-17)


### Features

* (NTQ) Add gas to ERC20Token object ([f88b679](https://github.com/propeller-heads/protosim/commit/f88b679fec33aaa07cf1161be728fb9ce0ac358f))
* Add console subscriber option to run locally ([da20c5c](https://github.com/propeller-heads/protosim/commit/da20c5c9003508ccd8be9abff5d03b3836289ea8))
* Add gas prices to NTQv2 ([b082491](https://github.com/propeller-heads/protosim/commit/b0824917f22cf841e52c9af8abc91f6387a867d7))
* Convert protosim dir into src ([41577f1](https://github.com/propeller-heads/protosim/commit/41577f151fb2e1086a1f2132d048e97c9277ae67))
* **decoder:** Make handling vm updates public. ([84ba99f](https://github.com/propeller-heads/protosim/commit/84ba99f4e69dde6085d17e141ba83bdd20364aa6))
* Don't use enum_dispatch in ProtocolSim ([30beec1](https://github.com/propeller-heads/protosim/commit/30beec1c3d025740d7dd5ef2a94c4b80ce66e327))
* Move graph (Protograph) into the NTQ src directory ([72e26d2](https://github.com/propeller-heads/protosim/commit/72e26d26eaeb29af135c8ca7f6e46bad82c2b9b2))
* **ntq:** Update tycho-client for smoother startups ([0cf633b](https://github.com/propeller-heads/protosim/commit/0cf633b1f1cf059c6534cd40323464006f380813))
* **ntq:** Update tycho-client. ([9141ce2](https://github.com/propeller-heads/protosim/commit/9141ce2596464d0fc4a05668da9b705d9283c74f))
* NTQv2 deduct gas from token price calc ([83095b4](https://github.com/propeller-heads/protosim/commit/83095b4c89959b4b26aaf098d9efa15f7a9d07aa))
* NTQv2 pass gas amount to price calculation ([3466807](https://github.com/propeller-heads/protosim/commit/34668076c364327ffe91bdf18959891a995f8c2e))
* **protosim-py:** Add third party pool. ([04b56d8](https://github.com/propeller-heads/protosim/commit/04b56d83bee1db704b767460834e6d0126d5bcdd))
* **protosim:** Allow adding python sources ([02fbfcc](https://github.com/propeller-heads/protosim/commit/02fbfccf9a8f649d495f14e79f7891fff8be1b49))
* **protosim:** Replace opcode traces with foundry traces. ([07588e5](https://github.com/propeller-heads/protosim/commit/07588e5947b51fadd0b800daaf11a146f322aae9))
* **py:** Expose Starknet structs publicly. ([c48d0d9](https://github.com/propeller-heads/protosim/commit/c48d0d9306ce404092f02956c00f6f684146a99e))
* **quoter:** Support new and removed pools. ([906de9e](https://github.com/propeller-heads/protosim/commit/906de9ec1cfd273b8d499ad79f4fe4d221b6d96e))
* Setup protosim repo ([3a66682](https://github.com/propeller-heads/protosim/commit/3a66682c7d6c2a1b773f1e991ae7a3d9734fd802))
* **traces:** Add open telemetry tracing ([648b96c](https://github.com/propeller-heads/protosim/commit/648b96c274f03d4d355135c6ea7a02bb2f5073d4))
* **TTP:** Add logic to pull code for stateless contracts ([c83b282](https://github.com/propeller-heads/protosim/commit/c83b2822d02e5843a2c816ccad6491e151312809))
* update tycho-client to version 0.9.1 ([14be854](https://github.com/propeller-heads/protosim/commit/14be854e95c9129c802dab383a2c862d01cefe45))


### Bug Fixes

* AccountUpdate & ResponseAccount substitution ([1a21ef5](https://github.com/propeller-heads/protosim/commit/1a21ef5560d840fdfd6b1c9412fecee2abc9c3e3))
* add decode failed pools to skipped pools list ([d3d979c](https://github.com/propeller-heads/protosim/commit/d3d979ca155288ee2cfc3b70651f6e3e85158d20))
* Also set EVM to Cancun if trace is enabled ([286316a](https://github.com/propeller-heads/protosim/commit/286316a810ddd37b492670bf661874576eb2377c))
* changed pipeline for test and lint to generate a token for git r… ([#2](https://github.com/propeller-heads/protosim/issues/2)) ([8a5e879](https://github.com/propeller-heads/protosim/commit/8a5e879087e9648b855a9e231fbf40028085c088))
* dependecies looser requirments ([6fa7461](https://github.com/propeller-heads/protosim/commit/6fa746193612443da5874ad429b2afae37963d95))
* ignored pools update ([5c361c5](https://github.com/propeller-heads/protosim/commit/5c361c5b67883df384e01758e83c4fd40c11af57))
* improve db singleton initialize logic ([aa121f6](https://github.com/propeller-heads/protosim/commit/aa121f697ead66c304b66ff9b530282c872fa807))
* improve snapshot logs ([463f5d1](https://github.com/propeller-heads/protosim/commit/463f5d1e3327bd569c8cabb44e2899df56408678))
* improve TTP snapshot decoding error logs ([143feb5](https://github.com/propeller-heads/protosim/commit/143feb533ebe98498332b79e47977fc277ac0b25))
* initialize tycho db singleton on decoder init ([ff0fc4d](https://github.com/propeller-heads/protosim/commit/ff0fc4daf9f74ebd26ff4ffce0b3f38c45ff9d24))
* Misc fixes ([8056c93](https://github.com/propeller-heads/protosim/commit/8056c93d084eaa3852244669f2e921c9af29a4ff))
* Misc fixes around byte decoding and encoding. ([a679892](https://github.com/propeller-heads/protosim/commit/a679892455d760f0ae5bd2a3ef6231c32709b874))
* NTQ gas - take min value of ERC20Token array ([b1249af](https://github.com/propeller-heads/protosim/commit/b1249afecb54b7536429b5c3231f560c95eb09b1))
* **protosim:** Update time dependency. ([1482517](https://github.com/propeller-heads/protosim/commit/1482517cefb24894417d565f6bd043b2b91539ad))
* **quoter:** Add separate method to clear route cache. ([1b67bb2](https://github.com/propeller-heads/protosim/commit/1b67bb2ea86f85a84786212d2995983c3144c626))
* **quoter:** Update all tycho-client dependencies ([b830936](https://github.com/propeller-heads/protosim/commit/b830936cae107ef12cee00ad8d5aae2fd559283d))
* **quoter:** Update tycho-client dependency ([e23769f](https://github.com/propeller-heads/protosim/commit/e23769f14724f3a7206fd4cbf98f1bd9b054f7bd))
* skip applying deltas for ignored pools ([d430b1b](https://github.com/propeller-heads/protosim/commit/d430b1b7f09c41226481f7cb155ca5f3e5611530))
* skip failing starknet tests ([8fbf8ac](https://github.com/propeller-heads/protosim/commit/8fbf8acb00ea159fa8ae7ae69ee0d6ffc40f88e8))
* Stale prices ([eb25a5a](https://github.com/propeller-heads/protosim/commit/eb25a5ac40aac88b3c0027c9e60451c2da284d26))
* Support clone in DodoPoolState ([fdf2028](https://github.com/propeller-heads/protosim/commit/fdf202802bf813dc36ab2d043fa52ef3a2492da3))
* **ttp:** bump `tycho-indexer-client` version ([45fccf8](https://github.com/propeller-heads/protosim/commit/45fccf87e8df85f25f19a56fc2af3c90447532a0))
* **ttp:** fix tycho-client import ([34c893c](https://github.com/propeller-heads/protosim/commit/34c893c71317c4511d9b844a15b3c6cb036d39d5))
* **tycho-decoder:** fix typo in `pool.manual_updates` ([e696e3d](https://github.com/propeller-heads/protosim/commit/e696e3dd9b934aa460738c349f15ac3755f403e3))
* update tycho client ([f1b140c](https://github.com/propeller-heads/protosim/commit/f1b140ce985cfdfde8a6e236c2a98facceaab855))
* update tycho-client dependency ([78047bf](https://github.com/propeller-heads/protosim/commit/78047bfcede638f9c795158c9e19ed0ebae162e2))
* Use RwLock instead of RefCell in DodoPoolState ([51a2f87](https://github.com/propeller-heads/protosim/commit/51a2f87434256bdf5c725157eab68a3d07408658))

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
