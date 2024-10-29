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
