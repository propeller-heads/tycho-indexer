## [0.137.0](https://github.com/propeller-heads/tycho-indexer/compare/0.136.1...0.137.0) (2026-02-06)


### Features

* Notify Tycho SDK of new releases ([d86899f](https://github.com/propeller-heads/tycho-indexer/commit/d86899f5e25f72ddc9297631c33838ec6267ac59))
* Notify Tycho SDK of new releases ([#842](https://github.com/propeller-heads/tycho-indexer/issues/842)) ([e020d97](https://github.com/propeller-heads/tycho-indexer/commit/e020d970abaecd32ee0c9977837030bc9e8b9d6f))

## [0.136.1](https://github.com/propeller-heads/tycho-indexer/compare/0.136.0...0.136.1) (2026-02-05)

## [0.136.0](https://github.com/propeller-heads/tycho-indexer/compare/0.135.0...0.136.0) (2026-02-03)


### Features

* **block_history:** add error handling for partial block reverts and ensure latest block is a partial block ([e8e61fd](https://github.com/propeller-heads/tycho-indexer/commit/e8e61fd77adedd5d69815275818ded93507cb83c))
* **block_history:** add support for partial block handling and position determination and improve test coverage ([d8eacab](https://github.com/propeller-heads/tycho-indexer/commit/d8eacab821a54a9bcee964fb8bbfb8846a4740c7))
* **cli:** add partial_blocks flag to enable receiving incremental block updates ([cb27e64](https://github.com/propeller-heads/tycho-indexer/commit/cb27e64d3fc29af2280e5024a6dbb65a55b0dfad))
* client supports partial blocks ([#838](https://github.com/propeller-heads/tycho-indexer/issues/838)) ([7ec8b14](https://github.com/propeller-heads/tycho-indexer/commit/7ec8b145aa4a8e82aed52c4983d6841108a78fa5))
* **merge:** enhance merge logic to handle partial block validation and error reporting ([d77e22a](https://github.com/propeller-heads/tycho-indexer/commit/d77e22a9e78f21652dedb5731863790cdf48205c))
* **stream:** add send_partials flag to `TychoStreamBuilder` to enable receiving incremental block updates ([6c6a69a](https://github.com/propeller-heads/tycho-indexer/commit/6c6a69a83b94982d9ed39cc16b73d91685060798))
* **synchronizer:** add send_partials flag to `ProtocolStateSynchronizer` to enable incremental block updates ([1ed9e27](https://github.com/propeller-heads/tycho-indexer/commit/1ed9e2730ae4f4facae3ab8f514044a286a9e330))
* **synchronizer:** implement partial block handling and synchronization logic ([e7318e2](https://github.com/propeller-heads/tycho-indexer/commit/e7318e256162aa0ac770be0dc6bbb10e9cd82706))
* **synchronizer:** improve partial block handling by accepting full blocks as first messages and detecting block number increases instead of partial index decrease ([6661e76](https://github.com/propeller-heads/tycho-indexer/commit/6661e769996846b9dc9ec19858326152a369a129))

## [0.135.0](https://github.com/propeller-heads/tycho-indexer/compare/0.134.0...0.135.0) (2026-02-02)


### Features

* add partial block support to the ws ([#835](https://github.com/propeller-heads/tycho-indexer/issues/835)) ([e936191](https://github.com/propeller-heads/tycho-indexer/commit/e936191e0a3a829d40cbaf55e467614a81289cda))
* **blockchain:** add `is_partial` field to `BlockAggregatedChanges` ([156a92c](https://github.com/propeller-heads/tycho-indexer/commit/156a92c226c7cb2ba5d345cfd6333d794d5eb1d1))
* **common:** add is_partial method to check for partial block presence ([cea6371](https://github.com/propeller-heads/tycho-indexer/commit/cea63710ce9d44bbf5853d2df9c47a0e6ba76323))
* **dto:** add `is_partial` field to BlockChanges for partial block handling ([74d9631](https://github.com/propeller-heads/tycho-indexer/commit/74d9631db9d1b65a63eebea9f50092e4303c1a56))
* **dto:** add `partial_blocks` field to Subscribe command for partial block updates subscriptions ([8c67ff0](https://github.com/propeller-heads/tycho-indexer/commit/8c67ff0572838d559e4d67acae1395f4618282bb))
* **ws:** implement partial block filtering in subscription logic ([0ea7532](https://github.com/propeller-heads/tycho-indexer/commit/0ea7532d70d9d67fded35b918b9d69855dfe9a63))
* **ws:** rename partial_blocks parameter to send_partials and update related logic for block filtering ([66de802](https://github.com/propeller-heads/tycho-indexer/commit/66de80205047628f672ffaba6c305898742da927))
* **ws:** update block filtering logic for partial and revert subscriptions ([d862f04](https://github.com/propeller-heads/tycho-indexer/commit/d862f04a4e65371bb4f1335086b9d8b2e7c9b03f))

## [0.134.0](https://github.com/propeller-heads/tycho-indexer/compare/0.133.0...0.134.0) (2026-02-02)


### Features

* add optionnal partial block index to our block message structs ([bacca66](https://github.com/propeller-heads/tycho-indexer/commit/bacca66390cb0e29e3af5a0df0983d4e366ca6f6))
* add optionnal partial block index to our block message structs ([#834](https://github.com/propeller-heads/tycho-indexer/issues/834)) ([25d3623](https://github.com/propeller-heads/tycho-indexer/commit/25d3623346477f3605849cf8c91c0e8948959965))

## [0.133.0](https://github.com/propeller-heads/tycho-indexer/compare/0.132.2...0.133.0) (2026-01-30)


### Features

* bring back typetag derive to `ProtocolSim` trait ([#836](https://github.com/propeller-heads/tycho-indexer/issues/836)) ([aaaee59](https://github.com/propeller-heads/tycho-indexer/commit/aaaee590968aba1103d3bf1d9984bc10a7d08614))

## [0.132.2](https://github.com/propeller-heads/tycho-indexer/compare/0.132.1...0.132.2) (2026-01-28)


### Bug Fixes

* handle missing protocol component gracefully in PostgresGateway ([1074b45](https://github.com/propeller-heads/tycho-indexer/commit/1074b453bd33b2d350957aa07f83dc7a24cc7249))
* handle missing protocol component gracefully in PostgresGateway ([#833](https://github.com/propeller-heads/tycho-indexer/issues/833)) ([fbabc39](https://github.com/propeller-heads/tycho-indexer/commit/fbabc39fdbe4879a9528c8be855b07d774355112))

## [0.132.1](https://github.com/propeller-heads/tycho-indexer/compare/0.132.0...0.132.1) (2026-01-28)


### Bug Fixes

* substreams_lag_millis conditional on partial blocks ([ae17442](https://github.com/propeller-heads/tycho-indexer/commit/ae174423759190389199c23152821cdd6d475fa6))
* substreams_lag_millis conditional on partial blocks ([#832](https://github.com/propeller-heads/tycho-indexer/issues/832)) ([b3d6bf0](https://github.com/propeller-heads/tycho-indexer/commit/b3d6bf003f6aef7c74d8906b52311556901ee226))

## [0.132.0](https://github.com/propeller-heads/tycho-indexer/compare/0.131.0...0.132.0) (2026-01-27)


### Features

* add enable_partial_blocks option to indexer CLI ([951cb15](https://github.com/propeller-heads/tycho-indexer/commit/951cb15f60e93a7891afef218c715327cb78b234))
* add enable_partial_blocks option to indexer CLI ([#831](https://github.com/propeller-heads/tycho-indexer/issues/831)) ([8fdb033](https://github.com/propeller-heads/tycho-indexer/commit/8fdb033fa708fad5771619057a394f7221773c62))

## [0.131.0](https://github.com/propeller-heads/tycho-indexer/compare/0.130.1...0.131.0) (2026-01-27)


### Features

* expose partial blocks flad on SubstreamsStream ([ddd0054](https://github.com/propeller-heads/tycho-indexer/commit/ddd0054cb5a427e39dda81c8fe7ae03631e07d22))
* skip lag metrics on partial blocks ([dd2a783](https://github.com/propeller-heads/tycho-indexer/commit/dd2a783405621783662ce86944238489a37a9792))
* update substream dependencies ([f0b04ea](https://github.com/propeller-heads/tycho-indexer/commit/f0b04ea30a2312ac285dea9de872461ef45b637d))
* update substream stream to use v3 Request ([51dabc4](https://github.com/propeller-heads/tycho-indexer/commit/51dabc43881186ea8047bd06f0f713d9977e27bb))
* Update substreams sink files to support partial blocks ([#830](https://github.com/propeller-heads/tycho-indexer/issues/830)) ([84fd327](https://github.com/propeller-heads/tycho-indexer/commit/84fd327f0e8fb1a5c5bfac851f8b364d7cbd983c))

## [0.130.1](https://github.com/propeller-heads/tycho-indexer/compare/0.130.0...0.130.1) (2026-01-22)

## [0.130.0](https://github.com/propeller-heads/tycho-indexer/compare/0.129.1...0.130.0) (2026-01-21)


### Features

* add PartialEq and Serde to tycho-ethereum GasPrice. ([e66af2d](https://github.com/propeller-heads/tycho-indexer/commit/e66af2dfdc30e4ef82283e77137b7119f4897529))
* add PartialEq and Serde to tycho-ethereum GasPrice. ([#828](https://github.com/propeller-heads/tycho-indexer/issues/828)) ([2f2a78d](https://github.com/propeller-heads/tycho-indexer/commit/2f2a78d8512861cb4c09f97965263c4a48844363))

## [0.129.1](https://github.com/propeller-heads/tycho-indexer/compare/0.129.0...0.129.1) (2026-01-20)

## [0.129.0](https://github.com/propeller-heads/tycho-indexer/compare/0.128.0...0.129.0) (2026-01-13)


### Features

* add GasPriceGetter trait and implement gas price retrieval in EthereumRpcClient ([a276cc1](https://github.com/propeller-heads/tycho-indexer/commit/a276cc1f2e6187c65851753ac9259557c9393814))
* add GasPriceGetter trait and implement gas price retrieval in EthereumRpcClient ([#823](https://github.com/propeller-heads/tycho-indexer/issues/823)) ([ca96929](https://github.com/propeller-heads/tycho-indexer/commit/ca96929a425084d1d3fb8b8f9c99d4a65f0a26f8))

## [0.128.0](https://github.com/propeller-heads/tycho-indexer/compare/0.127.0...0.128.0) (2026-01-09)


### Features

* revert add typetag derive to `ProtocolSim` trait ([#822](https://github.com/propeller-heads/tycho-indexer/issues/822)) ([1641595](https://github.com/propeller-heads/tycho-indexer/commit/164159586d34fe62ca94f39dd812965533f2744b))

## [0.127.0](https://github.com/propeller-heads/tycho-indexer/compare/0.126.0...0.127.0) (2026-01-08)


### Features

* add typetag derive to `ProtocolSim` trait ([425c194](https://github.com/propeller-heads/tycho-indexer/commit/425c194a731df998ff94fb6610616b27cc75d969))
* add typetag derive to `ProtocolSim` trait ([#811](https://github.com/propeller-heads/tycho-indexer/issues/811)) ([bdbdf71](https://github.com/propeller-heads/tycho-indexer/commit/bdbdf713787dd76a1a228203c105391ae359da8d))

## [0.126.0](https://github.com/propeller-heads/tycho-indexer/compare/0.125.2...0.126.0) (2026-01-08)


### Features

* **migrations:** add SQL migrations for `pg_stat_statements` extension ([#820](https://github.com/propeller-heads/tycho-indexer/issues/820)) ([06599da](https://github.com/propeller-heads/tycho-indexer/commit/06599da112f3d06aa40e779404411e7cf2a86faf))
* **migrations:** add SQL scripts to create and drop pg_stat_statements extension ([4850934](https://github.com/propeller-heads/tycho-indexer/commit/4850934f9daa147ed31abecbbc7c94d05d798272))

## [0.125.2](https://github.com/propeller-heads/tycho-indexer/compare/0.125.1...0.125.2) (2025-12-19)


### Bug Fixes

* Update error message in query_pool_swap function ([d4b5450](https://github.com/propeller-heads/tycho-indexer/commit/d4b54505202e380c9467ef0ca5c0adc33a69861f))
* Update error message in query_pool_swap function ([#812](https://github.com/propeller-heads/tycho-indexer/issues/812)) ([7fd85ff](https://github.com/propeller-heads/tycho-indexer/commit/7fd85ff84fda2b641310b2ff28c6e9d6d72aa228))

## [0.125.1](https://github.com/propeller-heads/tycho-indexer/compare/0.125.0...0.125.1) (2025-12-17)

## [0.125.0](https://github.com/propeller-heads/tycho-indexer/compare/0.124.0...0.125.0) (2025-12-17)


### Features

* restore higher pagination limits ([#813](https://github.com/propeller-heads/tycho-indexer/issues/813)) ([5f33369](https://github.com/propeller-heads/tycho-indexer/commit/5f33369021d8259ce252843247b2a63db98feed5))

## [0.124.0](https://github.com/propeller-heads/tycho-indexer/compare/0.123.0...0.124.0) (2025-12-16)


### Features

* add min_traded_n_days_ago filter to RPC server configuration and validation ([b99e717](https://github.com/propeller-heads/tycho-indexer/commit/b99e7171e5afd4fbde3e7efbad68107df5099d5b))
* add RPC server configuration and validation for filtering thresholds ([c86bb8f](https://github.com/propeller-heads/tycho-indexer/commit/c86bb8fe5cd4b628d89022aedd41b3ed08bdff75))
* add RPC server configuration and validation for filtering thresholds ([#803](https://github.com/propeller-heads/tycho-indexer/issues/803)) ([8ce170b](https://github.com/propeller-heads/tycho-indexer/commit/8ce170bff47f33b910ae35898c8861c58cf96612))

## [0.123.0](https://github.com/propeller-heads/tycho-indexer/compare/0.122.3...0.123.0) (2025-12-16)


### Features

* Address PR reviews. Add new return parameter. ([25da39c](https://github.com/propeller-heads/tycho-indexer/commit/25da39c66f2d6d30e75e4f60510e27d0fde4ca50))
* Unify two methods in protocol sim. Add enum for price constraint ([ecbf5b2](https://github.com/propeller-heads/tycho-indexer/commit/ecbf5b26ccd935c11849586930c9ce358981c4ae))


### Bug Fixes

* add input validation for Price struct parameters ([e2508a0](https://github.com/propeller-heads/tycho-indexer/commit/e2508a0a5e19f9bf013e9813dbc61fd4ed863e96))

## [0.122.3](https://github.com/propeller-heads/tycho-indexer/compare/0.122.2...0.122.3) (2025-12-15)


### Bug Fixes

* **dci:** add entrypoint_id to trace metrics ([ef3012d](https://github.com/propeller-heads/tycho-indexer/commit/ef3012dfbb306d2cb3c20bdb5194e0dbf730624b))

## [0.122.2](https://github.com/propeller-heads/tycho-indexer/compare/0.122.1...0.122.2) (2025-12-15)


### Bug Fixes

* early exit account extractions on empty storage requests ([1772677](https://github.com/propeller-heads/tycho-indexer/commit/1772677b17e6d8f65b597e55a28a94b5e89094aa))
* full indexing check on slot extraction trigger ([eb2187b](https://github.com/propeller-heads/tycho-indexer/commit/eb2187b8a690302ad2e60e4c570fbe194240885c))
* skip account extraction on new slots for full indexed contracts ([61e74ba](https://github.com/propeller-heads/tycho-indexer/commit/61e74ba95745abb848981eb994b4c1e5185f2611))
* skip account extraction on new slots for full indexed contracts ([#808](https://github.com/propeller-heads/tycho-indexer/issues/808)) ([c87e18e](https://github.com/propeller-heads/tycho-indexer/commit/c87e18ef994a81a38fd34daeb28b2b1be51ef9c0))

## [0.122.1](https://github.com/propeller-heads/tycho-indexer/compare/0.122.0...0.122.1) (2025-12-15)

## [0.122.0](https://github.com/propeller-heads/tycho-indexer/compare/0.121.2...0.122.0) (2025-12-13)


### Features

* fix balance overrides for Go node providers ([355da1b](https://github.com/propeller-heads/tycho-indexer/commit/355da1b73cfd904e2f9cb77731cd224110f23ce3))
* fix balance overrides for Go node providers ([#807](https://github.com/propeller-heads/tycho-indexer/issues/807)) ([a31d5f2](https://github.com/propeller-heads/tycho-indexer/commit/a31d5f2db8497f463ace52de3d10cc37a1013bd6))

## [0.121.2](https://github.com/propeller-heads/tycho-indexer/compare/0.121.1...0.121.2) (2025-12-12)


### Bug Fixes

* normalise balance overrides (remove leading zeros) ([4ff652b](https://github.com/propeller-heads/tycho-indexer/commit/4ff652b0a6aab9bb290a998140d61581174a85b6))
* normalise balance overrides (remove leading zeros) ([#806](https://github.com/propeller-heads/tycho-indexer/issues/806)) ([6b7a6f9](https://github.com/propeller-heads/tycho-indexer/commit/6b7a6f99b0752e4ca16a31d917a353d731592079))

## [0.121.1](https://github.com/propeller-heads/tycho-indexer/compare/0.121.0...0.121.1) (2025-12-12)


### Bug Fixes

* add dci trace metrics ([5dee152](https://github.com/propeller-heads/tycho-indexer/commit/5dee152a6ffb479ffaf5fb0c4b761b0a896dd16e))
* add dci trace metrics ([#805](https://github.com/propeller-heads/tycho-indexer/issues/805)) ([e217b90](https://github.com/propeller-heads/tycho-indexer/commit/e217b90226bfac8f6c108d78b4ad590461df222e))
* **dci:** skip cache update on blocks with no traces ([4cc50cc](https://github.com/propeller-heads/tycho-indexer/commit/4cc50ccca667c104b32846cd3a1dbb4d171524fc))

## [0.121.0](https://github.com/propeller-heads/tycho-indexer/compare/0.120.0...0.121.0) (2025-12-11)


### Features

* add debug logging for RPC retry attempts and backoff duration ([96349e8](https://github.com/propeller-heads/tycho-indexer/commit/96349e84ae34eb4aa963c0f3ce4db286b190131b))
* add RPC retry and batching configuration structs and otherwise polish the PR ([039872f](https://github.com/propeller-heads/tycho-indexer/commit/039872fda9cb51e6fe3cf29832b5a627e3285400))
* add tracing instrumentation to async RPC methods for improved debugging ([2b32b8f](https://github.com/propeller-heads/tycho-indexer/commit/2b32b8f1d3b41c884ec82866052ffdff663c4424))
* implement attempt-based RPC retry logic with custom error handling ([cfe018e](https://github.com/propeller-heads/tycho-indexer/commit/cfe018e7ac44b7976124de785a47dc3fe72db65f))
* implement batch RPC support for slot detection and tracing ([a925115](https://github.com/propeller-heads/tycho-indexer/commit/a925115dc587ec402e389f8c14c48947e1763696))
* integrate `RetryPolicy` across RPC methods for improved error handling ([1408734](https://github.com/propeller-heads/tycho-indexer/commit/140873415a0c557ca532925c64ff48d0f9b461db))
* refactor RPC batching configuration to use enum and improve default settings. Update the methods that were checking for batch config to explicitly fail specifying that the RPC does not support batching ([1aeb24c](https://github.com/propeller-heads/tycho-indexer/commit/1aeb24c44010543a75559edaf2784f3d13473469))
* universal retry logic for the RPC ([#778](https://github.com/propeller-heads/tycho-indexer/issues/778)) ([6514e4e](https://github.com/propeller-heads/tycho-indexer/commit/6514e4e246330726afd33544399970aa7c0cb89b))
* use rpc retry policy for batch trace and access list processing ([964eb05](https://github.com/propeller-heads/tycho-indexer/commit/964eb05fb822212311e6dfff9cdb1ae98e0e690b))


### Bug Fixes

* add chunking based on `max_batch_size` for the slot_detector batch requests ([2382c4f](https://github.com/propeller-heads/tycho-indexer/commit/2382c4f9866e42fdab1c9e150f678e5f474fa985))
* correct typo in `ValueExtractionError` error message ([7d8dc86](https://github.com/propeller-heads/tycho-indexer/commit/7d8dc8627567cd9869929cdd341411762e04ffad))
* format slot and test values as 32-byte hex strings in RPC tracer params ([1eb0302](https://github.com/propeller-heads/tycho-indexer/commit/1eb03026aec6d858f0fb4021a57dc5ca5cc84d96))
* integrate the changes in the tycho-ethereum into tycho-indexer and re-export useful structs from backoff crate ([e36c7a3](https://github.com/propeller-heads/tycho-indexer/commit/e36c7a3a3df741c1cddaea812df6bf2978815768))

## [0.120.0](https://github.com/propeller-heads/tycho-indexer/compare/0.119.2...0.120.0) (2025-12-11)


### Features

* improvements for DCI on fast chains ([#802](https://github.com/propeller-heads/tycho-indexer/issues/802)) ([9835efb](https://github.com/propeller-heads/tycho-indexer/commit/9835efbaf4429a0d4139188cb201ad878bf7c8dc))
* **tycho-client:** extend dci support to non-ethereum chains ([424977c](https://github.com/propeller-heads/tycho-indexer/commit/424977c71ccaa09a47b399e3d570f20bd70fc836))


### Bug Fixes

* **dci:** handle native token balances overwrites if native token is a pool token ([7d92dd6](https://github.com/propeller-heads/tycho-indexer/commit/7d92dd6c879689af3aa0b78dfae462e178bc8d41))
* **storage:** chunk trace result inserts to avoid exceeding PostgreSQL param limit ([bd13042](https://github.com/propeller-heads/tycho-indexer/commit/bd130424b140c0bbc5473468cd264dab413716e2))

## [0.119.2](https://github.com/propeller-heads/tycho-indexer/compare/0.119.1...0.119.2) (2025-12-08)


### Bug Fixes

* chuck inserts across to avoid exceeding PostgreSQL parameter limits. ([c873493](https://github.com/propeller-heads/tycho-indexer/commit/c87349301a9358d3ecd991096b6dbb3b2debad7d))
* chuck inserts across to avoid exceeding PostgreSQL parameter limits. ([#800](https://github.com/propeller-heads/tycho-indexer/issues/800)) ([711e137](https://github.com/propeller-heads/tycho-indexer/commit/711e137a0f7d59766edcf60b898bb4b71d5ad8f6))

## [0.119.1](https://github.com/propeller-heads/tycho-indexer/compare/0.119.0...0.119.1) (2025-12-03)

## [0.119.0](https://github.com/propeller-heads/tycho-indexer/compare/0.118.1...0.119.0) (2025-12-02)


### Features

* restore higher pagination limits ([#796](https://github.com/propeller-heads/tycho-indexer/issues/796)) ([5a075c3](https://github.com/propeller-heads/tycho-indexer/commit/5a075c3c7f68395770b7bbd8410fb8d4b2353955))


### Bug Fixes

* restore higher pagination limits for StateRequestBody, TokensRequestBody, ProtocolComponentsRequestBody, and ProtocolStateRequestBody ([fdfde70](https://github.com/propeller-heads/tycho-indexer/commit/fdfde7040a0e3e511fc8f8529af6b0695cef2fbe))

## [0.118.1](https://github.com/propeller-heads/tycho-indexer/compare/0.118.0...0.118.1) (2025-12-02)

## [0.118.0](https://github.com/propeller-heads/tycho-indexer/compare/0.117.4...0.118.0) (2025-12-02)


### Features

* add minimum TVL config for RPC responses ([#794](https://github.com/propeller-heads/tycho-indexer/issues/794)) ([9caaa9f](https://github.com/propeller-heads/tycho-indexer/commit/9caaa9f7c7d49e3daf09dd4b94a545b456733dc1))
* add minimum TVL threshold for RPC responses ([1f651a8](https://github.com/propeller-heads/tycho-indexer/commit/1f651a8d61d65900597c347b1e58768cff207d66))
* Add script to compare slipstreams observations with on-chain state ([fbb3fae](https://github.com/propeller-heads/tycho-indexer/commit/fbb3faede0b13d8c941957e53af412a8b3cfa516))
* Add script to compare slipstreams observations with on-chain state ([#776](https://github.com/propeller-heads/tycho-indexer/issues/776)) ([5fa1166](https://github.com/propeller-heads/tycho-indexer/commit/5fa11660f99f6511da0ddc0337c52ffd40e3b6c5))

## [0.117.4](https://github.com/propeller-heads/tycho-indexer/compare/0.117.3...0.117.4) (2025-12-01)

## [0.117.3](https://github.com/propeller-heads/tycho-indexer/compare/0.117.2...0.117.3) (2025-11-28)

## [0.117.2](https://github.com/propeller-heads/tycho-indexer/compare/0.117.1...0.117.2) (2025-11-28)


### Bug Fixes

* ping point the source of untracked memory and adjust for it ([00350c5](https://github.com/propeller-heads/tycho-indexer/commit/00350c52fae87462ef5ebe87a6d4ab488e424c27))
* ping point the source of untracked memory and resolve most of it ([#788](https://github.com/propeller-heads/tycho-indexer/issues/788)) ([659a9f3](https://github.com/propeller-heads/tycho-indexer/commit/659a9f3cb7ad53308bf566169ffeccd0c6b70bc3))

## [0.117.1](https://github.com/propeller-heads/tycho-indexer/compare/0.117.0...0.117.1) (2025-11-27)

## [0.117.0](https://github.com/propeller-heads/tycho-indexer/compare/0.116.0...0.117.0) (2025-11-26)


### Features

* add a configurable RPC retry mechanism to CLI ([9397b32](https://github.com/propeller-heads/tycho-indexer/commit/9397b3206623abe60eb58b2e6a6d616e570d6f8d))
* get `RPCRetryConfig` from the CLI and pass it to the DCI plugin ([8db0cb4](https://github.com/propeller-heads/tycho-indexer/commit/8db0cb4c1a425f50a9ff3986b827fca06bccee31))
* make EVM balance slot detector configuration dependent on RPC retry settings ([6d077d2](https://github.com/propeller-heads/tycho-indexer/commit/6d077d2c0d386dcafece28059a70020c5e936727))
* RPC retries configurable from the CLI  ([#787](https://github.com/propeller-heads/tycho-indexer/issues/787)) ([e7df6d9](https://github.com/propeller-heads/tycho-indexer/commit/e7df6d9fe601ef8797a44f2ac8a83f8e6e00bc4b))
* unify RPC configuration into single RPCArgs and RPCConfig structs ([d83f976](https://github.com/propeller-heads/tycho-indexer/commit/d83f97626648e1db4ab37aa0b838c0e5bb4a64da))


### Bug Fixes

* resolve rebase conflicts by reverting to RPCRetryConfig-only approach ([027079a](https://github.com/propeller-heads/tycho-indexer/commit/027079a3766782a6ba703c1333c0cde8e5a12731))

## [0.116.0](https://github.com/propeller-heads/tycho-indexer/compare/0.115.0...0.116.0) (2025-11-26)


### Features

* add Price struct and swap_to_price/query_demand methods to ProtocolSim trait ([308ce9f](https://github.com/propeller-heads/tycho-indexer/commit/308ce9f0738c83a4e64e1c68e3e35151e0cfef02))
* Add swap_to_price and query_demand methods to ProtocolSim trait ([#789](https://github.com/propeller-heads/tycho-indexer/issues/789)) ([44e6a69](https://github.com/propeller-heads/tycho-indexer/commit/44e6a69ebf745b2fe6258c7ee27f7a372154f49d))

## [0.115.0](https://github.com/propeller-heads/tycho-indexer/compare/0.114.3...0.115.0) (2025-11-24)


### Features

* error on missing component id:params link ([cb47866](https://github.com/propeller-heads/tycho-indexer/commit/cb4786695500a588e9270dcb39ca10a5ee67c435))
* make component to params link required ([9064cf4](https://github.com/propeller-heads/tycho-indexer/commit/9064cf4740ae1d0b275dc4737cdf8a6c7f3bf00b))
* Make component to tracing params link required ([#779](https://github.com/propeller-heads/tycho-indexer/issues/779)) ([3e26adf](https://github.com/propeller-heads/tycho-indexer/commit/3e26adf20b8f034a034d56451e42aadef45cd5bb))

## [0.114.3](https://github.com/propeller-heads/tycho-indexer/compare/0.114.2...0.114.3) (2025-11-20)


### Bug Fixes

* handle `"storage": null` in `debug_storageRangeAt` responses with a wrapper ([0152c78](https://github.com/propeller-heads/tycho-indexer/commit/0152c78c55f3508447a24ed318497d9997d7829f))
* tmp handle `"storage": null` in `debug_storageRangeAt` responses  ([#785](https://github.com/propeller-heads/tycho-indexer/issues/785)) ([5a5fea8](https://github.com/propeller-heads/tycho-indexer/commit/5a5fea8008758b1eb3397b85b9049200c8ecdf74))

## [0.114.2](https://github.com/propeller-heads/tycho-indexer/compare/0.114.1...0.114.2) (2025-11-20)

## [0.114.1](https://github.com/propeller-heads/tycho-indexer/compare/0.114.0...0.114.1) (2025-11-18)


### Bug Fixes

* Fix DCI cache initialisation. ([78d7206](https://github.com/propeller-heads/tycho-indexer/commit/78d720601ca0d46276fe7e79bd0623f4c63a54e0))
* Fix DCI cache initialisation. ([#784](https://github.com/propeller-heads/tycho-indexer/issues/784)) ([54b321c](https://github.com/propeller-heads/tycho-indexer/commit/54b321c648723baf0e52eff36c8bef2fbb929b3d))

## [0.114.0](https://github.com/propeller-heads/tycho-indexer/compare/0.113.2...0.114.0) (2025-11-18)


### Features

* add script to delete huge protocols ([bcdd54f](https://github.com/propeller-heads/tycho-indexer/commit/bcdd54f23cfa80302f7099c8af0dffb5f7ae8802))
* add script to delete huge protocols ([#747](https://github.com/propeller-heads/tycho-indexer/issues/747)) ([b917e4f](https://github.com/propeller-heads/tycho-indexer/commit/b917e4f8a521f6c118636dab79e0cb3656235eec))

## [0.113.2](https://github.com/propeller-heads/tycho-indexer/compare/0.113.1...0.113.2) (2025-11-18)

## [0.113.1](https://github.com/propeller-heads/tycho-indexer/compare/0.113.0...0.113.1) (2025-11-17)


### Bug Fixes

* have both compressed and uncompressed pagination limits equal ([4e50026](https://github.com/propeller-heads/tycho-indexer/commit/4e5002618ea7a7785aa797f474007032f2c9b500))
* have both compressed and uncompressed pagination limits equal ([#780](https://github.com/propeller-heads/tycho-indexer/issues/780)) ([81285fc](https://github.com/propeller-heads/tycho-indexer/commit/81285fcca7fbdf979421fc1d0d768b27a724dc29))

## [0.113.0](https://github.com/propeller-heads/tycho-indexer/compare/0.112.0...0.113.0) (2025-11-14)


### Features

* add compression-aware pagination validation in `tycho-indexer` ([#768](https://github.com/propeller-heads/tycho-indexer/issues/768)) ([39b29e3](https://github.com/propeller-heads/tycho-indexer/commit/39b29e30cbc9b55b6a70c30a9efe558fa062ba5e))
* add compression-aware pagination validation in `tycho-indexer` RPC services ([98b636c](https://github.com/propeller-heads/tycho-indexer/commit/98b636c80952e26200474130a2bffca87c75a141))
* add pagination validation to `component_tvl` RPC handler and define limits for `ComponentTvlRequestBody` ([e717457](https://github.com/propeller-heads/tycho-indexer/commit/e7174572d0a635bd7353afcddabcfafab9422b23))

## [0.112.0](https://github.com/propeller-heads/tycho-indexer/compare/0.111.1...0.112.0) (2025-11-14)


### Features

* improve token retrieval with concurrent paginated requests ([#771](https://github.com/propeller-heads/tycho-indexer/issues/771)) ([a5a7bc6](https://github.com/propeller-heads/tycho-indexer/commit/a5a7bc6fd30c2709762ba2d8dac147feec021515))
* make concurrency limit configurable in `get_all_tokens` ([1103dac](https://github.com/propeller-heads/tycho-indexer/commit/1103dacb639148c9d74af721ce5aaf5972fc1798))

## [0.111.1](https://github.com/propeller-heads/tycho-indexer/compare/0.111.0...0.111.1) (2025-11-14)


### Bug Fixes

* address errors in swagger API ([#733](https://github.com/propeller-heads/tycho-indexer/issues/733)) ([1d5bc57](https://github.com/propeller-heads/tycho-indexer/commit/1d5bc574355f62d48a817fd8ebd9444c62155bd1))
* adjust schema definitions and resolve the swagger UI errors ([5ee04ee](https://github.com/propeller-heads/tycho-indexer/commit/5ee04eedb35bd723c2aa8c35ddc6ad618f980205))

## [0.111.0](https://github.com/propeller-heads/tycho-indexer/compare/0.110.0...0.111.0) (2025-11-14)


### Features

* major refactor of `tycho-ethereum` ([#742](https://github.com/propeller-heads/tycho-indexer/issues/742)) ([ab16908](https://github.com/propeller-heads/tycho-indexer/commit/ab169081cd1f54fb1854e420dc2225a21dd47b09))
* make `max_storage_slot_batch_size` configurable via environment variable in `BatchingConfig` ([ed88c90](https://github.com/propeller-heads/tycho-indexer/commit/ed88c905bb42a2ecf4182cdbc47262446f959d8a))


### Bug Fixes

* adjust the tracer tests that were added on main to match the refactored version of tycho ethereum ([21fe442](https://github.com/propeller-heads/tycho-indexer/commit/21fe4425b36dd868a51f344859007337160e13f2))
* correct JSON-RPC response IDs in entrypoint tracer tests ([9f87dde](https://github.com/propeller-heads/tycho-indexer/commit/9f87ddee65038565a82de9a1dcf60a9fda5f37ac))
* create a dedicated trace rpc client consistent with the previous design. Additionally, streamline the `EVMEntrypointService` initialization of an unnecessary Result wrapping ([91c4f5d](https://github.com/propeller-heads/tycho-indexer/commit/91c4f5d2f5d0767991b17d1f95192039a7304875))
* fix compilation issues ([a83a59a](https://github.com/propeller-heads/tycho-indexer/commit/a83a59a5d69446346efd0100ab70ce2cbf7712f1))
* handle `MissingBatchResponse` errors in RPC operations and improve error messages to fix test failing ([505f792](https://github.com/propeller-heads/tycho-indexer/commit/505f79258e905e856e8b7efaed7d503eb4cfda68))
* replace placeholder logic with `format!` for constructing JSON-RPC response in tracer tests ([797f420](https://github.com/propeller-heads/tycho-indexer/commit/797f4209f94790f04822cf139a5773418a9133d3))
* use dynamic `self.chain` instead of hardcoded `Chain::Ethereum` in block processing logic ([0445a3c](https://github.com/propeller-heads/tycho-indexer/commit/0445a3cfd53f1cd9dfe1b23fbbc741f5d972fde5))

## [0.110.0](https://github.com/propeller-heads/tycho-indexer/compare/0.109.2...0.110.0) (2025-11-13)


### Features

* rename component to params link table ([bdac794](https://github.com/propeller-heads/tycho-indexer/commit/bdac794efc7f3a52e8d8f1d6dea53bbc642f0c8f))
* utilise component to params link table to fetch only relevant params per component ([#775](https://github.com/propeller-heads/tycho-indexer/issues/775)) ([90acaa5](https://github.com/propeller-heads/tycho-indexer/commit/90acaa5dab13863925e295d2d22f9caf3667d1e6))


### Bug Fixes

* fetch only directly linked params per component ([095061b](https://github.com/propeller-heads/tycho-indexer/commit/095061b0f24ed730d1c2347b035139f9377da85c))

## [0.109.2](https://github.com/propeller-heads/tycho-indexer/compare/0.109.1...0.109.2) (2025-11-13)


### Bug Fixes

* prevent reqwest enabling compression by default ([1f55643](https://github.com/propeller-heads/tycho-indexer/commit/1f55643fc90d2e2fd2afad88d728968c340cf5ad))
* prevent reqwest enabling compression by default ([#772](https://github.com/propeller-heads/tycho-indexer/issues/772)) ([052f5d0](https://github.com/propeller-heads/tycho-indexer/commit/052f5d0e8f1587dd9d7fa7c3bbde43142632bc8c))

## [0.109.1](https://github.com/propeller-heads/tycho-indexer/compare/0.109.0...0.109.1) (2025-11-12)

## [0.109.0](https://github.com/propeller-heads/tycho-indexer/compare/0.108.0...0.109.0) (2025-11-07)


### Features

* add a way to quickly configure storage batch size ([e6994b8](https://github.com/propeller-heads/tycho-indexer/commit/e6994b8b04a648e3bd150db487837cb273d49354))
* add a way to quickly configure storage batch size ([#770](https://github.com/propeller-heads/tycho-indexer/issues/770)) ([29a0b4f](https://github.com/propeller-heads/tycho-indexer/commit/29a0b4f811896ed58fc94800fd7df1a72641b932))

## [0.108.0](https://github.com/propeller-heads/tycho-indexer/compare/0.107.1...0.108.0) (2025-11-07)


### Features

* add client support for both `ws` and `rpc` compression ([#753](https://github.com/propeller-heads/tycho-indexer/issues/753)) ([fb0f702](https://github.com/propeller-heads/tycho-indexer/commit/fb0f702c91a41c20ae5c75b4e3f523023dbcb328))
* add configurable options and zstd compression support to `HttpRPCClient` and WebSocket subscriptions ([c9d1ae2](https://github.com/propeller-heads/tycho-indexer/commit/c9d1ae24e84ebb100c5374374ffa8d5147786b35))

## [0.107.1](https://github.com/propeller-heads/tycho-indexer/compare/0.107.0...0.107.1) (2025-11-07)


### Bug Fixes

* **account_extractor:** gracefully handle null storage responses ([6a63a6c](https://github.com/propeller-heads/tycho-indexer/commit/6a63a6cf1bf408fb42a7710e743a200061564577))
* **account_extractor:** gracefully handle null storage responses ([#769](https://github.com/propeller-heads/tycho-indexer/issues/769)) ([cbb4a4f](https://github.com/propeller-heads/tycho-indexer/commit/cbb4a4f278a8c44bc4d5e5d2f3c512808af1245f))
* handle null storage value in storage fetch response ([789fe2e](https://github.com/propeller-heads/tycho-indexer/commit/789fe2eff4ded788cd9da92e812662d68b4976f0))

## [0.107.0](https://github.com/propeller-heads/tycho-indexer/compare/0.106.0...0.107.0) (2025-11-07)


### Features

* Call all account_extractor futures together ([357bbe9](https://github.com/propeller-heads/tycho-indexer/commit/357bbe98babce6f1149712261099a31bc8a2090a))
* sequentially process storage futures instead of concurrently ([1bc92e4](https://github.com/propeller-heads/tycho-indexer/commit/1bc92e4fbb9200948771f5ce229771dd60549c88))


### Bug Fixes

* Fix batch account storage requests handling ([#766](https://github.com/propeller-heads/tycho-indexer/issues/766)) ([66f57d7](https://github.com/propeller-heads/tycho-indexer/commit/66f57d7159687f0d2e0b686d22e2963d8d98d33d))
* Fix batch vec initialization by recreating it for every batch ([2d7b2cb](https://github.com/propeller-heads/tycho-indexer/commit/2d7b2cb9563ec8d45cb7ae16a81e2fcd707d8418))

## [0.106.0](https://github.com/propeller-heads/tycho-indexer/compare/0.105.4...0.106.0) (2025-11-06)


### Features

* Add custom bytecode for Unichain V4 MiniRouter ([af86232](https://github.com/propeller-heads/tycho-indexer/commit/af862328a8111fd4b167e7234c3070afa1eb1332))
* Add custom bytecode for Unichain V4 MiniRouter ([#765](https://github.com/propeller-heads/tycho-indexer/issues/765)) ([6b585d8](https://github.com/propeller-heads/tycho-indexer/commit/6b585d892108f9a1beea04bad32966de54d79cf3))

## [0.105.4](https://github.com/propeller-heads/tycho-indexer/compare/0.105.3...0.105.4) (2025-11-06)

## [0.105.3](https://github.com/propeller-heads/tycho-indexer/compare/0.105.2...0.105.3) (2025-11-06)

## [0.105.2](https://github.com/propeller-heads/tycho-indexer/compare/0.105.1...0.105.2) (2025-11-06)


### Bug Fixes

* use a correct tracing router address ([a3b2f8a](https://github.com/propeller-heads/tycho-indexer/commit/a3b2f8a227be861e8712bef673bdb6cdbf75d7ad))
* use a correct tracing router address ([#760](https://github.com/propeller-heads/tycho-indexer/issues/760)) ([298d398](https://github.com/propeller-heads/tycho-indexer/commit/298d398dc6d403530ff733c7a7091f6780add549))

## [0.105.1](https://github.com/propeller-heads/tycho-indexer/compare/0.105.0...0.105.1) (2025-11-06)

## [0.105.0](https://github.com/propeller-heads/tycho-indexer/compare/0.104.1...0.105.0) (2025-11-06)


### Features

* add dedicated UniswapV4Hooks dci plugin config type ([9d1f3cc](https://github.com/propeller-heads/tycho-indexer/commit/9d1f3cc42c099bcc98e1167e62b0b14c6ba45182))
* make dci blacklist addresses configurable ([8e1db98](https://github.com/propeller-heads/tycho-indexer/commit/8e1db9826086bfcb82527c33eb58f786aca262df))
* make uniswap v4 hooks DCI plugin chain agnostic ([#756](https://github.com/propeller-heads/tycho-indexer/issues/756)) ([95257d3](https://github.com/propeller-heads/tycho-indexer/commit/95257d3f2ecfe6159c93fb422952f0c3fd7c3cf9))
* set trace router address to hardcoded random address ([27ad55c](https://github.com/propeller-heads/tycho-indexer/commit/27ad55ccd722606e76e70e70ba3493f25bf53f31))


### Bug Fixes

* argument order of usv4 hook dci creation ([208c6c9](https://github.com/propeller-heads/tycho-indexer/commit/208c6c9b7a369e48d597f4284857933b17689e01))

## [0.104.1](https://github.com/propeller-heads/tycho-indexer/compare/0.104.0...0.104.1) (2025-11-05)


### Bug Fixes

* Decrease max batch size on account extractor ([16c477b](https://github.com/propeller-heads/tycho-indexer/commit/16c477be24efc4e67b6d65a88c3f779725bc0b0a))
* Decrease max batch size on account extractor ([#758](https://github.com/propeller-heads/tycho-indexer/issues/758)) ([fd4524d](https://github.com/propeller-heads/tycho-indexer/commit/fd4524d60a196b845a369242afa48090e89e43aa))

## [0.104.0](https://github.com/propeller-heads/tycho-indexer/compare/0.103.1...0.104.0) (2025-11-05)


### Features

* Add ability to register default Hook Orchestrator ([1b1b5c9](https://github.com/propeller-heads/tycho-indexer/commit/1b1b5c9a00a15a6d9c2cd1781a3d774a67f1fb7b))
* Enriches component metadata with balance updates ([7c78ef7](https://github.com/propeller-heads/tycho-indexer/commit/7c78ef71962d87bb0b9719e2c4ee423d75e48c1f))
* Index all composable hooks ([#746](https://github.com/propeller-heads/tycho-indexer/issues/746)) ([a90ec11](https://github.com/propeller-heads/tycho-indexer/commit/a90ec11d0e510aa967ff3a3b06c6f0018d5c4e6d))
* Move the metadata enrichment logic to the hook orchestrator ([bc842c3](https://github.com/propeller-heads/tycho-indexer/commit/bc842c38020d0e00b5280da83ae9c06e85b0e22b))

## [0.103.1](https://github.com/propeller-heads/tycho-indexer/compare/0.103.0...0.103.1) (2025-11-05)

## [0.103.0](https://github.com/propeller-heads/tycho-indexer/compare/0.102.0...0.103.0) (2025-11-05)


### Features

* add zstd compression support for WebSocket subscriptions ([4cf8256](https://github.com/propeller-heads/tycho-indexer/commit/4cf8256e77e97625060d5ec439a9b8190e5d0891))
* changed `CompressionError` handling for WebSocket communication from retry to fatal ([4a469bf](https://github.com/propeller-heads/tycho-indexer/commit/4a469bfd2d7677e07fe7b5a01599ceb18585bce2))
* enable zstd compression support in `tycho-indexer` ws ([#749](https://github.com/propeller-heads/tycho-indexer/issues/749)) ([2e2e3d9](https://github.com/propeller-heads/tycho-indexer/commit/2e2e3d99fe4626366fea4c03aa855b3946183b9a))

## [0.102.0](https://github.com/propeller-heads/tycho-indexer/compare/0.101.4...0.102.0) (2025-11-05)


### Features

* enable zstd compression support in `tycho-indexer` HTTP responses and add tests for compression behavior ([50be5b5](https://github.com/propeller-heads/tycho-indexer/commit/50be5b5314df36bf9444ad8c94453467c899204c))
* enable zstd compression support in `tycho-indexer` rpc ([#748](https://github.com/propeller-heads/tycho-indexer/issues/748)) ([ae13a7d](https://github.com/propeller-heads/tycho-indexer/commit/ae13a7d4e20a160284c6181f8950246820e73375))

## [0.101.4](https://github.com/propeller-heads/tycho-indexer/compare/0.101.3...0.101.4) (2025-11-05)

## [0.101.3](https://github.com/propeller-heads/tycho-indexer/compare/0.101.2...0.101.3) (2025-11-04)


### Bug Fixes

* Fix tracer batch request response parsing order ([a5fb8d3](https://github.com/propeller-heads/tycho-indexer/commit/a5fb8d3846eeb35bee228c631d8577f9d7d339f4))
* Fix tracer batch request response parsing order ([#752](https://github.com/propeller-heads/tycho-indexer/issues/752)) ([f7500bf](https://github.com/propeller-heads/tycho-indexer/commit/f7500bff4e77da92e821254177ec4dbe4ed34f7a))

## [0.101.2](https://github.com/propeller-heads/tycho-indexer/compare/0.101.1...0.101.2) (2025-11-04)


### Bug Fixes

* BlockParam creation in synchronizer ([dc797c4](https://github.com/propeller-heads/tycho-indexer/commit/dc797c4b55ca8f316885ea635c0e37dfda4ca558))
* BlockParam creation in synchronizer ([#754](https://github.com/propeller-heads/tycho-indexer/issues/754)) ([1658a74](https://github.com/propeller-heads/tycho-indexer/commit/1658a7426c53d25cda6ec0421924e9dbe20464ff))

## [0.101.1](https://github.com/propeller-heads/tycho-indexer/compare/0.101.0...0.101.1) (2025-11-04)


### Bug Fixes

* Allowance slot calculation - try next slot on error ([cdafeb5](https://github.com/propeller-heads/tycho-indexer/commit/cdafeb5854c41bea0a733a52e3d52103db9e4b55))
* Allowance slot calculation - try next slot on error ([#750](https://github.com/propeller-heads/tycho-indexer/issues/750)) ([7619036](https://github.com/propeller-heads/tycho-indexer/commit/7619036ad7c26253b73173a421e322c67da8e16b))

## [0.101.0](https://github.com/propeller-heads/tycho-indexer/compare/0.100.1...0.101.0) (2025-11-03)


### Features

* Better RPC get_snapshots organization ([5451349](https://github.com/propeller-heads/tycho-indexer/commit/54513492302d7b85bc4eac056fdbd3c68502a4b7))
* Expose get_snapshots in RPC client ([1f9e702](https://github.com/propeller-heads/tycho-indexer/commit/1f9e70277f533941ba295bf5e9ac2bd82210acc9))
* Expose get_snapshots in RPC client ([#743](https://github.com/propeller-heads/tycho-indexer/issues/743)) ([cfa8959](https://github.com/propeller-heads/tycho-indexer/commit/cfa89593b3d4eb1adbe8cb2d936d5d42b9dbc17e))
* get_snapshots takes SnapshotRequestBody as input ([bd8b2ea](https://github.com/propeller-heads/tycho-indexer/commit/bd8b2eab775da15f59d37f76c10f77d46b39ed31))
* Move chunk_size and concurrency to get_snapshots input ([b153090](https://github.com/propeller-heads/tycho-indexer/commit/b1530907d61ab490bcec828ddfbfdbe42a1588d8))
* Use references in ShapshotParameters ([8e966be](https://github.com/propeller-heads/tycho-indexer/commit/8e966beead2983911997d42e45f70b6122ea9e4f))


### Bug Fixes

* Test fixes after get_snapshots moved to RPC ([18437d6](https://github.com/propeller-heads/tycho-indexer/commit/18437d6f6406b571a98bf5b7d4c25ad91c003c5f))

## [0.100.1](https://github.com/propeller-heads/tycho-indexer/compare/0.100.0...0.100.1) (2025-10-30)


### Bug Fixes

* Balance + Allowance slot calculation ([abc5a94](https://github.com/propeller-heads/tycho-indexer/commit/abc5a940f68cfb86d7d96ef99f3dd832b880c636))
* Balance + Allowance slot calculation ([#725](https://github.com/propeller-heads/tycho-indexer/issues/725)) ([3cd424f](https://github.com/propeller-heads/tycho-indexer/commit/3cd424fc58079cce93ede8492d7908fcd19a4e2d))
* instead of choosing last slot, use same balance back as before ([facc5e9](https://github.com/propeller-heads/tycho-indexer/commit/facc5e9868a06c31a4c6f62b6d251b3fcf501482))

## [0.100.0](https://github.com/propeller-heads/tycho-indexer/compare/0.99.2...0.100.0) (2025-10-30)


### Features

* Add a cap on how much TracingParams are retried ([62671fb](https://github.com/propeller-heads/tycho-indexer/commit/62671fb20aad5cce2664735e9fbacffc908b0236))
* move params_to_retry identification to separate fn ([655e0f9](https://github.com/propeller-heads/tycho-indexer/commit/655e0f9ce0d066656bd3e3226489c0acdae95fef))
* Retrigger on updates of untraced TracingParams ([#728](https://github.com/propeller-heads/tycho-indexer/issues/728)) ([6de6644](https://github.com/propeller-heads/tycho-indexer/commit/6de66445dca8a4a041b80edffd88abeb68464e9d))
* Rollback using EntryPointWithTracingParams as cache key ([2c04cb6](https://github.com/propeller-heads/tycho-indexer/commit/2c04cb638a0c4908a199ed5bdb6ffebff84d3807))
* Update DCI Cache to keep track of TraceParams without results ([706f34a](https://github.com/propeller-heads/tycho-indexer/commit/706f34a654e4e4fd749d76a90ace052b7f7388a8))
* Update DCI to retry on changed Components that had failed tracing ([625b475](https://github.com/propeller-heads/tycho-indexer/commit/625b475d56204d8f5890ba0f5f45599bde36da7a))
* Use EntryPointWithTracingParams as cache key ([17d1a47](https://github.com/propeller-heads/tycho-indexer/commit/17d1a4771c1c8dc32c4209ff5c452326d203b402))

## [0.99.2](https://github.com/propeller-heads/tycho-indexer/compare/0.99.1...0.99.2) (2025-10-28)


### Bug Fixes

* erc20 abi panicking on big decimals values ([#744](https://github.com/propeller-heads/tycho-indexer/issues/744)) ([be07e3b](https://github.com/propeller-heads/tycho-indexer/commit/be07e3b882ea05d5be188e81e9d3a48fc540826e))
* fix erc20 abi panicking on big decimals values ([0fe3bdb](https://github.com/propeller-heads/tycho-indexer/commit/0fe3bdb49436b99a46f5c1a13fbd10dfcc093d5c))

## [0.99.1](https://github.com/propeller-heads/tycho-indexer/compare/0.99.0...0.99.1) (2025-10-28)


### Bug Fixes

* reschedule DB cronjobs ([1c123f0](https://github.com/propeller-heads/tycho-indexer/commit/1c123f0266f389b721c69d8d89fa70c67eafa5c2))
* reschedule DB cronjobs ([#740](https://github.com/propeller-heads/tycho-indexer/issues/740)) ([cc4256a](https://github.com/propeller-heads/tycho-indexer/commit/cc4256abcc8176d1eac4a5d2b72ec3ec11c7fcbf))

## [0.99.0](https://github.com/propeller-heads/tycho-indexer/compare/0.98.1...0.99.0) (2025-10-22)


### Features

* optimize cloning instead of expensive `msg`, only clone `msg.header` ([6ff30ba](https://github.com/propeller-heads/tycho-indexer/commit/6ff30ba3dcdd3b8f89ef3555c4fbde7a6222207d))


### Bug Fixes

* catch missed error handling in message printer of `cli.rs` ([6f8b4fb](https://github.com/propeller-heads/tycho-indexer/commit/6f8b4fbb0e73ae2f408e727bc6dc9df0d09d2d2c))
* correct typo in `deltas.rs` doc comments ([4134115](https://github.com/propeller-heads/tycho-indexer/commit/413411584ed391c35fc8c593c10a822db51cd0f7))
* handle CLI errors cleanly in `main.rs` ([6e96ca5](https://github.com/propeller-heads/tycho-indexer/commit/6e96ca5bb053ff3a8f62d11435125fc42e73e747))
* improve error handling for task monitoring in `cli.rs` ([7d97eac](https://github.com/propeller-heads/tycho-indexer/commit/7d97eacdaf04521702d8e8356df298da9350b466))
* incorrect `block_history` usage by replacing it with `new_block_history` in `feed/mod.rs` ([eedd967](https://github.com/propeller-heads/tycho-indexer/commit/eedd9675aef73a3b111acb21801b8edc19708ddc))
* remove unreachable error branches in `stream.rs` ([6e9cc37](https://github.com/propeller-heads/tycho-indexer/commit/6e9cc3755f7a010846ee579b25551fc7d241a5fa))
* simplify error handling in `handle_error_for_backoff` ([1bb6ae5](https://github.com/propeller-heads/tycho-indexer/commit/1bb6ae5e11f41e2bdf95e8e1c08311a92001ec4d))

## [0.98.1](https://github.com/propeller-heads/tycho-indexer/compare/0.98.0...0.98.1) (2025-10-21)


### Bug Fixes

* bug reporting 0 blocks sync rate ([d6df0f1](https://github.com/propeller-heads/tycho-indexer/commit/d6df0f1f2c8430efe71d1879a664d500b28d4a92))
* bug reporting 0 blocks sync rate ([#737](https://github.com/propeller-heads/tycho-indexer/issues/737)) ([9a82f93](https://github.com/propeller-heads/tycho-indexer/commit/9a82f9358322d10e7e9f3a2b08761154e407dd06))

## [0.98.0](https://github.com/propeller-heads/tycho-indexer/compare/0.97.0...0.98.0) (2025-10-17)


### Features

* add cache entry count metric to RPC monitoring ([b6eb0b7](https://github.com/propeller-heads/tycho-indexer/commit/b6eb0b7b23866009f5d29eea82a7e89db80408e0))

## [0.97.0](https://github.com/propeller-heads/tycho-indexer/compare/0.96.2...0.97.0) (2025-10-16)


### Features

* logging middleware ([#732](https://github.com/propeller-heads/tycho-indexer/issues/732)) ([6624db9](https://github.com/propeller-heads/tycho-indexer/commit/6624db9b628e6c721ba381827f574358db1d3add))

## [0.96.2](https://github.com/propeller-heads/tycho-indexer/compare/0.96.1...0.96.2) (2025-10-16)


### Bug Fixes

* RPC cache weighting and tidy memory metrics ([#731](https://github.com/propeller-heads/tycho-indexer/issues/731)) ([40a21f0](https://github.com/propeller-heads/tycho-indexer/commit/40a21f0d2ed29f20154d69389db15c9488f34f3b))

## [0.96.1](https://github.com/propeller-heads/tycho-indexer/compare/0.96.0...0.96.1) (2025-10-13)


### Bug Fixes

* Revert "chore: monitoring and logging ([#723](https://github.com/propeller-heads/tycho-indexer/issues/723))" ([#730](https://github.com/propeller-heads/tycho-indexer/issues/730)) ([003656d](https://github.com/propeller-heads/tycho-indexer/commit/003656dc567e53cd6943d9b1089962425d24f08c))


### Reverts

* Revert "chore: monitoring and logging (#723)" ([d2b7406](https://github.com/propeller-heads/tycho-indexer/commit/d2b7406885a66159cecede50057778c8161b4f58)), closes [#723](https://github.com/propeller-heads/tycho-indexer/issues/723)

## [0.96.0](https://github.com/propeller-heads/tycho-indexer/compare/0.95.2...0.96.0) (2025-10-13)


### Features

* integrate `deepsize` for memory usage reporting ([#729](https://github.com/propeller-heads/tycho-indexer/issues/729)) ([b194f84](https://github.com/propeller-heads/tycho-indexer/commit/b194f8424290548da36b7f2f0bb303ef5e901337))

## [0.95.2](https://github.com/propeller-heads/tycho-indexer/compare/0.95.1...0.95.2) (2025-10-10)

## [0.95.1](https://github.com/propeller-heads/tycho-indexer/compare/0.95.0...0.95.1) (2025-10-10)

## [0.95.0](https://github.com/propeller-heads/tycho-indexer/compare/0.94.1...0.95.0) (2025-10-09)


### Features

* add bsc chain ([a8d3973](https://github.com/propeller-heads/tycho-indexer/commit/a8d39731e51115a081c23ae8224b18a8c5b2f780))
* add bsc chain ([#724](https://github.com/propeller-heads/tycho-indexer/issues/724)) ([0a8d4bf](https://github.com/propeller-heads/tycho-indexer/commit/0a8d4bfc31c5345867b6f9c06fb4cdd47f02abec))


### Bug Fixes

* function name typo ([e8da824](https://github.com/propeller-heads/tycho-indexer/commit/e8da824904e3325c685fc7b85242e4d3f02d62b6))

## [0.94.1](https://github.com/propeller-heads/tycho-indexer/compare/0.94.0...0.94.1) (2025-10-08)

## [0.94.0](https://github.com/propeller-heads/tycho-indexer/compare/0.93.1...0.94.0) (2025-10-07)


### Features

* make RPC retry config more permissive ([101325f](https://github.com/propeller-heads/tycho-indexer/commit/101325f5857b04ad954a198ddc26e5267e34b006))
* make RPC retry config more permissive ([#717](https://github.com/propeller-heads/tycho-indexer/issues/717)) ([e322b5c](https://github.com/propeller-heads/tycho-indexer/commit/e322b5c8292537587f8bcc5ae1ca5cdf68e826cc))

## [0.93.1](https://github.com/propeller-heads/tycho-indexer/compare/0.93.0...0.93.1) (2025-10-07)

## [0.93.0](https://github.com/propeller-heads/tycho-indexer/compare/0.92.1...0.93.0) (2025-10-07)


### Features

* add native balance tracking in DCI ([55edb21](https://github.com/propeller-heads/tycho-indexer/commit/55edb2188552f2f80cffa109d80cb6e2b6218c71))
* add native balance tracking in DCI ([#721](https://github.com/propeller-heads/tycho-indexer/issues/721)) ([247525f](https://github.com/propeller-heads/tycho-indexer/commit/247525f90cd241e0eb151a8175c9126636aefcde))

## [0.92.1](https://github.com/propeller-heads/tycho-indexer/compare/0.92.0...0.92.1) (2025-10-02)


### Bug Fixes

* make new component tokens available to blacklist ([23e21ed](https://github.com/propeller-heads/tycho-indexer/commit/23e21ed00b9e4ed175c4526367155cdfc79433c5))
* make new component tokens available to blacklist ([#720](https://github.com/propeller-heads/tycho-indexer/issues/720)) ([f686d77](https://github.com/propeller-heads/tycho-indexer/commit/f686d770fbe1da43196592ec7358cb3bdd060ea0))

## [0.92.0](https://github.com/propeller-heads/tycho-indexer/compare/0.91.2...0.92.0) (2025-10-02)


### Features

* add configurable batch commit threshold for extractors ([#712](https://github.com/propeller-heads/tycho-indexer/issues/712)) ([635a3a6](https://github.com/propeller-heads/tycho-indexer/commit/635a3a6d164126c7252f9b43ab82f96296c4af45))

## [0.91.2](https://github.com/propeller-heads/tycho-indexer/compare/0.91.1...0.91.2) (2025-10-01)


### Bug Fixes

* support configuring `substreams_api_token` via CLI and instead of only env variables ([f8b1ece](https://github.com/propeller-heads/tycho-indexer/commit/f8b1ece18db7ce710ebd3c27e9e88ae33576e480))
* support configuring `substreams_api_token` via CLI and instead of only env variables ([#716](https://github.com/propeller-heads/tycho-indexer/issues/716)) ([f7dfb24](https://github.com/propeller-heads/tycho-indexer/commit/f7dfb2408746d9ce3808e7926f96eaf91c033182))

## [0.91.1](https://github.com/propeller-heads/tycho-indexer/compare/0.91.0...0.91.1) (2025-09-30)


### Bug Fixes

* correctly parse token balances in token-analyzer ([7ebb91d](https://github.com/propeller-heads/tycho-indexer/commit/7ebb91dad827fe72780ad83d22284cbae061b560))
* correctly parse token balances in token-analyzer ([#715](https://github.com/propeller-heads/tycho-indexer/issues/715)) ([c31f74e](https://github.com/propeller-heads/tycho-indexer/commit/c31f74e28d61c4bb95ee271e8eb0db68b8835a25))

## [0.91.0](https://github.com/propeller-heads/tycho-indexer/compare/0.90.0...0.91.0) (2025-09-30)


### Features

* Remove dependency on ethers, contracts, ethrpc and ethcontract ([0e798bf](https://github.com/propeller-heads/tycho-indexer/commit/0e798bfbc4e87fd7b9268e10feb46dbbb0bb1c5b))
* Remove dependency on ethers, contracts, ethrpc and ethcontract ([#713](https://github.com/propeller-heads/tycho-indexer/issues/713)) ([043d774](https://github.com/propeller-heads/tycho-indexer/commit/043d774f206620462c1395c7c3945d2a6c941b71))

## [0.90.0](https://github.com/propeller-heads/tycho-indexer/compare/0.89.0...0.90.0) (2025-09-29)


### Features

* Client stability improvements ([#711](https://github.com/propeller-heads/tycho-indexer/issues/711)) ([4a87809](https://github.com/propeller-heads/tycho-indexer/commit/4a87809d5ab09c5eebf5f116c849989f534aaf90))
* correctly deal with advanced synchronizers ([cc9bdce](https://github.com/propeller-heads/tycho-indexer/commit/cc9bdce0dadbe093ef7bfb7d5560cf0f20753bb7))
* keep stale protocol streams ([d6837dd](https://github.com/propeller-heads/tycho-indexer/commit/d6837dddfc4083aa57b85cb13d4c46cc4777073e))
* skip snapshots on quick recoveries ([1648362](https://github.com/propeller-heads/tycho-indexer/commit/1648362bf944c94c6143e4a78c0289191ad1cb86))
* skip syncing extractors messages ([e272e70](https://github.com/propeller-heads/tycho-indexer/commit/e272e70a57e1dd3894c4cee71031a8ad672bcd74))


### Bug Fixes

* avoid unsubscribing multiple times ([7a23165](https://github.com/propeller-heads/tycho-indexer/commit/7a2316592babd431cd6cb56a9e972017b138b19e))

## [0.89.0](https://github.com/propeller-heads/tycho-indexer/compare/0.88.1...0.89.0) (2025-09-26)


### Features

* add `get_oldest_block` method in reorg buffer ([913ee16](https://github.com/propeller-heads/tycho-indexer/commit/913ee1605a261738c012f92bf9c3ce2a1efea941))
* decouple `ReorgBuffer` db commit tracking from finality ([#710](https://github.com/propeller-heads/tycho-indexer/issues/710)) ([a969a82](https://github.com/propeller-heads/tycho-indexer/commit/a969a82dd99d428083306497981bb6e19cea0a0a))
* have the extractor set the `db_committed_upto_block_height` ([711d80b](https://github.com/propeller-heads/tycho-indexer/commit/711d80bb3a3827846d2236379aa42bdd3543ea88))
* rework reorg buffer to track committed height independently of finality ([fd676f9](https://github.com/propeller-heads/tycho-indexer/commit/fd676f9a0d9dfb654328f025a245e6d9085a5c4f))


### Bug Fixes

* adjust revert-finalized height to equal to last not first purged block and improve error handling ([e5982d5](https://github.com/propeller-heads/tycho-indexer/commit/e5982d5d6749a3534d7acbf35f38eaf0230b3064))

## [0.88.1](https://github.com/propeller-heads/tycho-indexer/compare/0.88.0...0.88.1) (2025-09-25)

## [0.88.0](https://github.com/propeller-heads/tycho-indexer/compare/0.87.0...0.88.0) (2025-09-25)


### Features

* add `RPCMetadataProvider` for batch processing of RPC requests. ([286a0ec](https://github.com/propeller-heads/tycho-indexer/commit/286a0ec6d801a2d3e6bbaa8d139cbc66c8c65226))
* Add AllowanceSlotDetector ([8f9f3f9](https://github.com/propeller-heads/tycho-indexer/commit/8f9f3f95214255f0bc06c7656f136e2858e064d5))
* Add AllowanceSlotDetector ([#698](https://github.com/propeller-heads/tycho-indexer/issues/698)) ([ca7546b](https://github.com/propeller-heads/tycho-indexer/commit/ca7546b0ff6f1a4a9ef2fd56cf3dd7bff3c0016f))
* add back tracer.rs ([f8b4d54](https://github.com/propeller-heads/tycho-indexer/commit/f8b4d545583aa2f8f8bc4be91f85dd6923eb0efe))
* Add Balance overrides to Entrypoint Generator ([88df98b](https://github.com/propeller-heads/tycho-indexer/commit/88df98b0300e59ba104d877fe9ddf1c25cd9655d))
* add component pausing in `hook_dci` ([231a65e](https://github.com/propeller-heads/tycho-indexer/commit/231a65e6653dda788f34c8463148be291892a85d))
* add custom errors for improved debugging and handling ([289b34d](https://github.com/propeller-heads/tycho-indexer/commit/289b34dbbbf1cf2ccfd060fe51bc0fa624ece7bd))
* Add Display implementation for EntryPointWithTracingParams ([ca4c030](https://github.com/propeller-heads/tycho-indexer/commit/ca4c03010c61f878236e5a4dafca77e4ce408946))
* Add Display implementation for StorageSnapshotRequest ([cd4434a](https://github.com/propeller-heads/tycho-indexer/commit/cd4434aa9580af8bd3e41a392f09bc7bbfe3cdae))
* Add Grafana stack to docker-compose.yaml ([3f553b2](https://github.com/propeller-heads/tycho-indexer/commit/3f553b2c9404de9aeb0925643c0100945b2afd25))
* Add integration tests and debug logs ([7bcc400](https://github.com/propeller-heads/tycho-indexer/commit/7bcc4003930efaa68ea29a26726412a0cf92fee0))
* add logic to pause components on tracing failures ([7a00b5f](https://github.com/propeller-heads/tycho-indexer/commit/7a00b5ff5da454fca9365266a0b85fd9bb3450dc))
* add metadata response parser trait ([1ee35c1](https://github.com/propeller-heads/tycho-indexer/commit/1ee35c1fbf2c77459ba607619d2f189eb53e1f76))
* Add prune_addresses to RPCTracerParams ([014059a](https://github.com/propeller-heads/tycho-indexer/commit/014059a27900b71fda925281ec192588b7f5a8ad))
* Add retry on Metadata RPC calls ([52a6a9a](https://github.com/propeller-heads/tycho-indexer/commit/52a6a9a3160b2c4c66a8436e41c644ec1ed6541b))
* Add retry with exponential backoff for failed RPC calls ([e265a05](https://github.com/propeller-heads/tycho-indexer/commit/e265a05506975f29557d2f1be0a28f610efd95d2))
* Add slot offset to tracing result ([199ce78](https://github.com/propeller-heads/tycho-indexer/commit/199ce78400717c8ebd11aabfc862ebba0e81bbb2))
* add support for hook identifier in hook registries ([6a5f201](https://github.com/propeller-heads/tycho-indexer/commit/6a5f2018863170ed28ed789b663e9f2ce09285fc))
* add support for hooks ([#611](https://github.com/propeller-heads/tycho-indexer/issues/611)) ([a4e6725](https://github.com/propeller-heads/tycho-indexer/commit/a4e6725942def91f5e6a6c43de6d039aeeb7320e))
* Add test initialization for Univ4 DCI ([08ff9cc](https://github.com/propeller-heads/tycho-indexer/commit/08ff9cc474c682c9c993efdb842e7db1fdee4f18))
* add the ability to override state on DCI EntrypointParams ([e008974](https://github.com/propeller-heads/tycho-indexer/commit/e008974a632ae10e2ede7352087d9091565bd27b))
* add tracing to evaluate dci and hook_dci performance ([34f53ed](https://github.com/propeller-heads/tycho-indexer/commit/34f53ed3efaa7809ac62cfd9772fc2973934f80a))
* Add unit tests and improve packed slot detection in detect_retrigger ([3d0ecae](https://github.com/propeller-heads/tycho-indexer/commit/3d0ecae1160e872fe33b963ce4ba0a67de9d4ca8))
* Add V4MiniRouter runtime ([83d571b](https://github.com/propeller-heads/tycho-indexer/commit/83d571bc526d911170013955429fa6b55e2e1501))
* Enhance storage response handling in EVMBatchAccountExtractor ([732041a](https://github.com/propeller-heads/tycho-indexer/commit/732041a9101c913bc283c6e619aef8475ac50c65))
* Expose previous slot value field ([e06039c](https://github.com/propeller-heads/tycho-indexer/commit/e06039c6e7a7eda1dd62792c64b000d8a154674a))
* Expose separate startup timeout for protocols. ([749fb71](https://github.com/propeller-heads/tycho-indexer/commit/749fb711788f883317932563988685c1bd045759))
* extract reason for failed request ([6cc91ea](https://github.com/propeller-heads/tycho-indexer/commit/6cc91ea7b8317203f3e39c41dea16ef029a792be))
* Fix chrono deprecation errors post update ([40a7b39](https://github.com/propeller-heads/tycho-indexer/commit/40a7b39a76a463a613d02de155ebfd16b292d155))
* Fix EntrypointTracingParams index on Database ([ad2af1f](https://github.com/propeller-heads/tycho-indexer/commit/ad2af1f7758c1c999a411be74e81e3eddcfc81fa))
* Handle initialization and errors ([ebe0da2](https://github.com/propeller-heads/tycho-indexer/commit/ebe0da288f659c65f3dd33b3731b762e6e643efd))
* **hook-support:** implement metadata generator for Euler Swap ([a392dc0](https://github.com/propeller-heads/tycho-indexer/commit/a392dc0ff7f87aed8eca697e2649887ef42e6839))
* implement `DefaultUniswapV4HookOrchestrator` ([5375a7d](https://github.com/propeller-heads/tycho-indexer/commit/5375a7de2d74620d95d9bdabdac8a1a6e5ce21f1))
* implement a retry logic in the tracer ([d65b2c6](https://github.com/propeller-heads/tycho-indexer/commit/d65b2c67a1b33decabe800e37e53a6c9c3b18646))
* implement Balance slot detector ([69bab67](https://github.com/propeller-heads/tycho-indexer/commit/69bab67a9640a243c31b82b101d3de1227dadb01))
* Implement default SwapAmountEstimator ([aa8b41d](https://github.com/propeller-heads/tycho-indexer/commit/aa8b41d570db152c67e75fa140cbc9200eaf0864))
* implement Euler metadata parser ([44c52e3](https://github.com/propeller-heads/tycho-indexer/commit/44c52e3ff202e292c65fdfa87885fb391229b10a))
* Implement HookEntrypointGenerator ([f70f7fa](https://github.com/propeller-heads/tycho-indexer/commit/f70f7fa791af1b3c2fca0016df7f56d8392040b0))
* Implement Hooks permission detector ([e3929a4](https://github.com/propeller-heads/tycho-indexer/commit/e3929a486c1209e5ffbe4d69fa4f690872402c65))
* implement metadata orchestrator ([14fa1df](https://github.com/propeller-heads/tycho-indexer/commit/14fa1df171300f32bb2c8eb557b547da1d63c989))
* implement metadata registries ([cfb06f2](https://github.com/propeller-heads/tycho-indexer/commit/cfb06f2f33e2695c22d71bf773976e45001585a6))
* Implement UniwapV4 Hooks DCI with core features ([4c8c71a](https://github.com/propeller-heads/tycho-indexer/commit/4c8c71a9d78ff466cd498cdffea54af9213e1e01))
* improve account extractor logging ([7923ee4](https://github.com/propeller-heads/tycho-indexer/commit/7923ee479bcdb86ce4ca7c18a475eadfb7830d7b))
* Improve logs and instrumentation on dci ([579985f](https://github.com/propeller-heads/tycho-indexer/commit/579985f581830873b427fa19102646d437052363))
* Improve retrigger detection with offset-aware address comparison ([f0b1dbb](https://github.com/propeller-heads/tycho-indexer/commit/f0b1dbb7b270b65e9a77277385f2505e6705bcee))
* introduce a new error type for tracing failure ([3c3a65d](https://github.com/propeller-heads/tycho-indexer/commit/3c3a65d7acc2c97ccde3c77d595b376b274d102e))
* Load Euler hooks from JSON, rename uniswap-v4 protocol system ([e5477ab](https://github.com/propeller-heads/tycho-indexer/commit/e5477ab511dfcb814c1ec2027deadf2f7ec645f3))
* Make AccountDelta code and change private ([5ec44b2](https://github.com/propeller-heads/tycho-indexer/commit/5ec44b2b23396fe679767486b9857e83b909f0f2))
* Make BalanceSlotDetector obligatory and configurable on EntrypointGenerator ([02e8fdd](https://github.com/propeller-heads/tycho-indexer/commit/02e8fdd4c14791cbaddd9649cb9cb17ffd69aefd))
* merge tracing results on inserts ([7a6ff8f](https://github.com/propeller-heads/tycho-indexer/commit/7a6ff8f2a4319ffba9e843086ceff1dd96099207))
* reduce batch size to 50 ([6ea6042](https://github.com/propeller-heads/tycho-indexer/commit/6ea60429a3ce54d6ce892adf4db4c3c4eeb61064))
* reduce time version to fix conflict with tycho-simulation ([0838b85](https://github.com/propeller-heads/tycho-indexer/commit/0838b8506b57a0fcb092b638e1a9f2f8d3c4f787))
* Rename structs and fix StorageOverride usage ([7afba1e](https://github.com/propeller-heads/tycho-indexer/commit/7afba1e26fd23f346cc91dd89929ddaa057685c7))
* Retry on transient rpc error. ([a56d8d9](https://github.com/propeller-heads/tycho-indexer/commit/a56d8d93df5a6fa572094e206d26bf585487d117))
* return separated error on tracing ([40c6ff6](https://github.com/propeller-heads/tycho-indexer/commit/40c6ff6a4fb0310932e5c13d33371b05c5c190fb))
* Track all storage slots on DCI, excluding tokens or blacklist addr ([886b3da](https://github.com/propeller-heads/tycho-indexer/commit/886b3daa7a997d7b80a1413f2a8ea7259fed0722))
* Update balances and limits percentages to cover more cases ([87a09ee](https://github.com/propeller-heads/tycho-indexer/commit/87a09ee0d9f49c08919a3bfe1419b4ee20bc6704))
* Upgrade alloy, contracts, ethrpc, ethcontract ([847177d](https://github.com/propeller-heads/tycho-indexer/commit/847177d80e45c512820128d7590e58085b10b9bd))
* Use BigInt instead of U256 ([4515b0c](https://github.com/propeller-heads/tycho-indexer/commit/4515b0ca6a023f54e354f1c5909b19b2338b7711))
* Use custom contract to fetch Euler limits with the correct values ([#690](https://github.com/propeller-heads/tycho-indexer/issues/690)) ([2d24a09](https://github.com/propeller-heads/tycho-indexer/commit/2d24a093f46decfd50dc8bc709ba48eac5a06480))
* Use hook address for Entrypoint id ([ed251c6](https://github.com/propeller-heads/tycho-indexer/commit/ed251c668ac75f2000e884d88970edf49c54dd49))
* Use specific RPC for tracing ([6f856cb](https://github.com/propeller-heads/tycho-indexer/commit/6f856cb9bf1bf1ba9489b2f16a1bf29b5a0bfadf))
* Use tycho-substreams 0.5.0 ([5e2ab18](https://github.com/propeller-heads/tycho-indexer/commit/5e2ab180e48e6c7bf5c1618673dd388d85b46c71))
* Use unique entrypoint IDs per hook on Entrypoint Generator ([5965541](https://github.com/propeller-heads/tycho-indexer/commit/59655416476351a59ea5c565d9e7c474857dc9f6))
* validate that the found slots actually modify the balance ([410610b](https://github.com/propeller-heads/tycho-indexer/commit/410610bde1d21351bbe1811b0c1e9d9946ba8155))


### Bug Fixes

* adapt dci `extract_tracked_updates` ([ba5d56a](https://github.com/propeller-heads/tycho-indexer/commit/ba5d56a38e57cd1f9c6f1b43535a9403d21799c2))
* Add and use constructor for AccountDelta ([4116686](https://github.com/propeller-heads/tycho-indexer/commit/4116686ce077d8d4d314698e5fdff5c2e00f1adf))
* add prune_addresses to the generated RPCTracerParams ([104098d](https://github.com/propeller-heads/tycho-indexer/commit/104098d0b81447588d08dde8273922c0db98bac6))
* Blacklist permit2 ([13a1cab](https://github.com/propeller-heads/tycho-indexer/commit/13a1cabe360bbb9c91b07f6742507e840219e2d6))
* cargo fmt + test fixes ([ea61492](https://github.com/propeller-heads/tycho-indexer/commit/ea614927b6a339d58d0ec6f873d827b70aaf7773))
* correct tracked_contract cache None semantics ([6f2b241](https://github.com/propeller-heads/tycho-indexer/commit/6f2b241fdbd724153650354cacdfb5a6d98cc2d9))
* correctly merge attributes when inserting "pausing". ([771ad9a](https://github.com/propeller-heads/tycho-indexer/commit/771ad9a98895efc7ce4779a71a733e9149bebcb0))
* DCI logs and traces ([dbacdbc](https://github.com/propeller-heads/tycho-indexer/commit/dbacdbc2c11732d64b1ca2b5c00ff930bf3fb94b))
* detect account dependencies from non-call opcodes in EVM tracer ([ab4f93f](https://github.com/propeller-heads/tycho-indexer/commit/ab4f93fb58825e83d2b44abd9bb206f0594c2b63))
* Do not overwrite Component State when adding Entrypoints ([786f661](https://github.com/propeller-heads/tycho-indexer/commit/786f66101bb11d13a022fe014ed59fd81753df67))
* Enable TLS on Alloy ([153b501](https://github.com/propeller-heads/tycho-indexer/commit/153b501606a5464c859ad538b5a5106590ea8758))
* faulty client rpc test ([49f7953](https://github.com/propeller-heads/tycho-indexer/commit/49f7953ad0da2b4a8a3aef11777707fac32d21ff))
* Fetch new accounts even if they don't have storage slots ([77df048](https://github.com/propeller-heads/tycho-indexer/commit/77df048b394e5832c3c944ecf4f28867573aea71))
* Fetch new storage slots detected after a new tracing ([1a93cbf](https://github.com/propeller-heads/tycho-indexer/commit/1a93cbf5ae1516ffe0bbbd70cd662d506c8f2273))
* fix CI ([c6131a6](https://github.com/propeller-heads/tycho-indexer/commit/c6131a6c928f07d99c33af96127fab6105df1168))
* Fix EulerMetadataGenerator to use hooks address instead of ComponentId ([5947240](https://github.com/propeller-heads/tycho-indexer/commit/5947240d5a5e8d1b16b99b0a2efea9b50a5ec92c))
* Fix Limit entrypoint insertion ([42ec085](https://github.com/propeller-heads/tycho-indexer/commit/42ec085b8484a13015e19f42d27da6a890c1d02c))
* Fix TLS not working after bumping Alloy version ([#706](https://github.com/propeller-heads/tycho-indexer/issues/706)) ([1355379](https://github.com/propeller-heads/tycho-indexer/commit/1355379cfcef553fcb675ab0f7ff726e166eac80))
* Fix token ordering and calldata generation ([0315746](https://github.com/propeller-heads/tycho-indexer/commit/031574621dba13219e79bd61a0376ac75c279a7b))
* fmt & badly closed braces ([994d27d](https://github.com/propeller-heads/tycho-indexer/commit/994d27d9ab84d322c8eeed2afcb5fde9331c47ea))
* Handle unordered tokens on EntrypointGenerator ([66efdf7](https://github.com/propeller-heads/tycho-indexer/commit/66efdf7299b3ac8b15a76797e1dcc6972ba24087))
* Improve interfaces, fix EntrypointId and attributes ([4ffd876](https://github.com/propeller-heads/tycho-indexer/commit/4ffd8768e5d3f14afb9331e89a05f19c83510ef8))
* increase client timeout ([674caf9](https://github.com/propeller-heads/tycho-indexer/commit/674caf9b4e3d05fc855fee02f87f9a880252d901))
* increase default max missed blocks on mainnet ([3114dd6](https://github.com/propeller-heads/tycho-indexer/commit/3114dd6618e933761c3b987e1ef5f381bad03d7a))
* increase heartbeat timeout ([#703](https://github.com/propeller-heads/tycho-indexer/issues/703)) ([93560e9](https://github.com/propeller-heads/tycho-indexer/commit/93560e9af872bb90d9ccb7304b4eb56baff6342f))
* Inject on block Entrypoints instead of only EntrypointParams ([5b3e267](https://github.com/propeller-heads/tycho-indexer/commit/5b3e2679ed89a9c4d2b9c2a29dc394d871c341ae))
* make `TracingResult` deserialization backward compatible ([868202d](https://github.com/propeller-heads/tycho-indexer/commit/868202d5684f8bb38d40b9e0d20092fce724dd5b))
* make `TracingResult` deserialization backward compatible ([#707](https://github.com/propeller-heads/tycho-indexer/issues/707)) ([6695c1e](https://github.com/propeller-heads/tycho-indexer/commit/6695c1edab0aca1ef3d8a6c929b52040862266ee))
* make clippy happy ([8a3fb8d](https://github.com/propeller-heads/tycho-indexer/commit/8a3fb8d6e405b5942d304c12ef686fb31a69a99f))
* Override the correct contract for token balances ([4054c2a](https://github.com/propeller-heads/tycho-indexer/commit/4054c2a38ee482a3ef4c43cba6ff79c2d426724c))
* Post rebase fixes ([7bfada4](https://github.com/propeller-heads/tycho-indexer/commit/7bfada4842015fab783a9124a5f6c3d7a26bb44e))
* prevent entrypoint regeneration for components that were already traced. ([319eef8](https://github.com/propeller-heads/tycho-indexer/commit/319eef87b0e1e59ef393f3e04581e92fe770590d))
* properly handle finality for layers with set values ([bb5c02d](https://github.com/propeller-heads/tycho-indexer/commit/bb5c02df88fc27bf2983cee864b8ef12ccdaf553))
* properly order tokens when parsing euler response ([f058dc8](https://github.com/propeller-heads/tycho-indexer/commit/f058dc803a603d8b93e54d426e6a514b322ecd9e))
* Reduce swap amounts to up to 10% of the reserves ([aef8e5c](https://github.com/propeller-heads/tycho-indexer/commit/aef8e5c17e9ba0754188ec6c028c160ebcc47bd8))
* Reduce the percentages used to generate swap amounts ([1cca1f7](https://github.com/propeller-heads/tycho-indexer/commit/1cca1f72d8e1a533a2fd40f61f74eea6746f5cf3))
* Remove From<StorageKey> implementation ([373cc59](https://github.com/propeller-heads/tycho-indexer/commit/373cc5974adbabe4da253341e6483ed36dfc4b2e))
* remove unnecessary spans ([f83d424](https://github.com/propeller-heads/tycho-indexer/commit/f83d424138aebc06b94399d107f94d190cb3b7c7))
* retry on Balance detector if the call returns an RPC retriable error ([2878e51](https://github.com/propeller-heads/tycho-indexer/commit/2878e51f4d42fcf2ef7256d6a9f18b14c274bd40))
* retry on Balance detector if the call returns an RPC retriable error ([#708](https://github.com/propeller-heads/tycho-indexer/issues/708)) ([b25a266](https://github.com/propeller-heads/tycho-indexer/commit/b25a2661f3bfab33ed7103bbe6cbf8a89c65a48e))
* test_traced_entry_point_display test ([f997b66](https://github.com/propeller-heads/tycho-indexer/commit/f997b66913436ea0f0fa07c0d83ea09ac02542c7))
* Update Entrypoint DB Schema to include external_id on uniqueness validation ([c91ed9b](https://github.com/propeller-heads/tycho-indexer/commit/c91ed9b459c2ea40597f2dd394309ce208113b49))
* wrongly dereferenced offset var ([c0d645d](https://github.com/propeller-heads/tycho-indexer/commit/c0d645d7e00bb3931d6c641ebb565912f3bef638))

## [0.87.0](https://github.com/propeller-heads/tycho-indexer/compare/0.86.0...0.87.0) (2025-09-23)


### Features

* enhance RpcCache with memory size weighing ([d33e6aa](https://github.com/propeller-heads/tycho-indexer/commit/d33e6aa7d02b9ca290c879a87ae92cdc15f39c11))
* enhance RpcCache with memory size weighing ([#700](https://github.com/propeller-heads/tycho-indexer/issues/700)) ([58d352a](https://github.com/propeller-heads/tycho-indexer/commit/58d352a3f56414b9e697d74163c4ba7e318efb40))

## [0.86.0](https://github.com/propeller-heads/tycho-indexer/compare/0.85.0...0.86.0) (2025-09-19)


### Features

* handle end-of-stream as a valid state, instead of as an error ([3463428](https://github.com/propeller-heads/tycho-indexer/commit/34634287f6549168cf2c079b92f71ad099efb0dd))


### Bug Fixes

* create an async_main function so that run_indexer can create its own tokio runtime ([64c7720](https://github.com/propeller-heads/tycho-indexer/commit/64c77200f93d0607f5a62bd78fa7bbb4bfe2503d))

## [0.85.0](https://github.com/propeller-heads/tycho-indexer/compare/0.84.0...0.85.0) (2025-09-18)


### Features

* Expose retry configurations on TychoStreamBuilder ([e677e13](https://github.com/propeller-heads/tycho-indexer/commit/e677e13e9a15bce36925d05cf1c34fdf01122531))
* Expose retry configurations on TychoStreamBuilder ([#695](https://github.com/propeller-heads/tycho-indexer/issues/695)) ([ccbc67d](https://github.com/propeller-heads/tycho-indexer/commit/ccbc67d32eba32c9c9de3ee97d684e20959dbf13))


### Bug Fixes

* reconnection test timing issues. ([780d967](https://github.com/propeller-heads/tycho-indexer/commit/780d967779f1fdab42c7c5f173fca251f058fb6f))

## [0.84.0](https://github.com/propeller-heads/tycho-indexer/compare/0.83.4...0.84.0) (2025-09-18)


### Features

* communicate websocket server errors correctly ([e3b1d1e](https://github.com/propeller-heads/tycho-indexer/commit/e3b1d1e6e3042ce73fba9afbfc8957a5e9758746))
* communicate websocket server errors correctly ([#694](https://github.com/propeller-heads/tycho-indexer/issues/694)) ([75a9a37](https://github.com/propeller-heads/tycho-indexer/commit/75a9a37e066debcb24c74ec6c886e10ceb4c2f79))

## [0.83.4](https://github.com/propeller-heads/tycho-indexer/compare/0.83.3...0.83.4) (2025-09-11)


### Bug Fixes

* prevent race condition in extractors/server startup sequence ([5a1af8e](https://github.com/propeller-heads/tycho-indexer/commit/5a1af8ead6e9eca9906b914a8b81c4b5e13f0da7))
* prevent race condition in extractors/server startup sequence ([#689](https://github.com/propeller-heads/tycho-indexer/issues/689)) ([90023a1](https://github.com/propeller-heads/tycho-indexer/commit/90023a13554a49e09c3e4e84be3c5d2424580506))

## [0.83.3](https://github.com/propeller-heads/tycho-indexer/compare/0.83.2...0.83.3) (2025-09-10)


### Bug Fixes

* Add protocol_system to RunSpkgArgs ([7673d41](https://github.com/propeller-heads/tycho-indexer/commit/7673d41ea2982c8486712fb0ae0bf2a12d847235))
* Add protocol_system to RunSpkgArgs ([#688](https://github.com/propeller-heads/tycho-indexer/issues/688)) ([6afbf17](https://github.com/propeller-heads/tycho-indexer/commit/6afbf17578801d3b14d7a67805c682d3cdd7d3dc))

## [0.83.2](https://github.com/propeller-heads/tycho-indexer/compare/0.83.1...0.83.2) (2025-09-09)


### Bug Fixes

* buffer overflow handling with force unsubscribe ([216ed42](https://github.com/propeller-heads/tycho-indexer/commit/216ed42a67ead3f36ce671e96cd6d7f01c4f018a))
* handle buffer overflow in client ([#686](https://github.com/propeller-heads/tycho-indexer/issues/686)) ([a34668b](https://github.com/propeller-heads/tycho-indexer/commit/a34668b68c3dc7fac5e3892619ae4ab69f19762d))

## [0.83.1](https://github.com/propeller-heads/tycho-indexer/compare/0.83.0...0.83.1) (2025-09-05)


### Bug Fixes

* correctly get all values from cache when needed. ([ebe6ff5](https://github.com/propeller-heads/tycho-indexer/commit/ebe6ff57504722c71c95db77a7b8b5e584c221b9))
* correctly get all values from cache when needed. ([#673](https://github.com/propeller-heads/tycho-indexer/issues/673)) ([b8250fa](https://github.com/propeller-heads/tycho-indexer/commit/b8250fa9dcad90a4b2237c23753b3a158c0aba11))

## [0.83.0](https://github.com/propeller-heads/tycho-indexer/compare/0.82.0...0.83.0) (2025-08-30)


### Features

* add a retry logic for account extraction in DCI ([fc6d226](https://github.com/propeller-heads/tycho-indexer/commit/fc6d22696baf91d123cfc8c7ea08de4093995d95))
* add retry loop around account extraction in DCI ([#671](https://github.com/propeller-heads/tycho-indexer/issues/671)) ([f529864](https://github.com/propeller-heads/tycho-indexer/commit/f5298642ac0b86ba6c6dafa5770bbeb6c1192524))

## [0.82.0](https://github.com/propeller-heads/tycho-indexer/compare/0.81.6...0.82.0) (2025-08-26)


### Features

* add user identity in metrics and spans ([382f408](https://github.com/propeller-heads/tycho-indexer/commit/382f408dd8a93b4a41a9f5f2dfc22ef69ce699f2))
* add user identity in metrics and spans ([#669](https://github.com/propeller-heads/tycho-indexer/issues/669)) ([1aadf8d](https://github.com/propeller-heads/tycho-indexer/commit/1aadf8de18c055b0a4eea8c8f544130b8d7ccdaf))

## [0.81.6](https://github.com/propeller-heads/tycho-indexer/compare/0.81.5...0.81.6) (2025-08-13)


### Bug Fixes

* Simplify GetAmountOutParams to hold Bytes only ([cdc8509](https://github.com/propeller-heads/tycho-indexer/commit/cdc85098fddbb7aad8fe95bf98c02dd8ee2676f5))
* Simplify GetAmountOutParams to hold Bytes only ([#653](https://github.com/propeller-heads/tycho-indexer/issues/653)) ([c35d458](https://github.com/propeller-heads/tycho-indexer/commit/c35d458fae12d98ff1818918e51c3232a3134413))

## [0.81.5](https://github.com/propeller-heads/tycho-indexer/compare/0.81.4...0.81.5) (2025-08-12)


### Bug Fixes

* Derive Debug in SignedQuote ([31fd3c7](https://github.com/propeller-heads/tycho-indexer/commit/31fd3c7e715d61e586568f1b818ec5df2946fe28))
* Derive Debug in SignedQuote ([#650](https://github.com/propeller-heads/tycho-indexer/issues/650)) ([29fe8ad](https://github.com/propeller-heads/tycho-indexer/commit/29fe8ad75277e833bb80e0bbf8657ada5a2986a1))

## [0.81.4](https://github.com/propeller-heads/tycho-indexer/compare/0.81.3...0.81.4) (2025-08-11)


### Bug Fixes

* WsDeltas client forever blocking subscribe. ([1b6ff33](https://github.com/propeller-heads/tycho-indexer/commit/1b6ff333150613031dc2ffc1b0c1b36170c2fdea))
* WsDeltas client forever blocking subscribe. ([#648](https://github.com/propeller-heads/tycho-indexer/issues/648)) ([4c2e989](https://github.com/propeller-heads/tycho-indexer/commit/4c2e989e3f0997646fe82834d237cc1a0b6c9a67))

## [0.81.3](https://github.com/propeller-heads/tycho-indexer/compare/0.81.2...0.81.3) (2025-08-08)


### Bug Fixes

* buggy transitions to advanced ([904314e](https://github.com/propeller-heads/tycho-indexer/commit/904314e5d20485d768e0abb0be3080d30220c430))
* For now error if we are left with only advanced streams. ([40d3670](https://github.com/propeller-heads/tycho-indexer/commit/40d367092a125ba8a50838b3dc814b527e69fe57))
* improve stale synchronizer detection in BlockSynchronizer ([0991d3f](https://github.com/propeller-heads/tycho-indexer/commit/0991d3f84989a211c55bd092c8509f530cd0efb3))
* prevent premature main loop exit when all synchronizers are delayed ([d04ad69](https://github.com/propeller-heads/tycho-indexer/commit/d04ad6909f198536e3d99956d9de39063b785f57))
* stale synchronizer detection ([#647](https://github.com/propeller-heads/tycho-indexer/issues/647)) ([77f45d4](https://github.com/propeller-heads/tycho-indexer/commit/77f45d437d5df1e73d463403301671276df6e4f1))

## [0.81.2](https://github.com/propeller-heads/tycho-indexer/compare/0.81.1...0.81.2) (2025-08-06)


### Bug Fixes

* Resolve WebSocket deadlock with async subscription handling ([ba5715f](https://github.com/propeller-heads/tycho-indexer/commit/ba5715f92a81a3242696419fda15c7263e62a3f1))
* Websocket deadlocks ([#642](https://github.com/propeller-heads/tycho-indexer/issues/642)) ([cfde3ba](https://github.com/propeller-heads/tycho-indexer/commit/cfde3ba0cad753a1e05f98aab605f2358e9e80a4))


### Performance Improvements

* Eliminate mutex from WebSocket subscribers for lock-free access ([2a11192](https://github.com/propeller-heads/tycho-indexer/commit/2a11192f1a5dce89f3f2b40d3f158bbb2cd0a494))

## [0.81.1](https://github.com/propeller-heads/tycho-indexer/compare/0.81.0...0.81.1) (2025-08-06)


### Bug Fixes

* add proper deltas subscription cleanup and fix tests ([14a682f](https://github.com/propeller-heads/tycho-indexer/commit/14a682f013dba94236e2637209439d700f224cd1))
* ensure state_sync cleanup runs on all exit paths ([c482b23](https://github.com/propeller-heads/tycho-indexer/commit/c482b236ae30022744e5c852d0d7e8a9e2d6b33e))
* prevent unnecessary warnings in deltas client unsubscribe ([0fa5c1b](https://github.com/propeller-heads/tycho-indexer/commit/0fa5c1bdd671f26b555700b1a9e17dcd11fff297))
* properly close WebSocket client and log close errors ([db0d27e](https://github.com/propeller-heads/tycho-indexer/commit/db0d27e26641e02c6e641697c70449945f15d214))
* tycho-client shutdown cleanup and improve error handling ([#637](https://github.com/propeller-heads/tycho-indexer/issues/637)) ([2043997](https://github.com/propeller-heads/tycho-indexer/commit/2043997db77bdb68177a2a8507d1cfa80f4f912b))

## [0.81.0](https://github.com/propeller-heads/tycho-indexer/compare/0.80.0...0.81.0) (2025-07-29)


### Features

* Change return of as_indicatively_priced to Result ([c34c6bf](https://github.com/propeller-heads/tycho-indexer/commit/c34c6bf6424af37407926f135545bd76d06525ed))
* Change return of as_indicatively_priced to Result ([#645](https://github.com/propeller-heads/tycho-indexer/issues/645)) ([803575b](https://github.com/propeller-heads/tycho-indexer/commit/803575bcbd287840c00bcd90516272a1181e0b23))

## [0.80.0](https://github.com/propeller-heads/tycho-indexer/compare/0.79.0...0.80.0) (2025-07-29)


### Features

* Add as_indicatively_priced in ProtocolSim ([1d71bb2](https://github.com/propeller-heads/tycho-indexer/commit/1d71bb2e316d27ef089a81fe4200cbdb476e6c11))
* Add as_indicatively_priced in ProtocolSim  ([#644](https://github.com/propeller-heads/tycho-indexer/issues/644)) ([30e1d57](https://github.com/propeller-heads/tycho-indexer/commit/30e1d57de680f4cab529e3c844af330e2f181504))
* Implement IndicativelyPriced for ProtocolSim ([7a3571e](https://github.com/propeller-heads/tycho-indexer/commit/7a3571eadaf3ff95b5180284237a3e952052b06a))
* Make IndicativelyPriced a super trait of ProtocolSim ([7bce804](https://github.com/propeller-heads/tycho-indexer/commit/7bce8048c14b1fa3d6eb99715b19c62ccb4bee07))

## [0.79.0](https://github.com/propeller-heads/tycho-indexer/compare/0.78.6...0.79.0) (2025-07-25)


### Features

* Add default to FeedMessage ([cedc469](https://github.com/propeller-heads/tycho-indexer/commit/cedc469222ccf75912ef2a6a6258f9141b817d7f))
* Add default to FeedMessage ([#639](https://github.com/propeller-heads/tycho-indexer/issues/639)) ([b120186](https://github.com/propeller-heads/tycho-indexer/commit/b120186dcfaefe7f6469976dd506920724d1f9e4))


### Bug Fixes

* Add gas_usage to Token ([66a91b5](https://github.com/propeller-heads/tycho-indexer/commit/66a91b5b18446b69c5490a68f6e0025ab2cb4bdf))

## [0.78.6](https://github.com/propeller-heads/tycho-indexer/compare/0.78.5...0.78.6) (2025-07-25)

## [0.78.5](https://github.com/propeller-heads/tycho-indexer/compare/0.78.4...0.78.5) (2025-07-24)


### Bug Fixes

* Remove missing state query on versioning ([e0db7c0](https://github.com/propeller-heads/tycho-indexer/commit/e0db7c088f70d0d2af54ccad0a42b09b10ed520f))
* Remove missing state query on versioning ([#636](https://github.com/propeller-heads/tycho-indexer/issues/636)) ([df08a88](https://github.com/propeller-heads/tycho-indexer/commit/df08a88e8c622d7b9f82ef75e1424ca1d65c6fb7))

## [0.78.4](https://github.com/propeller-heads/tycho-indexer/compare/0.78.3...0.78.4) (2025-07-24)


### Bug Fixes

* Specify minimum rust version ([de37e86](https://github.com/propeller-heads/tycho-indexer/commit/de37e86220d32f678a77082cfe377d01402ca125))
* Specify minimum rust version ([#638](https://github.com/propeller-heads/tycho-indexer/issues/638)) ([a052d76](https://github.com/propeller-heads/tycho-indexer/commit/a052d76b883228532f1d7f00d67231e90c4da02e))

## [0.78.3](https://github.com/propeller-heads/tycho-indexer/compare/0.78.2...0.78.3) (2025-07-22)

## [0.78.2](https://github.com/propeller-heads/tycho-indexer/compare/0.78.1...0.78.2) (2025-07-21)

## [0.78.1](https://github.com/propeller-heads/tycho-indexer/compare/0.78.0...0.78.1) (2025-07-18)


### Bug Fixes

* disable DCI queries on Base and Unichain ([7cbc552](https://github.com/propeller-heads/tycho-indexer/commit/7cbc55250367c65872d4213e9538ccbb3875d56f))
* disable DCI queries on Base and Unichain ([#632](https://github.com/propeller-heads/tycho-indexer/issues/632)) ([7d94b96](https://github.com/propeller-heads/tycho-indexer/commit/7d94b96996de5c8dcec182d9cc92e5bb5cb8888f))

## [0.78.0](https://github.com/propeller-heads/tycho-indexer/compare/0.77.2...0.78.0) (2025-07-18)


### Features

* Add IndicativelyPriced trait ([14d4b47](https://github.com/propeller-heads/tycho-indexer/commit/14d4b4760c3886c30bdbe8d4e7d7e0c3ed7401ca))
* Add IndicativelyPriced trait ([#631](https://github.com/propeller-heads/tycho-indexer/issues/631)) ([60fa7b2](https://github.com/propeller-heads/tycho-indexer/commit/60fa7b2a46385200e49d58cc0958ccc9642cb1f8))

## [0.77.2](https://github.com/propeller-heads/tycho-indexer/compare/0.77.1...0.77.2) (2025-07-17)


### Bug Fixes

* Generalise FeedMessage to hold a HeaderLike and not a BlockHeader ([8394336](https://github.com/propeller-heads/tycho-indexer/commit/839433620169c764aa27cacdb79f791cd96daa71))
* Generalise FeedMessage to hold a HeaderLike and not a BlockHeader ([#624](https://github.com/propeller-heads/tycho-indexer/issues/624)) ([85ae669](https://github.com/propeller-heads/tycho-indexer/commit/85ae669a6441ed4ecedac9d79ade35fa63d0edb8))
* Rename ts to block_number_or_timestamp ([58a0128](https://github.com/propeller-heads/tycho-indexer/commit/58a012848295bf748c1bed277f9557f1b1ede46c))

## [0.77.1](https://github.com/propeller-heads/tycho-indexer/compare/0.77.0...0.77.1) (2025-07-16)


### Bug Fixes

* Revert: "fix: Correctly set Url scheme in TychoStreamBuilder" ([#627](https://github.com/propeller-heads/tycho-indexer/issues/627)) ([d8f2b0b](https://github.com/propeller-heads/tycho-indexer/commit/d8f2b0b83fde53b1a47e0d8b4f4f6b7caa96aa94))

## [0.77.0](https://github.com/propeller-heads/tycho-indexer/compare/0.76.1...0.77.0) (2025-07-14)


### Features

* Generalise Header and add ProtocolSim ([#619](https://github.com/propeller-heads/tycho-indexer/issues/619)) ([d6c7be4](https://github.com/propeller-heads/tycho-indexer/commit/d6c7be437c54c8369740d577442657d3e6c1350e))
* Generalise Header by creating a HeaderLike trait ([828f4d4](https://github.com/propeller-heads/tycho-indexer/commit/828f4d44bba6fec9be3e25546eff52391dd808fa))
* Move ProtocolSim from simulation to tycho-common ([97e8e08](https://github.com/propeller-heads/tycho-indexer/commit/97e8e08db5ee442af13c7dd25135bd6edb3fb269))

## [0.76.1](https://github.com/propeller-heads/tycho-indexer/compare/0.76.0...0.76.1) (2025-07-11)


### Bug Fixes

* Correctly set Url scheme in TychoStreamBuilder ([bac1975](https://github.com/propeller-heads/tycho-indexer/commit/bac19756741194b2ecc5902b4fc4e92f20585464))
* Correctly set Url scheme in TychoStreamBuilder ([#621](https://github.com/propeller-heads/tycho-indexer/issues/621)) ([839e919](https://github.com/propeller-heads/tycho-indexer/commit/839e91917da0a7c9a1ad340fd7fed205700a6f36))

## [0.76.0](https://github.com/propeller-heads/tycho-indexer/compare/0.75.1...0.76.0) (2025-07-11)


### Features

* Add id and wrapped_native_token to Chain ([9c79c8f](https://github.com/propeller-heads/tycho-indexer/commit/9c79c8f7a3501e1edd2b86cff43460729b62991f))
* Add timestamp to Header ([684834a](https://github.com/propeller-heads/tycho-indexer/commit/684834a8f053907ad9547b68d870d2e2c4117249))
* Remove duplicated models ([#618](https://github.com/propeller-heads/tycho-indexer/issues/618)) ([b528e9b](https://github.com/propeller-heads/tycho-indexer/commit/b528e9b38a9e321f295f09bcb90d9760a7e3c591))
* Rename CurrencyToken to Token ([a30c046](https://github.com/propeller-heads/tycho-indexer/commit/a30c046ac7b022f7a816545486af81e724863f07))

## [0.75.1](https://github.com/propeller-heads/tycho-indexer/compare/0.75.0...0.75.1) (2025-07-11)


### Bug Fixes

* correctly handle reverts in DCI cache ([aee8b7d](https://github.com/propeller-heads/tycho-indexer/commit/aee8b7d70ef65977b4cd9343cf9f5473643fb154))
* correctly handle reverts in DCI cache ([#620](https://github.com/propeller-heads/tycho-indexer/issues/620)) ([ab4c838](https://github.com/propeller-heads/tycho-indexer/commit/ab4c838fafeb73138f386249c9af75cd154215a3))

## [0.75.0](https://github.com/propeller-heads/tycho-indexer/compare/0.74.0...0.75.0) (2025-07-07)


### Features

* Support cloning FeedMessage ([408a349](https://github.com/propeller-heads/tycho-indexer/commit/408a349ff9b282276402c5090a550b7edc38535b))
* Support cloning FeedMessage ([#612](https://github.com/propeller-heads/tycho-indexer/issues/612)) ([ab32f4a](https://github.com/propeller-heads/tycho-indexer/commit/ab32f4a0d3458ceb186835d6318beadb230735e3))

## [0.74.0](https://github.com/propeller-heads/tycho-indexer/compare/0.73.0...0.74.0) (2025-06-30)


### Features

* **client-py:** add missing endpoints ([efd6d96](https://github.com/propeller-heads/tycho-indexer/commit/efd6d96a8d09d6313af77ca42bda4b9ac9d1e8d0))
* **client-py:** add pagination to all endpoints ([f7c98b2](https://github.com/propeller-heads/tycho-indexer/commit/f7c98b2658f5b4c047db0842d1ca1bab236c67f0))
* **client-py:** update python RPC client ([#606](https://github.com/propeller-heads/tycho-indexer/issues/606)) ([f6a4ef5](https://github.com/propeller-heads/tycho-indexer/commit/f6a4ef54095d5e5d2b550d81316ce282413268c0))

## [0.73.0](https://github.com/propeller-heads/tycho-indexer/compare/0.72.1...0.73.0) (2025-06-27)


### Features

* mark creation_tx as deprecated on ResponseAccount ([224c4b8](https://github.com/propeller-heads/tycho-indexer/commit/224c4b883a6733e310b9feb6c06ecc81c5d7338d))
* **storage:** remove join to transaction table in get_contracts ([0e6e9e5](https://github.com/propeller-heads/tycho-indexer/commit/0e6e9e5071ca722887266a8861862a66ddb6dea6))


### Bug Fixes

* correctly fill the reorg buffer ([10c951d](https://github.com/propeller-heads/tycho-indexer/commit/10c951def0487fa97baf4e93ee519d40e35435b0))
* correctly fill the reorg buffer ([#605](https://github.com/propeller-heads/tycho-indexer/issues/605)) ([2f924f5](https://github.com/propeller-heads/tycho-indexer/commit/2f924f5f38380e5f878d294693af946b3ab02379))
* do not filter out contracts with NULL created_ts ([46fbd82](https://github.com/propeller-heads/tycho-indexer/commit/46fbd822dfb91cd75a9ed83b4ee9ef96875648d4))
* filter for accounts that have associated code ([e9904bb](https://github.com/propeller-heads/tycho-indexer/commit/e9904bb7b1b6d518142e116b22887e4d7a29836d))
* improve handling of missing code errors ([7393c92](https://github.com/propeller-heads/tycho-indexer/commit/7393c92d006e211aca4eed378485334c8a159700))
* remove transaction table query from get_contract ([f60106a](https://github.com/propeller-heads/tycho-indexer/commit/f60106afa7932a063d9be0891bb53cc369f88cdf))
* **storage:** fix bug that filters out contracts missing a creation_tx ([#602](https://github.com/propeller-heads/tycho-indexer/issues/602)) ([75428da](https://github.com/propeller-heads/tycho-indexer/commit/75428da852b4b0aca169504f10cc9a59cec068a5))

## [0.72.1](https://github.com/propeller-heads/tycho-indexer/compare/0.72.0...0.72.1) (2025-06-25)


### Bug Fixes

* **client:** link dci detected contracts to components within the tracker ([#601](https://github.com/propeller-heads/tycho-indexer/issues/601)) ([98855bf](https://github.com/propeller-heads/tycho-indexer/commit/98855bf2ad1a0930a5f2fba08056c3b18231beb0))
* link dci detected contracts to components within the tracker ([3137ccf](https://github.com/propeller-heads/tycho-indexer/commit/3137ccf29beb50783c26baf8b9c2191c2fde823d))

## [0.72.0](https://github.com/propeller-heads/tycho-indexer/compare/0.71.4...0.72.0) (2025-06-24)


### Features

* **dci:** add revert logic ([#590](https://github.com/propeller-heads/tycho-indexer/issues/590)) ([2d12b87](https://github.com/propeller-heads/tycho-indexer/commit/2d12b87417ba3d59d72d7f257e8933031ad529c8))
* **dci:** add support for reorgs. ([f6c23bf](https://github.com/propeller-heads/tycho-indexer/commit/f6c23bf842065ec271dffe781e058403a41ebe13))

## [0.71.4](https://github.com/propeller-heads/tycho-indexer/compare/0.71.3...0.71.4) (2025-06-23)


### Bug Fixes

* correctly handle traced entrypoint upserts ([0e69e84](https://github.com/propeller-heads/tycho-indexer/commit/0e69e84cd004faef89c1a9f177440c55d7e8ef86))
* correctly handle traced entrypoint upserts ([#599](https://github.com/propeller-heads/tycho-indexer/issues/599)) ([e58d546](https://github.com/propeller-heads/tycho-indexer/commit/e58d5469f91b04c1776006a7dc12def6b7a62763))

## [0.71.3](https://github.com/propeller-heads/tycho-indexer/compare/0.71.2...0.71.3) (2025-06-19)

## [0.71.2](https://github.com/propeller-heads/tycho-indexer/compare/0.71.1...0.71.2) (2025-06-19)


### Bug Fixes

* fix build for python wheel and crates.io ([#597](https://github.com/propeller-heads/tycho-indexer/issues/597)) ([b0e99ae](https://github.com/propeller-heads/tycho-indexer/commit/b0e99aee906cd4d70912f42d72e79747ef7225bc))
* fix python wheel build ([20ae4bf](https://github.com/propeller-heads/tycho-indexer/commit/20ae4bfe1652359f17c2fa9a87dd9f4903080f2b))

## [0.71.1](https://github.com/propeller-heads/tycho-indexer/compare/0.71.0...0.71.1) (2025-06-19)


### Bug Fixes

* get DCI plugin RPC url from global config ([88f2b91](https://github.com/propeller-heads/tycho-indexer/commit/88f2b91ab1e85fddd4883324b707e7c610d29b34))
* get DCI plugin RPC url from global config ([#596](https://github.com/propeller-heads/tycho-indexer/issues/596)) ([cc922c4](https://github.com/propeller-heads/tycho-indexer/commit/cc922c4d0eef3cfbdab365f6efad8982b2be0bbc))

## [0.71.0](https://github.com/propeller-heads/tycho-indexer/compare/0.70.9...0.71.0) (2025-06-19)


### Features

* (WIP) Add get_traced_entrypoints endpoint. ([0528c3c](https://github.com/propeller-heads/tycho-indexer/commit/0528c3cbcff441e2d03542c3a513556ec49c9539))
* (WIP) get_traced_entrypoints pagination + caching ([2af5359](https://github.com/propeller-heads/tycho-indexer/commit/2af5359f92a9666659a4791089a8cb0bcbcf1f88))
* access control on add_entry_points ([9e9a7a4](https://github.com/propeller-heads/tycho-indexer/commit/9e9a7a4da46cc29c13e27c32baf1c6a0e76e9e6b))
* Add BatchAccountExtractor with balance and code get logic ([e3b6566](https://github.com/propeller-heads/tycho-indexer/commit/e3b6566fc6b46a9f2929816fe99c969578bee450))
* add block storage changes to BlockChanges extractor model ([fc96b8e](https://github.com/propeller-heads/tycho-indexer/commit/fc96b8eea49c667b5ffbfc880c5161fd11626671))
* add dci plugin to ProtocolExtractor ([5edf7e8](https://github.com/propeller-heads/tycho-indexer/commit/5edf7e8c6b9bf6538a8f205db24ad5d096861862))
* add entry point tables and types to PostgreSQL schema ([3e53c46](https://github.com/propeller-heads/tycho-indexer/commit/3e53c4682ae32f7a7cb8570b4c8c5aa86bc3c3f8))
* add entry point tracing functionality ([1d64d12](https://github.com/propeller-heads/tycho-indexer/commit/1d64d12d1a5c33c6dd5861e41f4b93ca76de5dca))
* add entrypoint and entrypoint params to TxWithChanges ([3237e0f](https://github.com/propeller-heads/tycho-indexer/commit/3237e0f06bf049156302b8f5b6908770a67679f0))
* add entrypoint tracking to component tracker ([87839a0](https://github.com/propeller-heads/tycho-indexer/commit/87839a081fe38c176ccbe7d15ce301b3095d1271))
* add get_traced_entry_points endpoint to RPCClient ([d4a3238](https://github.com/propeller-heads/tycho-indexer/commit/d4a3238765fbecba10c11ea16253293ce7de65d3))
* add get_valid_from to row versioning control ([003df54](https://github.com/propeller-heads/tycho-indexer/commit/003df54f6e1b093966f76bc67bc14857d40af363))
* add method to fetch account storage ([d1f2b4f](https://github.com/propeller-heads/tycho-indexer/commit/d1f2b4f6e887329150e3c69a97650e3a5c6507c8))
* add pagination to EntryPointGateway ([9df2e5a](https://github.com/propeller-heads/tycho-indexer/commit/9df2e5a5f7a99ee782bf9fa848e494e32785ffb2))
* add slots tracing to the RPC tracer ([21b98e5](https://github.com/propeller-heads/tycho-indexer/commit/21b98e5901085d1520477f29bad0e74cf5d08a1e))
* add trace results to BlockChanges and BlockAggregatedChanges ([5b4e56e](https://github.com/propeller-heads/tycho-indexer/commit/5b4e56e3c77a6af20d244f8f4b7db369948abf7d))
* add triggers for updating modification timestamps on entry point tables ([5d0d72b](https://github.com/propeller-heads/tycho-indexer/commit/5d0d72b0407eed06c1edf60607ce871a7eda73cb))
* Add Unknown RpcError type ([f0caeee](https://github.com/propeller-heads/tycho-indexer/commit/f0caeee31d53be0668834046e4efac49196306cb))
* add UpsertEntryPoints and UpsertTracedEntryPoints operations to WriteOp ([a71add2](https://github.com/propeller-heads/tycho-indexer/commit/a71add211a04c19c75dc4c73d9b79133cae8ede7))
* AddEntrypointRequestBody improvements ([405499c](https://github.com/propeller-heads/tycho-indexer/commit/405499c10c3b6f065b8f071979d1520f32e5d4db))
* address rebase changes ([3fd0d50](https://github.com/propeller-heads/tycho-indexer/commit/3fd0d503df43a1994c40a3d55b1b4507ca2f9bfb))
* Create DirectGateway and use in RPCHandler ([fc349ce](https://github.com/propeller-heads/tycho-indexer/commit/fc349ce4ef8ca61f7cc1e183660bd88f3ae865a8))
* create DynamicContractIndexerTrait for simpler generic handling ([df48540](https://github.com/propeller-heads/tycho-indexer/commit/df485403b7e374fc05360539642b45596530c8f3))
* DCI Release ([#595](https://github.com/propeller-heads/tycho-indexer/issues/595)) ([d33afb3](https://github.com/propeller-heads/tycho-indexer/commit/d33afb3eb28b20f0c7542883a7a6823da6913bc2))
* Do not error if tracing result not found + small fixes ([79d16e0](https://github.com/propeller-heads/tycho-indexer/commit/79d16e0b5d1def028f59e8ee465af520dbcd47f3))
* enhance EntryPointFilter to support component id filtering ([4694a18](https://github.com/propeller-heads/tycho-indexer/commit/4694a18fb7cdc9a60f1ff49c4fb455780a96a742))
* extend BlockAggregatedChanges and BlockChanhes dto to include DCI data ([cc6e8ed](https://github.com/propeller-heads/tycho-indexer/commit/cc6e8ed9f2140e4e2e724726481dc54fc3f717d2))
* extend TxWithChanges to include EntryPoints ([475e253](https://github.com/propeller-heads/tycho-indexer/commit/475e2538c3a2c0fa86761b05b2cdc45ed206a292))
* get rpc url from global args, get api key from env ([06debe1](https://github.com/propeller-heads/tycho-indexer/commit/06debe113e88a150bf46bfadbcfe377d852e9fdc))
* handle dci data on tycho-client synchronizer ([5196938](https://github.com/propeller-heads/tycho-indexer/commit/5196938f72d6ea1763d2d155894ea356d9804af2))
* implement entry-points functions on PostgresGateway ([1a374db](https://github.com/propeller-heads/tycho-indexer/commit/1a374db56bb42e5a786e9c5f61da743abf202d82))
* Manually paginate when getting traced entrypoint ([8dafb0d](https://github.com/propeller-heads/tycho-indexer/commit/8dafb0d0c4b038f396f7f99ab008fdbb803fff5b))
* merge traits and finish EVMBatchAccountExtractor ([69ef0f8](https://github.com/propeller-heads/tycho-indexer/commit/69ef0f84cca8b4f66c2ae2a6909e3e446a3acab5))
* move setting dci plugin to extractor config ([be06549](https://github.com/propeller-heads/tycho-indexer/commit/be06549d6fc106bc4a131656429b788fdba824e6))
* register add_entry_points endpoint ([6fdf540](https://github.com/propeller-heads/tycho-indexer/commit/6fdf540242f18a5c2dbcfe6a15859aabcac59e81))
* Return tracing results to user after adding entry points ([6a3153a](https://github.com/propeller-heads/tycho-indexer/commit/6a3153a8fae263b1e98c9113907f37e0023f9c9c))
* sketch DCI behavior ([efa87c7](https://github.com/propeller-heads/tycho-indexer/commit/efa87c74534d3a89f2e7c617a278ce88f0af7987))
* split inserting static and dynamic parts of a new contract ([76d8f71](https://github.com/propeller-heads/tycho-indexer/commit/76d8f71f29ee6af021295260283fe3bc6f6f901a))
* Take RPC_URL as input to ServicesBuilder ([b775185](https://github.com/propeller-heads/tycho-indexer/commit/b775185d88e6410d9ccca409d36a269103cad9df))
* Take tracer as input to RpcHandler ([28ed1b4](https://github.com/propeller-heads/tycho-indexer/commit/28ed1b45c279f735acd88efa8da7492b2d03be09))
* **tycho-common:** create a dedicated MergeError for merge issues ([169fe65](https://github.com/propeller-heads/tycho-indexer/commit/169fe65b7ece09fe1ab60cff7febe331afc4ef5b))
* Update DCI to use new parameters ([2ecd88c](https://github.com/propeller-heads/tycho-indexer/commit/2ecd88cb2c08d7b90bad73d808f6d36871673841))
* update tycho-substreams to 0.3.1 ([5336a53](https://github.com/propeller-heads/tycho-indexer/commit/5336a537a4b1e08417ce8514ed4d4fc1f85493ab))
* Use generic over EntryPointTracer for tracer ([3c62f1b](https://github.com/propeller-heads/tycho-indexer/commit/3c62f1b4e19c3eed1e08e5a61884aeee537dc7d6))
* **versioning:** drop versions older than what already exists in the db ([1c0c764](https://github.com/propeller-heads/tycho-indexer/commit/1c0c764a56149cfc656d314c0d2d3ba1a82be64a))


### Bug Fixes

* address a bug with `.returning` not returning on conflicts. ([db11bd2](https://github.com/propeller-heads/tycho-indexer/commit/db11bd24f2eb4add248260c9f136cf9fac0df5f2))
* correctly add default balances and code on account creations ([6e64424](https://github.com/propeller-heads/tycho-indexer/commit/6e6442462fb4e57528362d5595469025da28071b))
* correctly handle contract inserts ([9f35ee8](https://github.com/propeller-heads/tycho-indexer/commit/9f35ee8d94622f7b7455e8c5a376f9415e3c7f42))
* correctly handle many new entrypoints for a single transaction ([7ffdf5a](https://github.com/propeller-heads/tycho-indexer/commit/7ffdf5a8f10729f96e311eca669ec4f94fa5ef25))
* correctly pass entrypoint data when parsing Substreams message ([f36cfdf](https://github.com/propeller-heads/tycho-indexer/commit/f36cfdf7f337b1eb8bfc2f579cfe39ab16f66b03))
* correctly retrieve db ids when inserting tracing results. ([ae22943](https://github.com/propeller-heads/tycho-indexer/commit/ae2294312b0a7bbd824a1da1c4a8e2c82eabfecf))
* correctly retrives the rpc url from CLI args ([6731078](https://github.com/propeller-heads/tycho-indexer/commit/673107819203bf383f4eb2c89e0470ed216610b7))
* correctly serve entrypoint and tracing params in the PostgresGateway ([fbdab08](https://github.com/propeller-heads/tycho-indexer/commit/fbdab085de5868cfaf6376cf2d23175e4bea9f5b))
* correctly setup "rpc" DCI on startup ([7b31a19](https://github.com/propeller-heads/tycho-indexer/commit/7b31a19fe93c9ad997284b10cc846a1f6c2d2ada))
* correctly sort `txs_with_update` after DCI inserts ([98f6ace](https://github.com/propeller-heads/tycho-indexer/commit/98f6ace6abaade2585780f0bb98b6ad65596065e))
* do not update in insert contract gateway fn ([6cdcf8a](https://github.com/propeller-heads/tycho-indexer/commit/6cdcf8aca3dd2725ac8e1f8538cc209789251cb5))
* fix broken sql down migrations ([e5d41ab](https://github.com/propeller-heads/tycho-indexer/commit/e5d41ab1248b72ba6fc60159f1c0307971fcdb45))
* get_traced_entrypoints pagination + caching ([f6e1742](https://github.com/propeller-heads/tycho-indexer/commit/f6e17429620c30b65654d79313e7f54452ef636e))
* handle outdated deletes ([730e55b](https://github.com/propeller-heads/tycho-indexer/commit/730e55ba935a4cdf5b489d28686bf5cb7b142152))
* handle skipping multiple updates for same entity within a block ([e9ef60b](https://github.com/propeller-heads/tycho-indexer/commit/e9ef60b3ed22cf4d8417acb74958a7c7dea12760))
* Keep OpenAPI clean with proper dto macros ([a69ddcc](https://github.com/propeller-heads/tycho-indexer/commit/a69ddccb7c59c0f2c0d779d728ddcb40a77770ee))
* Make clippy happy ([67d725c](https://github.com/propeller-heads/tycho-indexer/commit/67d725c5ee3b99b4bbb695cce7efe3f1412e3536))
* Properly match params to result in get_traced_entry_points_inner ([ddd6cf5](https://github.com/propeller-heads/tycho-indexer/commit/ddd6cf51f537de567275984ad4abe6c50f741453))
* Remove add_entry_points from swagger UI ([29b9be1](https://github.com/propeller-heads/tycho-indexer/commit/29b9be121ded8b16f04f6cf4fd4c2753b0d0f9e9))
* Remove unnecessary clones ([8ad2c6c](https://github.com/propeller-heads/tycho-indexer/commit/8ad2c6cb7ae160c25fa7bebeb24c08401fa9624a))
* Remove unnecessary to_string (equivalent of cloning) ([20ac1f4](https://github.com/propeller-heads/tycho-indexer/commit/20ac1f4196d0c1a35c72984a606a523793e60693))
* Uncomment test ignore ([8cd9214](https://github.com/propeller-heads/tycho-indexer/commit/8cd92146a5781006354ae9cdb25a02dd3541604e))
* use latest db versions for outdated data check ([feecf18](https://github.com/propeller-heads/tycho-indexer/commit/feecf1809e10378d7f5b4aab758737316a64be6d))
* wrap the DCI plugin in an Arc Mutex ([09f0d51](https://github.com/propeller-heads/tycho-indexer/commit/09f0d51b34fb31770021f8c15cd384c8ca105018))

## [0.70.9](https://github.com/propeller-heads/tycho-indexer/compare/0.70.8...0.70.9) (2025-06-05)


### Bug Fixes

* convert ids to lowercase for the id base ComponentFilter ([0103c60](https://github.com/propeller-heads/tycho-indexer/commit/0103c60c95c8f61375d0d61c6f094e4a3058bf83))
* **tycho-client:** update cli docs, validation and address handling ([45870b1](https://github.com/propeller-heads/tycho-indexer/commit/45870b1bb7d4c9ec51336fe53571f9bd11d6bb3c))
* **tycho-client:** update cli docs, validation and address handling ([#591](https://github.com/propeller-heads/tycho-indexer/issues/591)) ([3272d34](https://github.com/propeller-heads/tycho-indexer/commit/3272d34cf420c2e0ce6d183ff0f1f07035b1eeea))

## [0.70.8](https://github.com/propeller-heads/tycho-indexer/compare/0.70.7...0.70.8) (2025-06-03)

## [0.70.7](https://github.com/propeller-heads/tycho-indexer/compare/0.70.6...0.70.7) (2025-05-21)


### Bug Fixes

* order protocol states query by protocol component ([a45d4a0](https://github.com/propeller-heads/tycho-indexer/commit/a45d4a01828c0346cf99ed1de136f4ec846064fd))
* order protocol states query by protocol component ([#582](https://github.com/propeller-heads/tycho-indexer/issues/582)) ([4597925](https://github.com/propeller-heads/tycho-indexer/commit/4597925eda1292bf1f05f06ad51c64a409e1c7d4))

## [0.70.6](https://github.com/propeller-heads/tycho-indexer/compare/0.70.5...0.70.6) (2025-05-19)

## [0.70.5](https://github.com/propeller-heads/tycho-indexer/compare/0.70.4...0.70.5) (2025-05-16)


### Bug Fixes

* **tycho-client:** fix block position bug for delayed extractors on start up ([#570](https://github.com/propeller-heads/tycho-indexer/issues/570)) ([46aa1af](https://github.com/propeller-heads/tycho-indexer/commit/46aa1afe47ff5cfffc984215a6ecc4f78ee92e7b))
* **tycho-client:** mark blocks older than the oldest in BlockHistory as delayed ([ebb55a9](https://github.com/propeller-heads/tycho-indexer/commit/ebb55a9844f8d7750f060f160bfd617224f33dc4))
* **tycho-client:** skip detached blocks on BlockHistory creation ([116e75a](https://github.com/propeller-heads/tycho-indexer/commit/116e75a77f461e72194f5a513f39f474898ea5c1))

## [0.70.4](https://github.com/propeller-heads/tycho-indexer/compare/0.70.3...0.70.4) (2025-05-15)


### Bug Fixes

* **postgres:** add on_conflict_do_nothing to contract balance and code upserts ([2ef58a8](https://github.com/propeller-heads/tycho-indexer/commit/2ef58a8c866a2ff41bbabf0538cb50ed18e71680))
* **postgres:** add on_conflict_do_nothing to contract balance and code upserts ([#574](https://github.com/propeller-heads/tycho-indexer/issues/574)) ([eb8956b](https://github.com/propeller-heads/tycho-indexer/commit/eb8956bcbbf3b9002fa86e3d74fe3bfae3e34718))

## [0.70.3](https://github.com/propeller-heads/tycho-indexer/compare/0.70.2...0.70.3) (2025-05-14)


### Bug Fixes

* update dockerfile rust version to 1.82 ([#573](https://github.com/propeller-heads/tycho-indexer/issues/573)) ([5b4a015](https://github.com/propeller-heads/tycho-indexer/commit/5b4a01506835545ab082a3694b53a404f16be6b8))

## [0.70.2](https://github.com/propeller-heads/tycho-indexer/compare/0.70.1...0.70.2) (2025-05-14)


### Bug Fixes

* log error code for substream error metrics ([b7d8f78](https://github.com/propeller-heads/tycho-indexer/commit/b7d8f78aaac3f597a4599fa845f31fa6bd07ef61))

## [0.70.1](https://github.com/propeller-heads/tycho-indexer/compare/0.70.0...0.70.1) (2025-05-14)


### Bug Fixes

* include message text in websocket error logging ([b2c78a9](https://github.com/propeller-heads/tycho-indexer/commit/b2c78a993390fa5bc5f2d6c511d48885e5f5e22b))
* include message text in websocket error logging ([0d2e6e7](https://github.com/propeller-heads/tycho-indexer/commit/0d2e6e730634e90016716f6cfceee013093c6683))
* **tycho-client:** include message text in websocket error logging ([#571](https://github.com/propeller-heads/tycho-indexer/issues/571)) ([cce6373](https://github.com/propeller-heads/tycho-indexer/commit/cce6373a3fe39376df0cfa4f166adc7d7f1c6bb7))

## [0.70.0](https://github.com/propeller-heads/tycho-indexer/compare/0.69.0...0.70.0) (2025-05-08)


### Features

* **tycho-client:** propogate block history errors on synchronizer ([de9c792](https://github.com/propeller-heads/tycho-indexer/commit/de9c79205b35312faf736165c9b8e4d56b3b0cd6))
* **tycho-client:** remove panics from block history handler ([81bf5af](https://github.com/propeller-heads/tycho-indexer/commit/81bf5af524eddbe16503b29026ee41aa55d42b4e))
* **tycho-client:** remove panics from BlockSynchronizer ([d6b4ae5](https://github.com/propeller-heads/tycho-indexer/commit/d6b4ae559d72cf56e3d3f9cb7034e144fdebbad9))
* **tycho-client:** remove panics from CLI ([d7a2aae](https://github.com/propeller-heads/tycho-indexer/commit/d7a2aae23f2b2943bb5d83e6d1f05d975c206a64))
* **tycho-client:** Remove panics from client ([#561](https://github.com/propeller-heads/tycho-indexer/issues/561)) ([d03c4a6](https://github.com/propeller-heads/tycho-indexer/commit/d03c4a6e2f2e9dbc8b6b69094e20e5c3ebe6888f))
* **tycho-client:** remove panics from detlas websocket client ([cc38d6c](https://github.com/propeller-heads/tycho-indexer/commit/cc38d6c6008f86edbf8938d920c9042a958b6d12))
* **tycho-client:** remove panics from detlas websocket client ([727429e](https://github.com/propeller-heads/tycho-indexer/commit/727429e36ce5fb373206c96b89a9b5b3f4cedef9))
* **tycho-client:** remove panics from RPCClient ([3df8ce7](https://github.com/propeller-heads/tycho-indexer/commit/3df8ce72723782a288efc841221021ff6981e00c))
* **tycho-client:** remove panics from state synchroniser ([5ae277b](https://github.com/propeller-heads/tycho-indexer/commit/5ae277b110ff795471dd49f49490b3eee71dd8e2))
* **tycho-client:** remove panics from TychoStreamBuilder ([ca5c82b](https://github.com/propeller-heads/tycho-indexer/commit/ca5c82bdced7bb87c293fa9d8e282f0f29d8b672))


### Bug Fixes

* box large errors ([771a36a](https://github.com/propeller-heads/tycho-indexer/commit/771a36a2111542dea7dbb72ee88dfde6ff5c3f2e))
* break synchronisation retry loop if ws client disconnected ([22b77b3](https://github.com/propeller-heads/tycho-indexer/commit/22b77b3eec28de7403fe98919addf3204c181d6c))
* combine SetUpError and InitializationError on the stream builder ([4edf71b](https://github.com/propeller-heads/tycho-indexer/commit/4edf71b66a6786ac1926dd93ba04a00fe9fc46c8))
* **tycho-client:** convert large SendError to an error string ([4c1f3e7](https://github.com/propeller-heads/tycho-indexer/commit/4c1f3e7125f953f4730c658c1434910b31a04065))

## [0.69.0](https://github.com/propeller-heads/tycho-indexer/compare/0.68.2...0.69.0) (2025-05-08)


### Features

* add component tvl ([#547](https://github.com/propeller-heads/tycho-indexer/issues/547)) ([86663e6](https://github.com/propeller-heads/tycho-indexer/commit/86663e6a9386cb38ecb56c419bde29171b9cb3f3))
* add system and pagination params ([356ab1a](https://github.com/propeller-heads/tycho-indexer/commit/356ab1ad9eac285a08d5652e5ecd8b9cbf05824d))
* component tvl rpc ([49b146c](https://github.com/propeller-heads/tycho-indexer/commit/49b146c492f9ea72243a33da62f9fa79c52adcf0))


### Bug Fixes

* lint ([2c74dfb](https://github.com/propeller-heads/tycho-indexer/commit/2c74dfb24d2bbeae4799e43bcd71219bcc7ee895))

## [0.68.2](https://github.com/propeller-heads/tycho-indexer/compare/0.68.1...0.68.2) (2025-05-02)


### Bug Fixes

* correctly exit extraction loop on stop signal ([1ad56d8](https://github.com/propeller-heads/tycho-indexer/commit/1ad56d8705a7da53e77c9b7678b1d617c0ea8df1))
* correctly exit extraction loop on stop signal ([#569](https://github.com/propeller-heads/tycho-indexer/issues/569)) ([d0fd91c](https://github.com/propeller-heads/tycho-indexer/commit/d0fd91c151df45cb395492a61034fa57b928fcc8))

## [0.68.1](https://github.com/propeller-heads/tycho-indexer/compare/0.68.0...0.68.1) (2025-05-02)


### Bug Fixes

* add backoff for retries on connections error with Substreams ([e9379b2](https://github.com/propeller-heads/tycho-indexer/commit/e9379b229c6866895709bd1b6ee32a50624e5f03))
* add backoff for retries on connections error with Substreams ([#562](https://github.com/propeller-heads/tycho-indexer/issues/562)) ([177857c](https://github.com/propeller-heads/tycho-indexer/commit/177857c017512356e032eb20b9fe28752cb5aaba))

## [0.68.0](https://github.com/propeller-heads/tycho-indexer/compare/0.67.3...0.68.0) (2025-05-02)


### Features

* enhance shutdown handling with SIGTERM support ([c7c5b0d](https://github.com/propeller-heads/tycho-indexer/commit/c7c5b0dd7e57bd6c12269cf24a7b8f2760ca54ff))
* enhance shutdown handling with SIGTERM support ([#568](https://github.com/propeller-heads/tycho-indexer/issues/568)) ([05cbea3](https://github.com/propeller-heads/tycho-indexer/commit/05cbea3fb0cbae507d0a36926794cd8cb7bcb4ab))

## [0.67.3](https://github.com/propeller-heads/tycho-indexer/compare/0.67.2...0.67.3) (2025-05-01)

## [0.67.2](https://github.com/propeller-heads/tycho-indexer/compare/0.67.1...0.67.2) (2025-05-01)

## [0.67.1](https://github.com/propeller-heads/tycho-indexer/compare/0.67.0...0.67.1) (2025-05-01)

## [0.67.0](https://github.com/propeller-heads/tycho-indexer/compare/0.66.5...0.67.0) (2025-04-30)


### Features

* update CORS to allow all subdomains of `propellerheads.xyz` ([d709443](https://github.com/propeller-heads/tycho-indexer/commit/d70944343d9b9ca3a6f7f9491493bf953807262e))
* update CORS to allow all subdomains of `propellerheads.xyz` ([#563](https://github.com/propeller-heads/tycho-indexer/issues/563)) ([a451301](https://github.com/propeller-heads/tycho-indexer/commit/a4513010bf3c95ef4f346f84805473f95cdc8bf0))

## [0.66.5](https://github.com/propeller-heads/tycho-indexer/compare/0.66.4...0.66.5) (2025-04-29)


### Bug Fixes

* remove error logging on RPCClient ([9934abd](https://github.com/propeller-heads/tycho-indexer/commit/9934abd76eecc93f0bdb84509121a5722e4c7ef5))
* remove error logging on RPCClient ([#560](https://github.com/propeller-heads/tycho-indexer/issues/560)) ([41f0704](https://github.com/propeller-heads/tycho-indexer/commit/41f0704af3002ed7df5ccee2fa818bf83ec1b7fc))

## [0.66.4](https://github.com/propeller-heads/tycho-indexer/compare/0.66.3...0.66.4) (2025-04-18)


### Bug Fixes

* **tycho-client:** relax default timeout values ([eba302f](https://github.com/propeller-heads/tycho-indexer/commit/eba302f11606798acc589f0ae3a57407a7b16da3))
* **tycho-client:** relax default timeout values ([#555](https://github.com/propeller-heads/tycho-indexer/issues/555)) ([3852e6a](https://github.com/propeller-heads/tycho-indexer/commit/3852e6a5db5932083feb37d9a0817e54ad8d3c49))

## [0.66.3](https://github.com/propeller-heads/tycho-indexer/compare/0.66.2...0.66.3) (2025-04-18)


### Bug Fixes

* cleanly close ws connections on timeouts ([319d988](https://github.com/propeller-heads/tycho-indexer/commit/319d988d3d095326f191907ab5e2a28e7fe7ca77))
* cleanly close ws connections on timeouts ([#556](https://github.com/propeller-heads/tycho-indexer/issues/556)) ([262d070](https://github.com/propeller-heads/tycho-indexer/commit/262d070b827730a594fef833484667d8825bdd78))

## [0.66.2](https://github.com/propeller-heads/tycho-indexer/compare/0.66.1...0.66.2) (2025-04-11)


### Bug Fixes

* Make Snapshot attributes pub ([#552](https://github.com/propeller-heads/tycho-indexer/issues/552)) ([55c668e](https://github.com/propeller-heads/tycho-indexer/commit/55c668e29a453809d820e362435093485d77d019))

## [0.66.1](https://github.com/propeller-heads/tycho-indexer/compare/0.66.0...0.66.1) (2025-04-10)

## [0.66.0](https://github.com/propeller-heads/tycho-indexer/compare/0.65.0...0.66.0) (2025-04-10)


### Features

* Implement retry logic for deadlock detection in database transactions ([5d63e49](https://github.com/propeller-heads/tycho-indexer/commit/5d63e497a0b8279a57f3809c84a1df91dd9cc261))
* Implement retry logic for deadlock detection in database transactions ([#549](https://github.com/propeller-heads/tycho-indexer/issues/549)) ([5a4b28e](https://github.com/propeller-heads/tycho-indexer/commit/5a4b28e49533ad3a99b2e7a08e905c18f9990a75))

## [0.65.0](https://github.com/propeller-heads/tycho-indexer/compare/0.64.2...0.65.0) (2025-04-02)


### Features

* Add link to Tycho.build telegram ([2ef1fe6](https://github.com/propeller-heads/tycho-indexer/commit/2ef1fe6687eb005b7f0b305abcb886136242a415))

## [0.64.2](https://github.com/propeller-heads/tycho-indexer/compare/0.64.1...0.64.2) (2025-04-01)


### Bug Fixes

* Set default value for account_balances in BlockChanges model ([4f69191](https://github.com/propeller-heads/tycho-indexer/commit/4f69191e2507a1e397ba930ce9719fec8bcd9366))
* Set default value for account_balances in BlockChanges model ([#544](https://github.com/propeller-heads/tycho-indexer/issues/544)) ([8ced9f9](https://github.com/propeller-heads/tycho-indexer/commit/8ced9f92a4c2d36feab51677f4fffea448dd5b60))

## [0.64.1](https://github.com/propeller-heads/tycho-indexer/compare/0.64.0...0.64.1) (2025-03-31)


### Bug Fixes

* include workspace cargo toml in release config ([2cecbd8](https://github.com/propeller-heads/tycho-indexer/commit/2cecbd8f050544b35e8bb82171dde7fa75781dd0))
* include workspace cargo toml in release config ([#543](https://github.com/propeller-heads/tycho-indexer/issues/543)) ([071af8a](https://github.com/propeller-heads/tycho-indexer/commit/071af8a0e40e51aa089d9b9d73da08d9ea736e6d))

## [0.64.0](https://github.com/propeller-heads/tycho-indexer/compare/0.63.1...0.64.0) (2025-03-31)


### Features

* add max_missed_blocks as staleness threshold ([d9c6846](https://github.com/propeller-heads/tycho-indexer/commit/d9c6846cb407a4a10928b3df6a1a7779530272ac))
* handle delayed exchanges on tycho-client ([d106b82](https://github.com/propeller-heads/tycho-indexer/commit/d106b82056a1db551031c3bf1911069fa19dd371))
* Handle delayed exchanges on tycho-client ([#539](https://github.com/propeller-heads/tycho-indexer/issues/539)) ([a5da6fd](https://github.com/propeller-heads/tycho-indexer/commit/a5da6fd1ebf7212430cff2b3d28d1efe48f211f6))
* only wait for one deltas message on client start up ([4fba42f](https://github.com/propeller-heads/tycho-indexer/commit/4fba42f168fac3a6d6c94a235a6aac9e39ffbdd5))
* use block_time + timeout as wait time for first deltas ([51e2313](https://github.com/propeller-heads/tycho-indexer/commit/51e23130d96f7b69fbe02eb439482fd7042bc693))


### Bug Fixes

* **tycho-client:** allow setting TYCHO_URL as an env var ([54fa5c4](https://github.com/propeller-heads/tycho-indexer/commit/54fa5c4a53f58e3562d1225f523c46831e8ae4ce))
* wait block time + timeout for first message ([751aae7](https://github.com/propeller-heads/tycho-indexer/commit/751aae7e62881412ca58840dd97085147b5a47df))

## [0.63.1](https://github.com/propeller-heads/tycho-indexer/compare/0.63.0...0.63.1) (2025-03-26)


### Bug Fixes

* add missing version to checkout action ([c025616](https://github.com/propeller-heads/tycho-indexer/commit/c025616b3c19106113c195bc95cb04c05848153f))
* add missing version to checkout action ([#537](https://github.com/propeller-heads/tycho-indexer/issues/537)) ([a803970](https://github.com/propeller-heads/tycho-indexer/commit/a803970ee129ef8d9ed8317ca0d2ecb5fe8c52c6))

## [0.63.0](https://github.com/propeller-heads/tycho-indexer/compare/0.62.0...0.63.0) (2025-03-26)


### Features

* Rename tycho-core to tycho-common. ([f5ed755](https://github.com/propeller-heads/tycho-indexer/commit/f5ed7559adf4fc64b4ac39ea0afdb9845e23bb1e))
* Rename tycho-core to tycho-common. ([#536](https://github.com/propeller-heads/tycho-indexer/issues/536)) ([476f3f3](https://github.com/propeller-heads/tycho-indexer/commit/476f3f34f58039877fa47863fd37e541ae4bb25f))

## [0.62.0](https://github.com/propeller-heads/tycho-indexer/compare/0.61.1...0.62.0) (2025-03-25)


### Features

* add Unichain support ([2422692](https://github.com/propeller-heads/tycho-indexer/commit/242269286d6020c1bd1489606783f2bf2e9ed6fd))
* add Unichain support ([#534](https://github.com/propeller-heads/tycho-indexer/issues/534)) ([e0c1b41](https://github.com/propeller-heads/tycho-indexer/commit/e0c1b41209b95b7408ef7a795ab99baea7b922d2))

## [0.61.1](https://github.com/propeller-heads/tycho-indexer/compare/0.61.0...0.61.1) (2025-03-11)


### Bug Fixes

* Add default to change attr to deprecate ([38efe73](https://github.com/propeller-heads/tycho-indexer/commit/38efe738f1620409f521c8ee5757c1b0f0598032))
* Revert skipping serialization on change field ([12e4482](https://github.com/propeller-heads/tycho-indexer/commit/12e4482f0b7e148223dbf550b3dd2223291d51fe))
* Revert skipping serialization on change field ([#529](https://github.com/propeller-heads/tycho-indexer/issues/529)) ([d53c7cf](https://github.com/propeller-heads/tycho-indexer/commit/d53c7cfe2607e30eaba517a49f0f3a444df7445c))

## [0.61.0](https://github.com/propeller-heads/tycho-indexer/compare/0.60.0...0.61.0) (2025-03-11)


### Features

* Add propellerheads docs domain to CORS allowance list ([7d87115](https://github.com/propeller-heads/tycho-indexer/commit/7d8711574bdf15c5e20fe9de1705a3dfd5bb85ab))
* add security requirement to paths ([55eec82](https://github.com/propeller-heads/tycho-indexer/commit/55eec823f39dc01d83407c63fad78a246e9da582))
* Allow CORS from Gitbook UI ([83c68b9](https://github.com/propeller-heads/tycho-indexer/commit/83c68b99a0fcd0ae26db230b2341e59d8fedbb65))
* Allow CORS from Gitbook UI ([#526](https://github.com/propeller-heads/tycho-indexer/issues/526)) ([98f8b41](https://github.com/propeller-heads/tycho-indexer/commit/98f8b4108e137b87bf5c98f00efc39d2c49021a8))
* Improve autogenerated openapi schema  ([#524](https://github.com/propeller-heads/tycho-indexer/issues/524)) ([53a4020](https://github.com/propeller-heads/tycho-indexer/commit/53a40202e9be65545e533a52592b86b57246de57))
* skip serializing change field on PC ([0317c8d](https://github.com/propeller-heads/tycho-indexer/commit/0317c8dc8a268ed78daa9d98fbfc74897d6cc5e9))

## [0.60.0](https://github.com/propeller-heads/tycho-indexer/compare/0.59.5...0.60.0) (2025-03-06)


### Features

* update codebase with latest substream message changes ([c5dca5e](https://github.com/propeller-heads/tycho-indexer/commit/c5dca5e5aac38b65f3fbd7e6472da28450263db9))
* update substreams proto files ([b72cb77](https://github.com/propeller-heads/tycho-indexer/commit/b72cb776e6ec88aaffd954c4374be39ee4c8b99c))
* update substreams proto messages ([#525](https://github.com/propeller-heads/tycho-indexer/issues/525)) ([3175a47](https://github.com/propeller-heads/tycho-indexer/commit/3175a470c552ca19495e1f7a532f07914b0a791b))

## [0.59.5](https://github.com/propeller-heads/tycho-indexer/compare/0.59.4...0.59.5) (2025-03-06)

## [0.59.4](https://github.com/propeller-heads/tycho-indexer/compare/0.59.3...0.59.4) (2025-03-06)

## [0.59.3](https://github.com/propeller-heads/tycho-indexer/compare/0.59.2...0.59.3) (2025-03-04)


### Bug Fixes

* update dockerfile ([114ad12](https://github.com/propeller-heads/tycho-indexer/commit/114ad127b494ec117f47dc30a21df141f9953739))
* update dockerfile ([dd4ffdc](https://github.com/propeller-heads/tycho-indexer/commit/dd4ffdc5e5a9bf177ce3504ab09f2285b9ad750f))
* update dockerfile ([be3c408](https://github.com/propeller-heads/tycho-indexer/commit/be3c40842e83a44e93244fd8c498e0da6e68b0df))
* update dockerfile ([#522](https://github.com/propeller-heads/tycho-indexer/issues/522)) ([488ac2e](https://github.com/propeller-heads/tycho-indexer/commit/488ac2edf3298085577b9b0eb506b4db37d27657))

## [0.59.2](https://github.com/propeller-heads/tycho-indexer/compare/0.59.1...0.59.2) (2025-03-04)

## [0.59.1](https://github.com/propeller-heads/tycho-indexer/compare/0.59.0...0.59.1) (2025-03-04)

## [0.59.0](https://github.com/propeller-heads/tycho-indexer/compare/0.58.3...0.59.0) (2025-02-28)


### Features

* fix conflicting timestamps, update latest block on reverts ([0bbd30e](https://github.com/propeller-heads/tycho-indexer/commit/0bbd30e64c7a5e74e173d5e3195449353c76efbd))
* get block by hash instead of number ([b38d97d](https://github.com/propeller-heads/tycho-indexer/commit/b38d97d1288bf528df6a9f21f68b8390479612e6))
* Handle blocks with same ts ([#494](https://github.com/propeller-heads/tycho-indexer/issues/494)) ([314de48](https://github.com/propeller-heads/tycho-indexer/commit/314de48e270ad8a749a72d3b254fc634a8994cc6))
* remove #[allow(dead_code)] ([f88c606](https://github.com/propeller-heads/tycho-indexer/commit/f88c606fe9040b316164727870645abf415c8632))
* return block_id together with cursor ([160757a](https://github.com/propeller-heads/tycho-indexer/commit/160757a1b662248dc0894074f342cb4e5250383b))
* simplify logic, remove previous block ts overwrite for Arbitrum ([e32cd2b](https://github.com/propeller-heads/tycho-indexer/commit/e32cd2bbb3778e10b5f25f7c8867b944ce63b8be))

## [0.58.3](https://github.com/propeller-heads/tycho-indexer/compare/0.58.2...0.58.3) (2025-02-28)


### Bug Fixes

* Fix token_balances typing on ResponseAccount ([e9d854b](https://github.com/propeller-heads/tycho-indexer/commit/e9d854bd9dedced448ffe6067a55738bf21cc689))
* Fix token_balances typing on ResponseAccount ([#514](https://github.com/propeller-heads/tycho-indexer/issues/514)) ([924e3d0](https://github.com/propeller-heads/tycho-indexer/commit/924e3d037d3def9dfb4804548de49e4095a547d7))

## [0.58.2](https://github.com/propeller-heads/tycho-indexer/compare/0.58.1...0.58.2) (2025-02-27)


### Bug Fixes

* propagate more meaningful RPC errors on the client ([#515](https://github.com/propeller-heads/tycho-indexer/issues/515)) ([6261432](https://github.com/propeller-heads/tycho-indexer/commit/6261432585ae1f2d4f8a99b6cfd629e4a9f1285f))
* propogate more meaningful RPC errors on the client ([bf92d73](https://github.com/propeller-heads/tycho-indexer/commit/bf92d73ae4a0535619b4d8d42f78c6c981403c34))
* return error with body on failed response parsing ([08b74cc](https://github.com/propeller-heads/tycho-indexer/commit/08b74cc0178dc0d69a3e461c271c401e3d23ee1e))

## [0.58.1](https://github.com/propeller-heads/tycho-indexer/compare/0.58.0...0.58.1) (2025-02-26)


### Bug Fixes

* index tokens table on quality for quicker quality based lookups ([7f38460](https://github.com/propeller-heads/tycho-indexer/commit/7f38460f1189deee46c934ec7ad535d93218fdec))

## [0.58.0](https://github.com/propeller-heads/tycho-indexer/compare/0.57.2...0.58.0) (2025-02-26)


### Features

* update PG gateway get_tokens quality filter to be ranged ([9648dd6](https://github.com/propeller-heads/tycho-indexer/commit/9648dd6b4b5d7021d8cc0057b644bbf3e5a656f2))
* update postgres gateway get_tokens quality filter to be ranged ([#516](https://github.com/propeller-heads/tycho-indexer/issues/516)) ([72fac95](https://github.com/propeller-heads/tycho-indexer/commit/72fac95de65110625d5fba154e675240866274f7))

## [0.57.2](https://github.com/propeller-heads/tycho-indexer/compare/0.57.1...0.57.2) (2025-02-14)

## [0.57.1](https://github.com/propeller-heads/tycho-indexer/compare/0.57.0...0.57.1) (2025-02-14)


### Bug Fixes

* add arbitrum to the native token migration ([657aa53](https://github.com/propeller-heads/tycho-indexer/commit/657aa53110416f5c54c8fc0ef6bba3293dcacf12))
* add arbitrum to the native token migration ([#512](https://github.com/propeller-heads/tycho-indexer/issues/512)) ([4a76b38](https://github.com/propeller-heads/tycho-indexer/commit/4a76b3802b1b1c9082f6bfc162d585c8173a2d6e))

## [0.57.0](https://github.com/propeller-heads/tycho-indexer/compare/0.56.5...0.57.0) (2025-02-14)


### Features

* add account balances to client-py ([e37f1c6](https://github.com/propeller-heads/tycho-indexer/commit/e37f1c6d96599aaa3e86e91643f4aebb226db575))
* add account balances to ResponseAccount ([145f270](https://github.com/propeller-heads/tycho-indexer/commit/145f2709aa4f6f27e30cc513553fa80f68c206f4))
* add account_balances to BlockChanges dto struct ([7cc3e3c](https://github.com/propeller-heads/tycho-indexer/commit/7cc3e3cd66d3d5a5a046e84d373a38e653185c26))
* add add_account_balances postgres gateway fn ([a38c0ae](https://github.com/propeller-heads/tycho-indexer/commit/a38c0aec5353992aca3b30c50066c0e9fb8351b9))
* add get_account_balances gateway fn ([83e87ef](https://github.com/propeller-heads/tycho-indexer/commit/83e87eff5bda2a373c64f123a25f5f92d0f917c9))
* add migration for token_id in account_balance table ([d3acab0](https://github.com/propeller-heads/tycho-indexer/commit/d3acab0c53ead8a902e43eb4db5d3055b602046c))
* add migration for token_id in account_balance table ([#495](https://github.com/propeller-heads/tycho-indexer/issues/495)) ([fa7e424](https://github.com/propeller-heads/tycho-indexer/commit/fa7e42442bed5cf7b840736fd042008f065317c1))
* also ensure native token when ensuring chain on start-up ([4cfd6c2](https://github.com/propeller-heads/tycho-indexer/commit/4cfd6c2387ad99ee5b40dd0a630e47b9c62ef72e))
* fetch account balances on get_contracts ([9ded485](https://github.com/propeller-heads/tycho-indexer/commit/9ded485ad33f5336f7f35f5a24a2ceceebc0d04f))
* handle account balance changes on reverts ([4cf80bb](https://github.com/propeller-heads/tycho-indexer/commit/4cf80bb4fe56cb8010935398067d2d3da0fb11f7))
* implement chain -> native token DB id cache ([b35fe77](https://github.com/propeller-heads/tycho-indexer/commit/b35fe77049697215ed3b530474c673aba9f53a52))
* implement hardcoded chain -> native token map ([531348c](https://github.com/propeller-heads/tycho-indexer/commit/531348c524ad5c265a5dd185c3082a027efa75e0))
* update existing postgres gateway methods with AccountBalance ([f67fb68](https://github.com/propeller-heads/tycho-indexer/commit/f67fb68fab649dea0ceb260e85c0b5b2568fb54a))
* Update Tycho Python client Account DTO ([#506](https://github.com/propeller-heads/tycho-indexer/issues/506)) ([a48bb82](https://github.com/propeller-heads/tycho-indexer/commit/a48bb822b5b2a54d71100ab309012a88633097e0))


### Bug Fixes

* do not error if ensure chains finds existing chain ([3874ac0](https://github.com/propeller-heads/tycho-indexer/commit/3874ac0528c65ec1437471bcd0b1785cb0fa97d4))
* filter balances by native token on account balance delta retrieval ([2d4655b](https://github.com/propeller-heads/tycho-indexer/commit/2d4655b3f4ff3b5b6561a639a9768f0cc730a832))
* only insert ETH native token if DB has 1 chain ([8a38bca](https://github.com/propeller-heads/tycho-indexer/commit/8a38bcabc85ed9b777017980b7adc919aa00f9f3))
* re-add mistakenly removed dead code clippy skip ([0c2de2b](https://github.com/propeller-heads/tycho-indexer/commit/0c2de2b92dc2cae3e35ae82641abf39eb54518e8))
* remove balance_float field ([2bb50f4](https://github.com/propeller-heads/tycho-indexer/commit/2bb50f4788b2227cad43c0e0df7f706e81fa40fc))
* set native token gas correctly ([58f1832](https://github.com/propeller-heads/tycho-indexer/commit/58f1832c584042f25944212b07ce8114ca8686e2))
* set native token gas value and improve cache name ([d3c3033](https://github.com/propeller-heads/tycho-indexer/commit/d3c303334f8496ac2239c75b44d2a9311af64302))
* set Starknet native token to ETH ([3f7ec77](https://github.com/propeller-heads/tycho-indexer/commit/3f7ec7733c9604924094d507558513ff5a79dac7))
* update accout balance table constraints ([7278897](https://github.com/propeller-heads/tycho-indexer/commit/727889779358bae778ee9f8863448439642f7c9f))
* update get_contract to filter balances by native token ([03dc2e0](https://github.com/propeller-heads/tycho-indexer/commit/03dc2e0fa616dc512dda14c3bb422a3f8f91d077))

## [0.56.5](https://github.com/propeller-heads/tycho-indexer/compare/0.56.4...0.56.5) (2025-02-12)


### Bug Fixes

* **rpc:** correctly apply TVL filtering on `/protocol_component` requests ([dd4dc20](https://github.com/propeller-heads/tycho-indexer/commit/dd4dc203ededcbe9c6de1eb73b1f99884966f3b2))
* **rpc:** correctly apply TVL filtering on `/protocol_component` requests ([#511](https://github.com/propeller-heads/tycho-indexer/issues/511)) ([588e368](https://github.com/propeller-heads/tycho-indexer/commit/588e36806046b1a779c791d6d9959b4fc76153a2))

## [0.56.4](https://github.com/propeller-heads/tycho-indexer/compare/0.56.3...0.56.4) (2025-02-11)


### Bug Fixes

* default RPC client and server to use HTTP/2 ([#508](https://github.com/propeller-heads/tycho-indexer/issues/508)) ([f611383](https://github.com/propeller-heads/tycho-indexer/commit/f6113838c889e5fd76feeaa85b3e41fc9a5bebe6))
* disable connection pooling on tycho-client rpc ([c6bb715](https://github.com/propeller-heads/tycho-indexer/commit/c6bb715d24f4122801f71d86791483ec41a07d8c))
* finetune connection timeouts on rpc ([b06ec9b](https://github.com/propeller-heads/tycho-indexer/commit/b06ec9b9a107892acb76bbe012abd510b6e495e4))
* set both client and server to use HTTP/2 ([1516abe](https://github.com/propeller-heads/tycho-indexer/commit/1516abea713ab747835941e7a95726e54d38dd29))

## [0.56.3](https://github.com/propeller-heads/tycho-indexer/compare/0.56.2...0.56.3) (2025-02-10)


### Bug Fixes

* increase Base block time default ([9bcb718](https://github.com/propeller-heads/tycho-indexer/commit/9bcb7188f281c39c36b20af860666605d7d3b82f))
* increase Base blocktime default ([#510](https://github.com/propeller-heads/tycho-indexer/issues/510)) ([82702cd](https://github.com/propeller-heads/tycho-indexer/commit/82702cdeee20c53e04e0c9e6e720909a4155cd00))

## [0.56.2](https://github.com/propeller-heads/tycho-indexer/compare/0.56.1...0.56.2) (2025-02-07)

## [0.56.1](https://github.com/propeller-heads/tycho-indexer/compare/0.56.0...0.56.1) (2025-02-06)


### Bug Fixes

* improve efficiency of activity filter on tokens query ([5649e46](https://github.com/propeller-heads/tycho-indexer/commit/5649e4659aed1a9f23e64a8d2812b72b412dc03e))
* improve efficiency of activity filter on tokens query ([#504](https://github.com/propeller-heads/tycho-indexer/issues/504)) ([de741e6](https://github.com/propeller-heads/tycho-indexer/commit/de741e64d9de08d50017872c27975113310dffd8))

## [0.56.0](https://github.com/propeller-heads/tycho-indexer/compare/0.55.2...0.56.0) (2025-02-05)


### Features

* **rpc:** sort tokens by address in `get_protocol_component` ([3014126](https://github.com/propeller-heads/tycho-indexer/commit/3014126a7deecdc56ed5cdf998968193ef9b3443))
* **rpc:** sort tokens by address in `get_protocol_component` ([#503](https://github.com/propeller-heads/tycho-indexer/issues/503)) ([f59b665](https://github.com/propeller-heads/tycho-indexer/commit/f59b6658d5bfe87e61776f199901dabf7b31c1f9))

## [0.55.2](https://github.com/propeller-heads/tycho-indexer/compare/0.55.1...0.55.2) (2025-02-05)


### Bug Fixes

* update ChangeType enum derived traits ([2e9032e](https://github.com/propeller-heads/tycho-indexer/commit/2e9032ea0afe219e897f87d4bcbf10c9360bb011))
* update ChangeType enum derived traits ([#502](https://github.com/propeller-heads/tycho-indexer/issues/502)) ([383e348](https://github.com/propeller-heads/tycho-indexer/commit/383e3482f45bb7960ad6e2593c3d54e964b6357d))

## [0.55.1](https://github.com/propeller-heads/tycho-indexer/compare/0.55.0...0.55.1) (2025-01-30)


### Bug Fixes

* clean up imports ([a32f8f9](https://github.com/propeller-heads/tycho-indexer/commit/a32f8f9e8ce1cc933c39ea1578aea77f4e181673))
* clean up imports ([#499](https://github.com/propeller-heads/tycho-indexer/issues/499)) ([0a8971b](https://github.com/propeller-heads/tycho-indexer/commit/0a8971ba9b7b566247431f8bd0c9c087ac2f4161))
* fix protocol system endpoint conversion to POST ([9f8d11b](https://github.com/propeller-heads/tycho-indexer/commit/9f8d11bdd2aa76ed4a7869d966142a110cb804f3))
* fix protocol system endpoint conversion to POST ([#498](https://github.com/propeller-heads/tycho-indexer/issues/498)) ([e559128](https://github.com/propeller-heads/tycho-indexer/commit/e5591282340b408c1d23a13b4d4cebf5b3b64115))

## [0.55.0](https://github.com/propeller-heads/tycho-indexer/compare/0.54.0...0.55.0) (2025-01-29)


### Features

* make protocol system a POST endpoint ([d85b2a4](https://github.com/propeller-heads/tycho-indexer/commit/d85b2a44166c376808e634c13839d2a95b4705fa))
* make protocol system a POST endpoint ([#496](https://github.com/propeller-heads/tycho-indexer/issues/496)) ([aad6b51](https://github.com/propeller-heads/tycho-indexer/commit/aad6b5153203a502920b05b1fcad67c80e307ae3))

## [0.54.0](https://github.com/propeller-heads/tycho-indexer/compare/0.53.0...0.54.0) (2025-01-27)


### Features

* add AccountBalance model to tx aggregated model ([ee96ba2](https://github.com/propeller-heads/tycho-indexer/commit/ee96ba27233b1e6a114f2e7326c79d7f938fb416))
* Add AccountBalance to core models ([#493](https://github.com/propeller-heads/tycho-indexer/issues/493)) ([cb86d4e](https://github.com/propeller-heads/tycho-indexer/commit/cb86d4e0ffb905c4d51a0a3514296305b8d19d3b))
* update parsing of new protobuf message changes ([1c424c0](https://github.com/propeller-heads/tycho-indexer/commit/1c424c05606bf9f056b7849a64bce559b17d008f))

## [0.53.0](https://github.com/propeller-heads/tycho-indexer/compare/0.52.0...0.53.0) (2025-01-23)


### Features

* add account balances to protobuf messages ([349aa2c](https://github.com/propeller-heads/tycho-indexer/commit/349aa2c61e0766db72b18c4920588c3969c12de8))
* add AccountBalances to the protobuf messages ([#492](https://github.com/propeller-heads/tycho-indexer/issues/492)) ([08cb0c6](https://github.com/propeller-heads/tycho-indexer/commit/08cb0c600447851c91493d1e58e81ce1362d47da))


### Bug Fixes

* remove unnecessary tx field in ProtocolComponent ([43e6573](https://github.com/propeller-heads/tycho-indexer/commit/43e65737f05fb48f06051670882ffc379616b1dd))

## [0.52.0](https://github.com/propeller-heads/tycho-indexer/compare/0.51.0...0.52.0) (2025-01-22)


### Features

* Add Base to supported chains ([c0afd1a](https://github.com/propeller-heads/tycho-indexer/commit/c0afd1ac5df5a3302e4a5153638d1c71889fa2be))
* Add Base to supported chains ([#491](https://github.com/propeller-heads/tycho-indexer/issues/491)) ([31447a8](https://github.com/propeller-heads/tycho-indexer/commit/31447a8ad3de358f330775e634bda326714cf2da))

## [0.51.0](https://github.com/propeller-heads/tycho-indexer/compare/0.50.0...0.51.0) (2025-01-20)


### Features

* update substreams client to accept compressed messages ([3a68674](https://github.com/propeller-heads/tycho-indexer/commit/3a6867418ba78a89568757a249dcd66fe2b758ff))
* update substreams client to accept compressed messages ([#489](https://github.com/propeller-heads/tycho-indexer/issues/489)) ([b441682](https://github.com/propeller-heads/tycho-indexer/commit/b4416824d66799d208812bd698ca12e16bba01cc))

## [0.50.0](https://github.com/propeller-heads/tycho-indexer/compare/0.49.2...0.50.0) (2025-01-17)


### Features

* add protocol system rpc ([#484](https://github.com/propeller-heads/tycho-indexer/issues/484)) ([9987d56](https://github.com/propeller-heads/tycho-indexer/commit/9987d5630c8be58173ca73a85549bf5f7c585644))
* add protocol_systems rpc ([9e44522](https://github.com/propeller-heads/tycho-indexer/commit/9e4452234a51a3ce83e76c82cfad0d430b0775ab))


### Bug Fixes

* add cache exist ([97f75a1](https://github.com/propeller-heads/tycho-indexer/commit/97f75a12cd1ff3b2a6cca8edf9b555d819192ac9))
* add sort before pagination ([c864f8f](https://github.com/propeller-heads/tycho-indexer/commit/c864f8f43669f778d01dca937d0e263918abf9ae))
* get method ([8540c47](https://github.com/propeller-heads/tycho-indexer/commit/8540c474e9b7a716cb4e2d61229d874d19fd51ad))

## [0.49.2](https://github.com/propeller-heads/tycho-indexer/compare/0.49.1...0.49.2) (2025-01-16)


### Bug Fixes

* add more db gateway 'get' tracing spans ([#487](https://github.com/propeller-heads/tycho-indexer/issues/487)) ([b11ee91](https://github.com/propeller-heads/tycho-indexer/commit/b11ee913628b0ae3053081b415e0c67472390df6))
* add more db gateway read spans ([958f357](https://github.com/propeller-heads/tycho-indexer/commit/958f357b7fd9ee8f4f59484133803c52ebbad3b5))

## [0.49.1](https://github.com/propeller-heads/tycho-indexer/compare/0.49.0...0.49.1) (2025-01-13)


### Bug Fixes

* map empty user identity to 'unknown' in metrics ([352016a](https://github.com/propeller-heads/tycho-indexer/commit/352016abbf6f9b8947af8a3a4baf1a0353a6ca33))
* map empty user identity to 'unknown' in metrics ([#485](https://github.com/propeller-heads/tycho-indexer/issues/485)) ([8d9fb62](https://github.com/propeller-heads/tycho-indexer/commit/8d9fb62c940f7b4d1c3c96e2d1dbb82242ef8f56))

## [0.49.0](https://github.com/propeller-heads/tycho-indexer/compare/0.48.0...0.49.0) (2025-01-10)


### Features

* add chain reorg metric ([b17b74f](https://github.com/propeller-heads/tycho-indexer/commit/b17b74f42b702d05d5283f010f7ebc0e5fe0766c))
* add substreams block message size metric ([5180275](https://github.com/propeller-heads/tycho-indexer/commit/5180275a876f29f06c9548d116cfc99980ac343a))
* extend substreams block message metrics ([#482](https://github.com/propeller-heads/tycho-indexer/issues/482)) ([b005e26](https://github.com/propeller-heads/tycho-indexer/commit/b005e26ec23b9ef318b324ac10301f04852d2be7))


### Bug Fixes

* add to and from block data to reorg metric ([44df826](https://github.com/propeller-heads/tycho-indexer/commit/44df826b5635864e1e6c067c7c8516e29fc94066))

## [0.48.0](https://github.com/propeller-heads/tycho-indexer/compare/0.47.0...0.48.0) (2025-01-10)


### Features

* bound end_idx to latest ([ea548ef](https://github.com/propeller-heads/tycho-indexer/commit/ea548ef21d78c3ace7c144223029f35b29f956ed))
* predefined behaviour for latest ts ([2ae6012](https://github.com/propeller-heads/tycho-indexer/commit/2ae60126cc71cd60a16d36e430e3b732a9b53542))
* revert changes and match current time ([81ad8e1](https://github.com/propeller-heads/tycho-indexer/commit/81ad8e19cfc654f8b21bd1817efaad34a1826fe7))
* revert previous changes && make version optional ([be15c0d](https://github.com/propeller-heads/tycho-indexer/commit/be15c0d8932219ca716644e1c4a685a02171401c))


### Bug Fixes

* delete all account balances for accounts to be deleted ([a3d9ffc](https://github.com/propeller-heads/tycho-indexer/commit/a3d9ffc0db659d8a074cb0e5c73f92fea9e1c72d))
* fix account balances bug ([c0b6678](https://github.com/propeller-heads/tycho-indexer/commit/c0b6678fb09786f0522a875cebae345e521ddf3c))
* fix protocol system deletion script account balances bug ([#477](https://github.com/propeller-heads/tycho-indexer/issues/477)) ([a749b53](https://github.com/propeller-heads/tycho-indexer/commit/a749b5305f23d4a66b177f6c89d6c269a62801e4))
* get_block_range ([6460d3d](https://github.com/propeller-heads/tycho-indexer/commit/6460d3d297a6667417f71f39fc066f897c0af762))
* test ([fe343d4](https://github.com/propeller-heads/tycho-indexer/commit/fe343d4e5e0396cb05c33a84de12fb3c1878a6ef))
* Update get_block_range to return full buffer when Ts is now or greater ([#470](https://github.com/propeller-heads/tycho-indexer/issues/470)) ([9507f32](https://github.com/propeller-heads/tycho-indexer/commit/9507f3280678be1b13f47feae7b90d523ef9d91e))

## [0.47.0](https://github.com/propeller-heads/tycho-indexer/compare/0.46.8...0.47.0) (2025-01-10)


### Features

* add user identity to ws connection metrics ([ac807b2](https://github.com/propeller-heads/tycho-indexer/commit/ac807b265f775aa27509cc3caa06274fddcda467))
* add user identity to ws connection metrics ([#480](https://github.com/propeller-heads/tycho-indexer/issues/480)) ([f2a3c8d](https://github.com/propeller-heads/tycho-indexer/commit/f2a3c8d1b0fbacdaea73277a60ca52a862b29d10))


### Bug Fixes

* default to 'unknown' if no user identity is present ([977f02e](https://github.com/propeller-heads/tycho-indexer/commit/977f02e6385ed283b0915ab020de6403a910f2df))

## [0.46.8](https://github.com/propeller-heads/tycho-indexer/compare/0.46.7...0.46.8) (2025-01-10)

## [0.46.7](https://github.com/propeller-heads/tycho-indexer/compare/0.46.6...0.46.7) (2025-01-09)


### Bug Fixes

* docker build ([68cb6a8](https://github.com/propeller-heads/tycho-indexer/commit/68cb6a8ef3abd146871ef5adaf8b91cfcf6e01bb)), closes [#474](https://github.com/propeller-heads/tycho-indexer/issues/474)
* docker build ([#475](https://github.com/propeller-heads/tycho-indexer/issues/475)) ([3569ee3](https://github.com/propeller-heads/tycho-indexer/commit/3569ee3ed22e25a8c78657ea09a87bf703451c58))

## [0.46.6](https://github.com/propeller-heads/tycho-indexer/compare/0.46.5...0.46.6) (2025-01-07)


### Bug Fixes

* changed validate pr condition ([c2913e6](https://github.com/propeller-heads/tycho-indexer/commit/c2913e618aba3000f4f5be0f1ae2b9a5f017b3a3))
* changed validate pr condition ([#476](https://github.com/propeller-heads/tycho-indexer/issues/476)) ([7bb6e84](https://github.com/propeller-heads/tycho-indexer/commit/7bb6e84bb31b63330d471265e6826eb9f8b5193f))
* try to run validate pr ([e646ed8](https://github.com/propeller-heads/tycho-indexer/commit/e646ed882662eb352c109f1391dda556591303ba))
* try to run validate pr ([4da002f](https://github.com/propeller-heads/tycho-indexer/commit/4da002f687cc1548f2cbf024e40c2270dc2bb4a5))
* try to run validate pr ([e85317d](https://github.com/propeller-heads/tycho-indexer/commit/e85317df16a7dcdf49847817ae7f89e9e250e2b5))

## [0.46.5](https://github.com/propeller-heads/tycho-indexer/compare/0.46.4...0.46.5) (2024-12-20)


### Bug Fixes

* switch block_processing_time metric to a gauge ([6ce8fd0](https://github.com/propeller-heads/tycho-indexer/commit/6ce8fd08f314862724a2a3aa805341cf02c5d88d))
* switch block_processing_time metric to a gauge ([#466](https://github.com/propeller-heads/tycho-indexer/issues/466)) ([8f2f584](https://github.com/propeller-heads/tycho-indexer/commit/8f2f5848d4dccf488557f9f55db0adb1baee9faa))

## [0.46.4](https://github.com/propeller-heads/tycho-indexer/compare/0.46.3...0.46.4) (2024-12-19)


### Bug Fixes

* calculate substream lag in millis ([5f3d503](https://github.com/propeller-heads/tycho-indexer/commit/5f3d503141f0b89c3c1ebae0f8c5f734b2b2770c))
* calculate substream lag in millis ([#465](https://github.com/propeller-heads/tycho-indexer/issues/465)) ([07916ff](https://github.com/propeller-heads/tycho-indexer/commit/07916fffbd61f6d68eaf3609762a41fa8b5c5057))

## [0.46.3](https://github.com/propeller-heads/tycho-indexer/compare/0.46.2...0.46.3) (2024-12-18)


### Bug Fixes

* rpc_requests metrics typo ([5cc490c](https://github.com/propeller-heads/tycho-indexer/commit/5cc490c6f6283c0c5b40bd54e17f8d5f290de3e2))
* split chain and extractor metric labels ([f15f2e2](https://github.com/propeller-heads/tycho-indexer/commit/f15f2e2ffa17cd4f34a4a8493bdb6e8892a7789e))
* split chain and extractor metric labels ([#463](https://github.com/propeller-heads/tycho-indexer/issues/463)) ([b98a5db](https://github.com/propeller-heads/tycho-indexer/commit/b98a5dbc74cbf76cfae8eae3d8b93a9c2c36d73a))

## [0.46.2](https://github.com/propeller-heads/tycho-indexer/compare/0.46.1...0.46.2) (2024-12-18)


### Bug Fixes

* decrement active subscription on ws connection close ([329fedd](https://github.com/propeller-heads/tycho-indexer/commit/329fedda025f42d6c65da931d4a9f0af1cc7a94c))
* decrement active subscription on ws connection close ([#462](https://github.com/propeller-heads/tycho-indexer/issues/462)) ([585ec90](https://github.com/propeller-heads/tycho-indexer/commit/585ec90fd6a62166a379e5a5a7a9e2917fd11a44))

## [0.46.1](https://github.com/propeller-heads/tycho-indexer/compare/0.46.0...0.46.1) (2024-12-17)


### Bug Fixes

* improve websocket metrics with extended metadata ([51c70eb](https://github.com/propeller-heads/tycho-indexer/commit/51c70eb54c8be6500f67335a393b89b60e9f9124))
* improve websocket metrics with extended metadata ([#460](https://github.com/propeller-heads/tycho-indexer/issues/460)) ([b8b3e1e](https://github.com/propeller-heads/tycho-indexer/commit/b8b3e1e8d5a9b966a830aed6dab18bfea72ba318))
* remove api key metric metadata ([4c12f56](https://github.com/propeller-heads/tycho-indexer/commit/4c12f5600f2d3cdbd185b8ced5274940c9434fc3))

## [0.46.0](https://github.com/propeller-heads/tycho-indexer/compare/0.45.2...0.46.0) (2024-12-16)


### Features

* **tycho-client:** increase pagination chunksize to 100 ([6c9b2da](https://github.com/propeller-heads/tycho-indexer/commit/6c9b2dac16b1f1ba999dc3028c480c908065037c))
* **tycho-client:** increase pagination chunksize to 100 ([#459](https://github.com/propeller-heads/tycho-indexer/issues/459)) ([c8b7ac6](https://github.com/propeller-heads/tycho-indexer/commit/c8b7ac6c6d30f484d03fffb6bcde29a7a4e41b6b))

## [0.45.2](https://github.com/propeller-heads/tycho-indexer/compare/0.45.1...0.45.2) (2024-12-13)


### Bug Fixes

* add extractor tag to block processing time metric ([d055d29](https://github.com/propeller-heads/tycho-indexer/commit/d055d295d0134e94d28bde725183f1f97686b360))
* add extractor tag to block processing time metric ([#458](https://github.com/propeller-heads/tycho-indexer/issues/458)) ([8305784](https://github.com/propeller-heads/tycho-indexer/commit/830578471caed1462a4e34148ade8680f00b569c))

## [0.45.1](https://github.com/propeller-heads/tycho-indexer/compare/0.45.0...0.45.1) (2024-12-12)


### Bug Fixes

* update SQL script to prune `transaction` table ([e43094a](https://github.com/propeller-heads/tycho-indexer/commit/e43094a529ea41c3a739ad458599bfc7eb627755))
* update SQL script to prune `transaction` table ([#455](https://github.com/propeller-heads/tycho-indexer/issues/455)) ([34ec325](https://github.com/propeller-heads/tycho-indexer/commit/34ec32557a5647bc828015e0813b6297ef9b4dc0))

## [0.45.0](https://github.com/propeller-heads/tycho-indexer/compare/0.44.0...0.45.0) (2024-12-12)


### Features

* add active websocket connections metric ([94f0a44](https://github.com/propeller-heads/tycho-indexer/commit/94f0a44c79a805c2075c30a219c3549811452ea4))
* add block processing time metric ([dc83c5e](https://github.com/propeller-heads/tycho-indexer/commit/dc83c5ea279c7d0140c65ba8404dcda60b9268a3))
* add dropped websocket connections metric ([5349418](https://github.com/propeller-heads/tycho-indexer/commit/53494184d16647c16fb6295e71fa6a45349ab57b))
* add metric for extractors current block ([ce89671](https://github.com/propeller-heads/tycho-indexer/commit/ce896718605054fc1073f1c4281c8b41d717b51b))
* add remaining sync time metric ([49de728](https://github.com/propeller-heads/tycho-indexer/commit/49de7281ae4f686b5332fdeaf32d73efc728c6e1))
* add RPC cache hits and misses count metrics ([10cef88](https://github.com/propeller-heads/tycho-indexer/commit/10cef881e903a1fb233df9dca0dca00fd370010a))
* add RPC failed requests count metric ([1dd9f95](https://github.com/propeller-heads/tycho-indexer/commit/1dd9f950ea7e8982f6b852f8f21597b106d04049))
* add RPC requests count metric ([571af0f](https://github.com/propeller-heads/tycho-indexer/commit/571af0fae7753abdf04eb1ca39f731224dff837d))
* add substream failure metrics ([258acb9](https://github.com/propeller-heads/tycho-indexer/commit/258acb90b1f5cfedc5f908ed7b526846544c72e1))
* add substreams lag metric ([485ea9c](https://github.com/propeller-heads/tycho-indexer/commit/485ea9cbf5d6b1d9508560ad33e072b2136d620f))
* add tycho-indexer metrics  ([#454](https://github.com/propeller-heads/tycho-indexer/issues/454)) ([13f780f](https://github.com/propeller-heads/tycho-indexer/commit/13f780fc4a5af6e5d0aa33987b94104c8f816044))


### Bug Fixes

* improve metric naming ([ddfedab](https://github.com/propeller-heads/tycho-indexer/commit/ddfedabdf85522b99cb8b9f42bc66001a5e1afef))
* improve substream metric labels ([3bfbf37](https://github.com/propeller-heads/tycho-indexer/commit/3bfbf378ce7f1feeed5dcee8601514b730d1a28e))

## [0.44.0](https://github.com/propeller-heads/tycho-indexer/compare/0.43.0...0.44.0) (2024-12-06)


### Features

* add metrics exporter and expose /metrics endpoint ([ff247c7](https://github.com/propeller-heads/tycho-indexer/commit/ff247c7a1b3e01c347bc66899be154b8143d4cfc))
* set up metrics exporter ([#453](https://github.com/propeller-heads/tycho-indexer/issues/453)) ([c426cd3](https://github.com/propeller-heads/tycho-indexer/commit/c426cd3e7588e62286d9cfc86c2d2e55204ff6fa))

## [0.43.0](https://github.com/propeller-heads/tycho-indexer/compare/0.42.3...0.43.0) (2024-11-29)


### Features

* Allow FeedMsg to be deserialized. ([f8d7655](https://github.com/propeller-heads/tycho-indexer/commit/f8d765554194ddd222e4c6f07811e8c99700615a))
* Allow FeedMsg to be deserialized. ([#451](https://github.com/propeller-heads/tycho-indexer/issues/451)) ([5d22803](https://github.com/propeller-heads/tycho-indexer/commit/5d228037843eb71555bb4478ca17a47e0ab996b7))

## [0.42.3](https://github.com/propeller-heads/tycho-indexer/compare/0.42.2...0.42.3) (2024-11-26)


### Bug Fixes

* **client:** remove hardcoded tycho host url ([2d9b1e1](https://github.com/propeller-heads/tycho-indexer/commit/2d9b1e1cda595c4a1329fcdd478bd2e57d77a260))
* **client:** remove hardcoded Tycho host url ([#449](https://github.com/propeller-heads/tycho-indexer/issues/449)) ([0181a1e](https://github.com/propeller-heads/tycho-indexer/commit/0181a1ef8c76a747e2192443525feb91973b155d))

## [0.42.2](https://github.com/propeller-heads/tycho-indexer/compare/0.42.1...0.42.2) (2024-11-25)


### Bug Fixes

* **rpc:** add buffer lookup for version given as block hash ([8fd6a86](https://github.com/propeller-heads/tycho-indexer/commit/8fd6a86eef8a328ef2ea625d71144e27af1529c9))
* **rpc:** add buffer lookup for version given as block hash ([#435](https://github.com/propeller-heads/tycho-indexer/issues/435)) ([a9672ad](https://github.com/propeller-heads/tycho-indexer/commit/a9672ad0e92dcc5af2f04c452e48e9007088a572))

## [0.42.1](https://github.com/propeller-heads/tycho-indexer/compare/0.42.0...0.42.1) (2024-11-20)


### Bug Fixes

* fix token analysis cronjob not setting quality for good tokens ([e0470dd](https://github.com/propeller-heads/tycho-indexer/commit/e0470dd0a97ea209d6789822ed80879e4311df6d))

## [0.42.0](https://github.com/propeller-heads/tycho-indexer/compare/0.41.1...0.42.0) (2024-11-19)


### Features

* **hex_bytes:** change hex bytes conversions to big endian ([3961824](https://github.com/propeller-heads/tycho-indexer/commit/39618244c4bbdc90d09af3af740edc34e6e68f76))
* **hex_bytes:** change hex bytes conversions to big endian ([#429](https://github.com/propeller-heads/tycho-indexer/issues/429)) ([e88a4c6](https://github.com/propeller-heads/tycho-indexer/commit/e88a4c67a9865f9505cf9827bb64e24e9cd73845))
* **tycho-ethereum:** update ether <-> bytes conversions to big endian ([3943560](https://github.com/propeller-heads/tycho-indexer/commit/39435606aaf0e92f9d5051a5df17617a0c7a075e))


### Bug Fixes

* make ethcontract optional ([2482ecc](https://github.com/propeller-heads/tycho-indexer/commit/2482ecc0592c1ef2592252543d00759fe22c11fc))

## [0.41.1](https://github.com/propeller-heads/tycho-indexer/compare/0.41.0...0.41.1) (2024-11-10)


### Bug Fixes

* fix formatting ([02f4d59](https://github.com/propeller-heads/tycho-indexer/commit/02f4d59ab7515a154110030eea97d956b8fcda47))
* fix token preprocessor symbol length to 255 chars ([0af6caa](https://github.com/propeller-heads/tycho-indexer/commit/0af6caa6c559222c12cc23f420c01dd5989a6a6c))
* fix token preprocessor symbol length to 255 chars ([#433](https://github.com/propeller-heads/tycho-indexer/issues/433)) ([466e620](https://github.com/propeller-heads/tycho-indexer/commit/466e6202e2409a47d0585dcbd535b63c23574e4b))
* **indexer:** correctly truncate token symbol ([9d7cd61](https://github.com/propeller-heads/tycho-indexer/commit/9d7cd6126c6e5dead0fa544a08c6d86807730ac8))

## [0.41.0](https://github.com/propeller-heads/tycho-indexer/compare/0.40.0...0.41.0) (2024-11-04)


### Features

* **tycho-client:** return the tokio handle from the stream builder ([06a669e](https://github.com/propeller-heads/tycho-indexer/commit/06a669e59ef2ec05c3aeb9a60b571a44ccf6e5ec))
* **tycho-client:** return the tokio handle from the stream builder ([#441](https://github.com/propeller-heads/tycho-indexer/issues/441)) ([173e774](https://github.com/propeller-heads/tycho-indexer/commit/173e774bd3726df5c93a938eafa8d1762a363250))

## [0.40.0](https://github.com/propeller-heads/tycho-indexer/compare/0.39.0...0.40.0) (2024-11-04)


### Features

* **tycho-client:** create rust client builder ([21d11a1](https://github.com/propeller-heads/tycho-indexer/commit/21d11a1a8dae0d79d675350902bbeaad60fa09a4))
* **tycho-client:** implement a rust client stream builder ([#439](https://github.com/propeller-heads/tycho-indexer/issues/439)) ([20be73c](https://github.com/propeller-heads/tycho-indexer/commit/20be73cdc4391805e2acf405ccf2fb5191dec3b7))
* **tycho-client:** improve error handling on TychoStreamBuilder ([b0a175c](https://github.com/propeller-heads/tycho-indexer/commit/b0a175ce0b4b484eecf85e12330f75925c3fa717))


### Bug Fixes

* **tycho-client:** do not error if no auth key is provided with tsl active ([19ac0d1](https://github.com/propeller-heads/tycho-indexer/commit/19ac0d12b1ed974b5ccb95cf2f62eca0f3b647ed))
* **tycho-client:** support fetching auth token from env var ([c1c03aa](https://github.com/propeller-heads/tycho-indexer/commit/c1c03aaa0a74b9170b57e70cf8e05fc9a8e79573))

## [0.39.0](https://github.com/propeller-heads/tycho-indexer/compare/0.38.0...0.39.0) (2024-11-02)


### Features

* **indexer:** expose s3 bucket as cli arg ([a55e126](https://github.com/propeller-heads/tycho-indexer/commit/a55e1265af2bf5b5bdc6c284c49128fc2590ae2f))
* **indexer:** parse s3 bucket from env variable ([c67fc38](https://github.com/propeller-heads/tycho-indexer/commit/c67fc3812007edc644b86efc45fa499aa098b2a9))
* **indexer:** parse s3 bucket from env variable ([#440](https://github.com/propeller-heads/tycho-indexer/issues/440)) ([104c4e9](https://github.com/propeller-heads/tycho-indexer/commit/104c4e90cf18a81dfe40ea5ea71b57f9be607691))

## [0.38.0](https://github.com/propeller-heads/tycho-indexer/compare/0.37.0...0.38.0) (2024-10-31)


### Features

* **rpc:** mark chain field in version param as deprecated ([8c00bde](https://github.com/propeller-heads/tycho-indexer/commit/8c00bdeb75edac5939f5eff415639cba7dd0d420))
* **rpc:** remove chain param from individual protocol ids ([4386dd0](https://github.com/propeller-heads/tycho-indexer/commit/4386dd0993d94484b39e861c989b559dd1f82ee0))
* **rpc:** remove chain param from individual protocol ids ([#437](https://github.com/propeller-heads/tycho-indexer/issues/437)) ([8c10d6a](https://github.com/propeller-heads/tycho-indexer/commit/8c10d6a9f8960f2d0e6d3bba50d1f82a41e935f2))
* **tycho-client:** update state endpoint body ([c535f79](https://github.com/propeller-heads/tycho-indexer/commit/c535f79a35bad00ca2443a1d643a9a344bb44118))

## [0.37.0](https://github.com/propeller-heads/tycho-indexer/compare/0.36.0...0.37.0) (2024-10-30)


### Features

* **storage:** update protocol state fetch query to apply all given filters ([1f64df2](https://github.com/propeller-heads/tycho-indexer/commit/1f64df222e7b258571e4b176dc779321f8ca504f))
* **storage:** update protocol state fetch query to apply all given filters ([#432](https://github.com/propeller-heads/tycho-indexer/issues/432)) ([5cb824e](https://github.com/propeller-heads/tycho-indexer/commit/5cb824e13c1cb4c86b290162cdeca6200307bb9f))

## [0.36.0](https://github.com/propeller-heads/tycho-indexer/compare/0.35.3...0.36.0) (2024-10-30)


### Features

* **scripts:** add balance check in uniswapv3 validation script ([25dc808](https://github.com/propeller-heads/tycho-indexer/commit/25dc8082d7223d89e4de12a539612d007f66fb5f))
* **scripts:** update uniswapv3 check script ([e1a1ce0](https://github.com/propeller-heads/tycho-indexer/commit/e1a1ce0f7351b29069d2f5b1bf9b9be2f3075012))

## [0.35.3](https://github.com/propeller-heads/tycho-indexer/compare/0.35.2...0.35.3) (2024-10-25)


### Bug Fixes

* **indexer:** correctly handle attributes deletions ([57fad94](https://github.com/propeller-heads/tycho-indexer/commit/57fad947c172ad0b5ecf9078a32580c204df679d))
* **indexer:** correctly handle attributes deletions ([#420](https://github.com/propeller-heads/tycho-indexer/issues/420)) ([faa08f6](https://github.com/propeller-heads/tycho-indexer/commit/faa08f645fc8a63ad2ed1fcd8689f586f96af1b5))

## [0.35.2](https://github.com/propeller-heads/tycho-indexer/compare/0.35.1...0.35.2) (2024-10-25)


### Bug Fixes

* pacakge release workflow ([5881d64](https://github.com/propeller-heads/tycho-indexer/commit/5881d641467325f26a164c73dd7cd64cbb344135))
* pacakge release workflow ([#431](https://github.com/propeller-heads/tycho-indexer/issues/431)) ([7b329a3](https://github.com/propeller-heads/tycho-indexer/commit/7b329a3f90fda2b1571617adcad83e8b7c36d39e))

## [0.35.1](https://github.com/propeller-heads/tycho-indexer/compare/0.35.0...0.35.1) (2024-10-24)


### Bug Fixes

* Fix ProtocolState RPC pagination by pre-paginating IDs ([fa485d2](https://github.com/propeller-heads/tycho-indexer/commit/fa485d25825df645380ea5d155bae010006f5ff4))
* Fix ProtocolState RPC pagination by pre-paginating IDs ([#425](https://github.com/propeller-heads/tycho-indexer/issues/425)) ([64ee5ce](https://github.com/propeller-heads/tycho-indexer/commit/64ee5ce22a56445b1bf7f970e96e78206b57f40d))
* remove unnecessary clone ([287d57f](https://github.com/propeller-heads/tycho-indexer/commit/287d57f9565bf2da4dcc80c406da6d9f845b0867))
* return total components when no id is specified for protocol_states ([8a78cb9](https://github.com/propeller-heads/tycho-indexer/commit/8a78cb9d6a7825afd66f4fa6b15483d8ce3ea771))

## [0.35.0](https://github.com/propeller-heads/tycho-indexer/compare/0.34.1...0.35.0) (2024-10-24)


### Features

* **ci:** Build wheels for python client. ([b882252](https://github.com/propeller-heads/tycho-indexer/commit/b8822526aa73f5643f5cf821ce1f64febc07605a))
* Ship tycho-client-py with binaries ([#427](https://github.com/propeller-heads/tycho-indexer/issues/427)) ([6e55465](https://github.com/propeller-heads/tycho-indexer/commit/6e55465fc8cc6a5f636016b7d45f19310b0c5ea8))
* **tycho-client:** Distribute binary with python lib. ([1540a4a](https://github.com/propeller-heads/tycho-indexer/commit/1540a4a9fb495746f479d4ce1ed5fd9477ae8556))

## [0.34.1](https://github.com/propeller-heads/tycho-indexer/compare/0.34.0...0.34.1) (2024-10-23)


### Bug Fixes

* **rpc:** correctly pass down delta buffer in RPC ([a1f35d8](https://github.com/propeller-heads/tycho-indexer/commit/a1f35d8bd4871ec01386155c894db8d74ff3f180))
* **rpc:** correctly pass down delta buffer in RPC ([#428](https://github.com/propeller-heads/tycho-indexer/issues/428)) ([de328a0](https://github.com/propeller-heads/tycho-indexer/commit/de328a04b529331586d40363e2aa1f4b68f79bbe))

## [0.34.0](https://github.com/propeller-heads/tycho-indexer/compare/0.33.1...0.34.0) (2024-10-22)


### Features

* **indexer:** introduce configurable post processors ([a9b9f2c](https://github.com/propeller-heads/tycho-indexer/commit/a9b9f2ced4f79cd95431a02a9c32dd6234a7dcc4))
* **indexer:** introduce configurable post processors ([#423](https://github.com/propeller-heads/tycho-indexer/issues/423)) ([4627cb4](https://github.com/propeller-heads/tycho-indexer/commit/4627cb430d3a80773e474e29ced4491d4c4e1eae))


### Bug Fixes

* correctly propagate missing post processor error ([5f655ae](https://github.com/propeller-heads/tycho-indexer/commit/5f655aee05c3f7c5cf2fe9c55d30e7c5c495da92))

## [0.33.1](https://github.com/propeller-heads/tycho-indexer/compare/0.33.0...0.33.1) (2024-10-22)


### Bug Fixes

* added secrets for build and push ([#421](https://github.com/propeller-heads/tycho-indexer/issues/421)) ([6567024](https://github.com/propeller-heads/tycho-indexer/commit/656702412ea34b5527c0505cb845dc85b2bd6ddf))
* **rpc:** allow to run `RpcHandler` without pending deltas. ([9ebb629](https://github.com/propeller-heads/tycho-indexer/commit/9ebb6296851d32c3d213bd7772bb60bf7bff0801))
* **rpc:** correctly handle requests with no ids specified ([#412](https://github.com/propeller-heads/tycho-indexer/issues/412)) ([8c04f17](https://github.com/propeller-heads/tycho-indexer/commit/8c04f171031b101b9b409372cc22ad7251676ad4))
* **rpc:** correctly handle when no ids are requested ([5470bf1](https://github.com/propeller-heads/tycho-indexer/commit/5470bf1600984826f0c1f7495ab20ec42121d7ae))
* **rpc:** fix running RPC without extractors ([#411](https://github.com/propeller-heads/tycho-indexer/issues/411)) ([c5b05cb](https://github.com/propeller-heads/tycho-indexer/commit/c5b05cbf6097c83c2ea90ce472ea880329f6d3ea))

## [0.33.0](https://github.com/propeller-heads/tycho-indexer/compare/0.32.0...0.33.0) (2024-10-11)


### Features

* **rpc:** return custom message for RPC error ([02daedb](https://github.com/propeller-heads/tycho-indexer/commit/02daedb1a8fc66d7d0847eaa81f589f020a77881))
* **rpc:** return custom message for RPC error ([#414](https://github.com/propeller-heads/tycho-indexer/issues/414)) ([6a51645](https://github.com/propeller-heads/tycho-indexer/commit/6a51645e986c14b1d9a9ec00dcbae3dd2cca746d))

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
