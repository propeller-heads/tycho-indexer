# Protocol External Contracts

Some protocols use external contracts such as oracles or price feed contracts. These
contracts are usually not tracked by the factories, making indexing them a challenge.
Even if they could be indexed, they are mostly black boxes since they are not part of the
protocol which means their code and bheaviour is unkown. So, it is hard to predict which
other contracts they may call.

## Case Studies

To get a good understanding of the problem, let us analyze a few protocols that utilize
such external components.

### Integral

Integral uses oracle contracts - these are linked to a pair (via a transaction/
contructor) **after** the pair was deployed. Naturally the oracle must have been
deployed before the pair. Making it impossible to index since we could not have
witnessed its deployment.

Making matters worse these pairs can have their oracle contracts changed at any time.
The oracle itself has to query an uniswap pool thus introducing yet another
contract whose state is required to successfully simulate the protocols actions.

### Balancer

Balancer allows users to deploy `ComposableStablePools` which use a user deployed oracle
contract to determine the price of the pool. Nothing is known about the oracle other
than the interface it has to implement. Pool owners can change the oracle at any time.

### Synthetix

TODO: Analyze

### GMX

TODO: Analyze

## Possible Solutions

To come up with a potential solution to this problem let's summarize what we do know
about the oracle contracts or what can be expected to be known in most cases.

### Interfaces:

We usually know that the oracle has to follow a certain interface. We also should be
able to know which methods of the interface are important for the protocol being
implemented to work correctly. Note that the interface may take parameters, that may
depend on the action being executed.

### Address:

We should be able to know the address of the oracle contract at component creation time.
Note that this is most likely only the entrypoint contract and this contract likely
calls other contracts to provide an accurate price.

### Code:

We know the contracts byte code and thus can do a very basic static analysis.

### Storage:

Eventually we will know the contracts storage, this means know which data the contract
has access to.

### 1. RPC against the interface

In the simplest case we have an interface that takes no parameters, so we can call the
methods against a rpc and cache their value on each block. Or even call the oracles
method on substreams each block.

- If the method has parameters this becomes quickly unfeasible.
- Even with caching, this would become likely too slow.
- Contract updates may change the oracles interface making this approach unstable.
- We would need a special mock contract for the oracle that returns the value we extracted via the RPC.

Although simple the amount of latency introduced makes this a suboptimal approach.

### 2. Index (all) oracles contracts

There are not that many oracle providers therefore it would be possible to start
indexing them. E.g. most likely it would make sense to index all of Chainlinks oracles.

This may work and is probably something we would want to do in the future. But it still
wouldn't cover a big amount of cases such as the Balancer or Integral case.

E.g. for integral we would need (vm) index all of uniswap, sushiswap, and other dexes if
their integral governance approves them. Most of this data would we'd likely never access.

Additionally, this will not cover all the use cases, we expect this to cover only a
small percentage. E.g. integral uses a wrapper contract against uniswap to parametrize
the TWAP time, this wrapper would still be missing even if we had all of uniswap vm
indexed.

### 3. Decode the blackbox

#### Deciphering the blackbox

The simplest way we have found, is to search both storage and code for address like
values. This is completely independent of whether the contract uses Solidity, Vyper or
any other language that compiles into evm bytecode.
Note that if the contract is a proxy, we should investigate both the proxy and the
implementation contract code and whenever the implementation is updated, we have to
re-execute the analysis.

The static analysis works as follows:

- Check the code for the presence of `STATICCALL`, `CALL` or `DELEGATECALL` opcodes
    - If not terminate
    - Note: `DELEGATECALL` likely indicates a proxy
- Find all PUSH20 - PUSH32 opcodes and collect their parameters
- Check if the parameter looks like an address (~20 bytes, high entropy), if it does save it
- Next check the first N (e.g. 512) storage slots values for address like values, save them
- Repeat until you have collected all addresses

The procedure above should give you all possibly called addresses in a high percentage
of cases.

#### Dynamic contract indexing

Once we get a set of new contracts, we need a way to index them. This includes
retrieving a one time snapshot and receiving all state updates to these contracts from
this moment onwards.

This will require a special extractor. This extractor does not start historically though,
nor will it emit any historical records to the DB. If we find external contracts, we
would only start indexing them at the detection time (as opposed to at protocol component
creation time as we do usually).

Once we detect a protocol external contract with all it's connected contracts, this
extractor will be notified about it. At this point, it will start extracting storage
changes for the communicated contracts, another task will start retrieving snapshots and
saving these snapshots to the database.

#### Remaining Risks

External contracts may suddenly change. E.g. one of them may be upgradeable and could
be upgraded to call another contract. This would change the set of contracts that are
being called and lead to errors down the road.

Obviously to make components calling external contracts available to clients will
suffer compared to a usual protocol components latency. It still should be possible to
happen within a few seconds.

Potential ideas to mitigate:

- Detect proxies, their patterns and monitor them for any upgrades
- Keep monitoring any storage slots that are known to contain addresses
- Detect calls to those contracts that contain an address
- In any of those above events re-execute the call tree analysis.
- Manual review of external components
    - Notify us about such contracts as they should be rare
    - Manually investigate
    - Ability to deactivate this component if it is not worth the risk
    - Ability to add event triggers, e.g. certain logs, to reevaluate the set of called contracts

## Implementation

From the above options, the third one is the best suited one. We will now look into a
few more details on how to implement it. Roughly we have to come up with a design for
the following steps:

1. Substreams communicates that a protocol external contract was identified
    - The minimum information should include:
        - Static attribute notifying us about the presence of external components
        - The current entrypoint contracts address (be aware that this can change over
          time, so it can't be under static attributes)
2. Tycho analyses the entrypoint and derives:
    - The total set of called contracts
    - The snapshots data for all the involved contracts
3. Tycho registers all new contracts with the dynamic contract indexer
    - This includes passing the initial snapshot to the indexer
4. The original extractor must synchronise with the DCI

### Modeling of components with external contracts

Since an external component is a blackbox, the set of called contracts can change at
any time. This means that to support this, we would ideally want to version the set of
called contracts.

It may also happen that two external components share some contracts. This should be no
problem with the current data schema though. The DCI can check existence before requesting
storage from the RPC and potentially skip contracts that are already being indexed.

Handling external components efficiently requires that we keep track of:

- All contracts addresses that are considered external - since this set may change over time.
- The entrypoint contract - also this contract may change over time.
- Additional metadata per contract within the context of this component: E.g. a set of
  storage lots and or log filters that trigger a re-execution of the static analysis.
- Parameters to use for the static analysis - e.g. the number of slots to consider
  for addresses.

Luckily we already have a tracking system for mutable protocol state, and we can reuse
it to model the data described above.

### Dealing with introduced latency

Statically analysing and retrieving all necessary data about contracts is likely to
introduce a significant amount of latency.

There may be protocols where each component has protocol external contracts (such as
Integral) and there might be others such as Balancer where only a small subset of
components requires them.

To avoid delaying client messages unnecessarily long, we will need a mechanism that
allows us to communicate protocol component creations with a delay, without impacting
other unrelated updates about the protocol.

We will implement this functionality client side. This means extractors will still
communicate creations as usual. But additional contracts are added via protocol state
updates. When clients receive such updates, they will have to take the appropriate
actions (retrieve snapshots, add component to their graph, etc.).
Clients also need to be aware about the fact that the component uses external
protocol components and have to check the components state if the component is ready to
be used or is still undergoing static analysis.

This also allows clients to simply ignore components that require protocol external
contracts since using these may be more risky than not using them.

### New extractor interfaces

Since static analysis and contract storage retrieval is chain specific this will be
offloaded to a separate component that communicates with the extractor. Let's call
this component the DynamicContractIndexer (DCI).

Upon witnessing a protocol component that requires protocol external contracts, the
extractor will forward the component to the DCI along with the block and transaction
it detected it at.

#### Problem with historical accuracy

Special care must be taken to send these request too early. Since the DCI can only
provide updates from the current time onwards. External components state can only be
updated at the current block onwards... this currently leaves us without a transaction
to attach these state changes to.

The DCI itself starts listening to storage slots updates and thereby indexing the
contracts that it received from other extractors. It can do so by consuming the raw
block model from firehose or by restarting a substream with new set of parameters.

The DCI will also statically analyze the components entrypoint contract, then craft the
necessary state update message for the protocol component. These state updates target
the creation transaction of the initially communicated protocol component (if not
syncing, if the extractor is syncing we probably have to create a dummy tx). Next it will
query a node for the complete snapshot of all contracts if not already done during
static analysis.

Each extractor will expose an inbox for finished data of the DCI. Once the DCI
finishes, it puts a block & tx scoped message into the inbox which contains the full
state of protocol component (e.g. all external contracts). Once every block, the inbox
is checked and if it contains a message, the extractor will try to insert the data
either into the database (in case the respective block is finalized) or into the revert
buffer.

#### TODO

Not sure about the above process yet, maybe the inbox should only be used to update
clients. All DB updates could be directly issued from the DCI. The DCI can offload static
analysis, storage retrieval and other chain specific task to an interface (e.g. API or
trait) so that the DCI itself stays chain agnostic.

Note: Initially the extractor may block to simplify a PoC implementation and then merge
the response immediately with the currently pending db transaction. (analysis and state
retrieval is expected to take somewhere between 1-2s)

### Synchronisation with extractors

The DCI will be available to clients. This means clients that want to support components
with external contracts, should also subscribe to the DCI.

This allows clients that do not require external contracts to benefit from increased
latency.

### Optionality

Last but not least it should be mentioned that all of the above processes should be as
much "opt-in" as possible. Meaning if we have a protocol/chain where we don't need
this - it shouldn't make our lives harder.

---

# Notes

Please ignore from here on down. Just a scratchpad.

This previously described procedures needs to be run per newly discovered external
contract. So basically once a protocol component creation informs us about an external
contract, Tycho would look up if we are already indexing it as an external contract
this can happen e.g. if we decide to index all of chainlink - external contracts also
need to save metadata about the interface that was used to fuzz them.

Several ways to models this:

- Metadata can be modeled as part of the attributes and the component should be treated
  as a hybrid.
- Alternatively external components can be protocol components - which are used by other
  components. Entrypoint contract would be mentioned under the contracts attribute. Other
  contracts would be tracked via attributes such that they can be updated if necessary.
    - Not sure if this would allow reusability of contracts - e.g. integrals entrypoint
      would be their custom oracle but the reusable part is the called uniswap constract.
- Probably the most concrete thing we could do is allow protocol set of called contracts
  to mutable (which would require versioning it). We should also add additional
  metadata to contracts, such as solidity code, abi, proxy, etc.

Related questions

- How should we treat proxies?
    - Detect via delegatecall opcodes

Fix Integral quickly

We know the oracle structure we should immediately start indexing them as soon as we
see them. We need a mechanism to fill in the missed storage slots. Which we will anyway
also need if we want to index the blackbox. That should quickly help to resolve the
main problem. We can do the backfill in a blocking fashion first.

Description of procedure:

Blocking

- We get a contract marked as external at block N
- Extractor will start to retrieve all slots for that contract
- Once done extractor proceeds as usual

Async

Option1:

- We get a contract marked as external at block N
- The affected component is withheld and the procedure is started
- Any transaction changes affecting the contract in question are withheld from clients but inserted into the revert
  buffer
- Once the job finished it can find one of two states:
    - Component was already inserted
        - We do a special db transaction to "backfill" the data
    - Component is still in the buffer
        - Just wait until it is, then backfill directly against db
        - Allow mutating data within the buffer
- We emit the component to clients on the next block

Option2:

- We get a contract marked as the external at block N
- The affected component is emitted as "not ready"
- Remaining changes are emitted as usual
    - Clients should ignore the component and changes
- Once the component is ready, we remit the component as updated

Components:

- A component to discover all contracts called by a blackbox contract
    - E.g. for integral that can be hardcoded
    - Short term simply batched call tracers can work
        - If we fuzz the interface, not necessarily swaps
        - Substreams should emit the correct ranges for tracing that interface
    - Mid-long term sth like Reth could be nice here...
    - The RPCStateReader could also work but would be very slow...
- A way to express external components - either with all callees known or without
- Most likely a mechanism to mark a component as not yet available and a way to alert extractors about it once it is.
    - How would this work, we discover ECs during indexing, mark them as available from the current date
    - Once indexing finishes, the components are available and have tvl
    - While syncing
        - We discover it, hand off to a job that will supply all the data needed
        - While the job runs tvl tracking etc. continue
        - Once the job finishes, we emit the component to clients
        - Problems:
            - We might receiving state updates about the component immediately after it is created
            - We can't emit to the client directly since it would try to load a snapshot that is not yet available.
            - Option 1:
                - Emit the component as usual mark it is not yet ready though
                - Client will not take a snapshot if the component is not ready yet
                    - It ignores any updates to it
                - Once it becomes ready the client does it's usual thing
            - Option 2:
                - The extractor does not emit the component and filters any messages for it
                    - But the component is kept in the revert buffer along with its updates
                - Therefore the extractors know about still pending components
                - Once the component is finished, the extractor emits it late and stops
                  filtering updates for it.
                - Client remains unchanged.
                - What happens if the state retrieval takes longer than the revert buffer length?
                - In this case the insertion procedure of the job becomes more complex, since it
                  needs to check which of the state that it just retrieved, has already been overwritten.

Questions:

- Should external contracts be treated with history?
    - If no, then the components created must be marked as only available as available_at from a later point in time.
    - If yes, we will have a high read cost an extremely high complexity since a substream has to wait on another one.