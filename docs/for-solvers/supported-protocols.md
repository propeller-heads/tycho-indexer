# Supported Protocols

Currently, Tycho supports the following protocols:

<table data-full-width="true"><thead><tr><th width="165.953125">Protocol</th><th width="221.7890625">Integration Type</th><th width="165.66015625">Simulation Time</th><th width="191.44921875">Chains</th><th>Partial Support Notes</th></tr></thead><tbody><tr><td><code>uniswap_v2</code></td><td>Native (<code>UniswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum, Base, Unichain</td><td></td></tr><tr><td><code>uniswap_v3</code></td><td>Native (<code>UniswapV3State</code>)</td><td>20 μs (0.02 ms)</td><td>Ethereum, Base, Unichain</td><td></td></tr><tr><td><code>uniswap_v4</code></td><td>Native (<code>UniswapV4State</code>)</td><td>3 μs (0.003 ms)</td><td>Ethereum, Base, Unichain</td><td>Only core uniswap V4 pools are supported on this native implementation.</td></tr><tr><td><code>uniswap_v4_hooks</code></td><td>Hybrid (<code>UniswapV4State</code>)</td><td>-</td><td>Ethereum</td><td>All composable hooks are supported.</td></tr><tr><td><code>vm:balancer_v2</code></td><td>VM (<code>EVMPoolState</code>)</td><td>0.5 ms</td><td>Ethereum</td><td>A few pools are currently unsupported. Use <code>balancer_v2_pool_filter</code></td></tr><tr><td><code>vm:curve</code></td><td>VM (<code>EVMPoolState</code>)</td><td>1 ms</td><td>Ethereum</td><td>Use <code>curve_pool_filter</code> to filter out pools with unsupported tokens types.<br>NOTE: curve requires a node RPC to fetch some code at startup. Please set the <code>RPC_URL</code> env var.</td></tr><tr><td><code>sushiswap_v2</code></td><td>Native (<code>UniswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum</td><td></td></tr><tr><td><code>pancakeswap_v2</code></td><td>Native (<code>PancakeswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum</td><td></td></tr><tr><td><code>pancakeswap_v3</code></td><td>Native (<code>UniswapV3State</code>)</td><td>20 μs (0.02 ms)</td><td>Ethereum, Base</td><td></td></tr><tr><td><code>ekubo_v2</code></td><td>Native (<code>EkuboState</code>)</td><td>1.5 μs (0.0015 ms)</td><td>Ethereum</td><td></td></tr><tr><td><code>vm:maverick_v2</code></td><td>VM (<code>EVMPoolState</code>)</td><td>-</td><td>Ethereum</td><td></td></tr></tbody></table>

{% hint style="info" %}
**Live tracker & Upcoming protocols**

* Currently supported protocols and Tycho status: [http://tycho.live/](http://tycho.live/)
* [List of upcoming protocols](https://docs.google.com/spreadsheets/d/1vDl57BthpeJ9WDqmCVXFdLLvmsm-_SwhSjVzobXJZ04/edit?usp=sharing)
{% endhint %}

{% hint style="info" %}
#### Register code snippet

{% code expandable="true" %}
```rust
fn register_exchanges(
    mut builder: ProtocolStreamBuilder,
    chain: &Chain,
    tvl_filter: ComponentFilter,
) -> ProtocolStreamBuilder {
    match chain {
        Chain::Ethereum => {
            builder = builder
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV2State>("sushiswap_v2", tvl_filter.clone(), None)
                .exchange::<PancakeswapV2State>("pancakeswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("pancakeswap_v3", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>("vm:balancer_v2", tvl_filter.clone(), Some(balancer_v2_pool_filter))
                .exchange::<UniswapV4State>("uniswap_v4", tvl_filter.clone(), None)
                .exchange::<EkuboState>("ekubo_v2", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>("vm:curve", tvl_filter.clone(), Some(curve_pool_filter))
                .exchange::<UniswapV4State>("uniswap_v4_hooks", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>("vm:maverick_v2", tvl_filter.clone(), None);
        }
        Chain::Base => {
            builder = builder
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV4State>("uniswap_v4", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("pancakeswap_v3", tvl_filter.clone(), None)
                .exchange::<AerodromeSlipstreamsState>("aerodrome_slipstreams", tvl_filter.clone(), None)
        }
        Chain::Unichain => {
            builder = builder
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV4State>("uniswap_v4", tvl_filter.clone(), None)
        }
        _ => {}
    }
    builder
}
```
{% endcode %}
{% endhint %}

### VM v.s. Native

There are two types of implementations:

* **Native** protocols have been implemented using an analytical approach and are ported to Rust - faster simulation.
* **VM** protocols execute the VM bytecode locally - this is easier to integrate the more complex protocols, however has slower simulation times than a native implementation.

Interested in adding a protocol? Refer to the [Tycho Simulation for DEXs](../for-dexs/protocol-integration/) documentation for implementation guidelines.
