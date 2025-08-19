# Supported Protocols

Currently, Tycho supports the following protocols:

<table><thead><tr><th width="147.09765625">Protocol</th><th width="258.85546875">Integration Type</th><th width="184.73828125">Simulation Time</th><th width="200.87109375">Chains</th></tr></thead><tbody><tr><td><code>uniswap_v2</code></td><td>Native (<code>UniswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum, Base, Unichain</td></tr><tr><td><code>uniswap_v3</code></td><td>Native (<code>UniswapV3State</code>)</td><td>20 μs (0.02 ms)</td><td>Ethereum, Base, Unichain</td></tr><tr><td><code>uniswap_v4</code></td><td>Native (<code>UniswapV4State</code>)</td><td>3 μs (0.003 ms)</td><td>Ethereum, Base, Unichain</td></tr><tr><td><code>vm:balancer_v2</code></td><td>VM  (<code>EVMPoolState</code>)</td><td>0.5 ms</td><td>Ethereum</td></tr><tr><td><code>vm:curve</code></td><td>VM (<code>EVMPoolState</code>)</td><td>1 ms</td><td>Ethereum</td></tr><tr><td><code>sushiswap_v2</code></td><td>Native (<code>UniswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum</td></tr><tr><td><code>pancakeswap_v2</code></td><td>Native (<code>PancakeswapV2State</code>)</td><td>1 μs (0.001 ms)</td><td>Ethereum</td></tr><tr><td><code>pancakeswap_v3</code></td><td>Native (<code>UniswapV3State</code>)</td><td>20 μs (0.02 ms)</td><td>Ethereum</td></tr><tr><td><code>ekubo_v2</code></td><td>Native (<code>EkuboState</code>)</td><td>1.5 μs (0.0015 ms)</td><td>Ethereum</td></tr></tbody></table>

{% hint style="info" %}
**Live tracker & Upcoming protocols**

* Currently supported protocols and Tycho status: [http://tycho.live/](http://tycho.live/)&#x20;
* [List of upcoming protocols](https://docs.google.com/spreadsheets/d/1vDl57BthpeJ9WDqmCVXFdLLvmsm-_SwhSjVzobXJZ04/edit?usp=sharing)
{% endhint %}

### VM v.s. Native

There are two types of implementations:

* **Native** protocols have been implemented using an analytical approach and are ported to Rust - faster simulation.
* **VM** protocols execute the VM bytecode locally - this is easier to integrate the more complex protocols, however has slower simulation times than a native implementation.

Interested in adding a protocol? Refer to the [Tycho Simulation for DEXs](../for-dexs/protocol-integration/) documentation for implementation guidelines.
