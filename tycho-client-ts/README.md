# Tycho TypeScript Client

A TypeScript client for interacting with the Tycho indexer service.

## Features

- RPC Client: Interact with the Tycho RPC server to query various blockchain data, including protocol components,
  states, contract states, and tokens.
- Streaming: Stream real-time data using the Tycho client binary, allowing for efficient monitoring and processing of
  live data.

## Installation

```bash
npm install tycho-client-ts
# or
yarn add tycho-client-ts
```

## Usage

### RPC Client

The TychoRPCClient class allows you to interact with the Tycho RPC server. You can query for protocol components,
protocol states, contract states, and tokens.

#### Example

```ts
import { TychoRPCClient } from "../src/rpc-client";
import { Chain } from "../src/dto";

async function rpcExample() {
  const client = new TychoRPCClient({
    rpcUrl: "http://localhost:4242",
    authToken: "sometoken",
    chain: Chain.Ethereum,
  });

  try {
    // Query protocol components
    const components = await client.getProtocolComponents({
      protocol_system: "uniswap_v2",
    });
    console.log("Protocol components:", components);

    // Query protocol state
    const state = await client.getProtocolState({
      protocol_system: "uniswap_v2",
      include_balances: true
    });
    console.log("Protocol state:", state);

    // Query contract state
    const contractState = await client.getContractState({});
    console.log("Contract state:", contractState);

    // Query tokens
    const tokens = await client.getTokens({});
    console.log("Tokens:", tokens);
  } catch (error) {
    console.error("RPC error:", error);
  }
}

rpcExample();
```

### Streaming

The TychoStream class allows you to start the Tycho client binary and stream data asynchronously.

#### Example

```ts
import { TychoStream } from '../src/stream';
import { Chain } from '../src/dto';

async function streamExample() {
  const stream = new TychoStream({
    tychoUrl: "localhost:4242",
    authToken: "sometoken",
    exchanges: ["uniswap_v2", "uniswap_v3"],
    blockchain: Chain.Ethereum,
    includeState: true,
    minTvl: 1000000, // $1M TVL
  });

  try {
    await stream.start();
    
    for await (const message of stream) {
      console.log('Received message:', message);
    }
  } catch (error) {
    console.error('Stream error:', error);
  }
}

streamExample();
```
