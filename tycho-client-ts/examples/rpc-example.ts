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
