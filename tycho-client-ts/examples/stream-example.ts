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