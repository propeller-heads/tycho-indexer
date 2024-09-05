# Tycho as a Service

Tycho offers a powerful and flexible service that allows users to access real-time updates and historical data for onchain financial protocols. You can interact with Tycho through WebSocket connections and RPC requests, either directly or by using our provided client libraries.

## Overview

Tycho as a service is designed for users who prefer a managed solution with minimal setup. By subscribing to our service, you gain access to live protocol state updates via WebSocket streams and can make historical queries through our RPC interface. This managed approach frees you from the complexities of deploying and maintaining the infrastructure, allowing you to focus on integrating Tycho’s data into your applications.

## Using the Client Libraries

We provide convenient client libraries that abstract away the complexities of managing and correctly utilising the various Tycho services.

### Key Features
- **Easy start up**: the client automatically queries and supplies the full states of the protocol components of interest at startup and subscribes for subsequent updates. Updates emitting while waiting for the initial states are buffered and emitted when appropriate.
- **Built-in filtering**: the client provides an easy means to filter for protocol components of interest through the use of a TVL threshold. Real-time TVL monitoring is conducted and components that newly pass the threshold are automatically fetched and propogated to the user. 
- **Synchronisation**: In the case that multiple protocols are subscribed to, the client automates synchronising the messages retrieved for each protocol, emitting a single combined message per block.

### Rust Crate
The Rust client library (`tycho-client`) allows you to connect, authenticate, and subscribe to protocol updates with minimal setup through an easy-to-use command line interface. All client functionality is also available as a Rust library. For more details, see the [Tycho Rust Client](./technical/tycho-client.md) section.

### Python Library
The Python client library (tycho-client-py) offers similar functionality, making it easy to integrate Tycho into Python applications. For more details, see the [Tycho Python Client](./technical/tycho-client-py.md) section.

By using these libraries, you can streamline your integration process and focus on processing the data rather than managing connections and filters.

## Connecting Directly

You can bypass the use of the clients and connect directly to Tycho. This approach requires you to manually handle filtering, message synchronization, and querying of full states when necessary.

### WebSocket Connection

To connect directly to the Tycho WebSocket service:

- **Establish a Connection**: Use your preferred WebSocket client to connect to the Tycho WebSocket endpoint.
- **Endpoint URL**: [TODO: update this]
- **Authenticate**: Provide your API key as part of the connection request headers.
- **Subscribe to Updates**: Once connected, subscribe to the protocol components you are interested in by sending a subscription message.
- **Handle Updates**: Your application will receive real-time updates as they occur, which can be processed according to your business logic.

### RPC Interface

The Tycho RPC interface allows you to query historical protocol states at any given block or timestamp. This is useful for new connections to retrieve full protocol states to subsequently apply updates to, or to fetch token data or contract code.

To make RPC requests directly:

- **Endpoint URL**: [TODO: update this]
- **Authenticate**: Include your API key in the request headers.
- **RPC Methods**: Utilize available RPC methods to query historical data. For example, you can request the state at a specific block number or timestamp, or request a list of pools filtered by TVL.
- **Handle Responses**: The responses will include the requested data, which you can then integrate into your application.

For more detailed technical information, please refer to our [Services](./technical/tycho-indexer.md#service) technical documentation.