# Technical Documentation

This section provides detailed technical documentation for developers and advanced users who want to understand the inner workings of Tycho, contribute to its development, or customize it for specific needs.

## What You’ll Find Here
This technical documentation is structured to guide you through the various components, concepts, and functionalities of Tycho. Whether you are looking to contribute to the project, deploy a self-hosted instance, or simply understand how Tycho works under the hood, the resources here will help you achieve your goals.

### Indexer
Tycho Indexer is the central component of the Tycho system, responsible for collecting, processing and aggregating on-chain data. It manages the flow of data, ensuring that it is efficiently processed and stored in the database, while also emitting it to subscribers in real time. The indexer operates the primary services offered by Tycho, including the WebSocket stream for live updates and the RPC interface for querying historical data.

Learn more about how the Tycho Indexer works and its services:

[Tycho Indexer](./technical/tycho-indexer.md)

### Core Structs
Understand the detailed models and structs used throughout Tycho, including the message formats emitted by the various services. This section covers the foundational data structures that enable Tycho to handle protocol state updates, queries, and client interactions.

Explore the core models and structs here:

[Tycho Core](./technical/tycho-core.md)

### Database Storage
Tycho's Database Storage system is critical for managing protocol state data. This section provides comprehensive documentation on the database schema and gateway controls. You’ll also find information on how Tycho stores, retrieves, and maintains historical state data, making it easy to query both real-time and historical information.

Access the database storage documentation here:

[Tycho Storage](./technical/tycho-storage.md)

### Clients
Tycho offers client libraries to simplify the interaction with the indexing system, allowing users to connect to the WebSocket service or make RPC requests without having to manage low-level details themselves.

- Tycho Rust Client: The Rust client offers a convenient CLI application for interacting with Tycho. All functionality is also available as a Rust library for integration into other applications.

    Learn more about the Rust client here:

    [Tycho Client](./technical/tycho-client.md)

- Tycho Python Client: For Python developers, the Python client library enables seamless interaction with the Tycho RPC server and WebSocket streams, offering an intuitive way to integrate Tycho’s data into Python-based applications.

    Explore the Python client here:

    [Tycho Python Client](./technical/tycho-client-py.md)
