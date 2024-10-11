# Tycho Core

This tycho-core crate defines all core models used across the various Tycho services. This crate encapsulates the core models only, separate from the database storage models, which are located in the [tycho-storage](../tycho-storage/) crate.

The core models in this crate are grouped based on their use case:
- Internal Models: These models represent the underlying structures used by Tycho's internal services.
- Message Models: These Data Transfer Objects (DTOs) facilitate communication between the server and clients.

## Internal Models

The internal models are located in the [models](./src/models/) module. These structs capture the detailed, low-level data structures that underpin the internal logic of Tycho services. They are designed to be highly granular to support the complex operations within Tycho.

## Message Models

The message models, also known as DTOs, are found in [dto.rs](./src/dto.rs). These structs serve to serialise and deserialise messages between server and client. Unlike internal models, DTOs are intentionally kept simple, focusing solely on data representation without embedding business logic.

### Encoding Standards

Most fields within the message models are encoded using hex bytes. Some useful tools for serialising and deserialising structs containing hex bytes are provided in [serde_primitives](./src/serde_primitives.rs). 

Note: while encoding specifics may vary depending on the protocol, integers are generally encoded in big-endian format.