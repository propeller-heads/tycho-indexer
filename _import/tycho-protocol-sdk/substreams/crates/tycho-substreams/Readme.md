# Tycho Substreams SDK

Some shared functionality that is used to create tycho substream packages.

## Protobuf Models

To generate the rust structs run the following command from within the root
directory:

```bash
buf generate --template substreams/crates/tycho-substreams/buf.gen.yaml --output substreams/crates/tycho-substreams/
```
