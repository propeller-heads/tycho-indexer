# Tycho Substreams SDK

Some shared functionality that is used to create tycho substream packages.

## Protobuf Models

Protobuf models are manually synced from the `tycho-indexer` repository whenever they 
changed.

To generate the rust structs run the following command from within the `./proto` 
directory:

```bash
buf generate \
  --path tycho \
  --template ../substreams/crates/tycho-substreams/buf.gen.yaml \
  --output ../substreams/crates/tycho-substreams/ 
```