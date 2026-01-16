# Custom protobuf models

In some cases, you may need to create custom intermediate protobuf messages, especially when facilitating communication between Substreams handler modules or storing additional data in stores.

Place these protobuf files within your Substreams package, such as `./substreams/ethereum-template/proto/custom-messages.proto`. Be sure to link them in the `substreams.yaml` file. For more details, refer to the substreams [manifest documentation](https://docs.substreams.dev/reference-material/substreams-components/manifests) or review the official Substreams [UniswapV2](https://github.com/messari/substreams/blob/master/uniswap-v2/substreams.yaml#L20-L22) example integration.
