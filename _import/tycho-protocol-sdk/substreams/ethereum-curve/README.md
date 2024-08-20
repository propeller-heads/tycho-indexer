# Instructions

The run command for our substream is a little different here due to the inclusion of the dynamic parameters for manually
admitted pools.

This command will add extra parameters to the `map_components` module via the `python params.py` script. This embeds
directly in the bash/zsh compatible command here. If `python` is not ideal, the script can be easily converted into
`bash` but it would require the `jq` executable (I've used AI to convert it just fine in testing).

```bash
$ substreams run -e mainnet.eth.streamingfast.io:443 substreams.yaml map_protocol_changes --start-block 11507454 --stop-block +100 -p map_components=`python params.py`
```

## `params.json`

This json file is a top-level array containing objects that describe a specific `ProtocolComponent`. Each object
contains the following fields:

- `name`: Just for documentation purposes
- `address`: The **lowercase** address of the component
- `tx_hash`: The hash of the transaction where the component was emitted
- `tokens`: A list of token addresses ordered in the exact same way as the Pool
- `static_attributes`: A nested object of key to value that represents the static attributes of the component.
- `attributes`: A nested object of key to value that represents attributes.

Please see the included 3 examples for `3pool`, `steth`, and `tricrypto2`.
