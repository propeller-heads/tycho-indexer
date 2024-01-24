# ABIs

`get_abis.py` is a simple python script using the etherscan API (free plan) to gather ABIs for all of the contracts we are tracking!

We then can define all of the abis via `substreams_ethereum::Abigen::new` in our `build.rs`.

## Recommendation

It would be apt to convert (maybe through copilot) the python code into the `build.rs` file and then automate the `Abigen` functionality.
