# Substreams Testing

We know testing your Substreams modules can be a pain. So, our goal here is to provide a quick and easy way to run end-to-end tests.

Our script will build the `.spkg` for your Substreams module, index the specified block range, and check if the expected state has been correctly indexed in PostgreSQL.

## How to Test

Here's what you need to do:

1. Get the latest version of our indexer.
2. Define your tests and expected state.
3. Run the testing script.

### Get the Latest Version of Tycho (Indexer)

We don't have a direct download link yet. Please reach out to us to get the latest version. Once you have it, place it in the `/testing/` folder.

### Define Your Tests

Define all your tests in a `yaml` file. You can find a template in `substreams/ethereum-template/test_assets.yaml`.

You'll need to:

- Point to the target substreams config file.
- Specify the expected protocol types.
- Define your tests.

For each test, the script will index all blocks between `start-block` and `stop-block` and check that the indexed state matches the expected state.

### Run the Script

Once everything is set up, run our script using the CLI.

First, you need a local postgres database

```bash
docker-compose up -d db
```

Then export an environment variable for RPC connection

```bash
export RPC_URL=your-chain-rpc
```

And finally run the testing script

```bash
python testing/cli.py --test_yaml_path "./substreams/your-substreams-folder/test_assets.yaml"
```

You can get the available CLI flags using `--help`
