# How to Run

## Prerequisites

Before continuing, ensure the following tools and libraries are installed on your system:

* [Docker](https://www.docker.com/): Containerization platform for running applications in isolated environments.
* [Conda](https://conda.io/projects/conda/en/latest/user-guide/install/index.html): Package and environment manager for Python and other languages.
* [AWS CLI](https://aws.amazon.com/cli/): Tool to manage AWS services from the command line.
* [Git](https://git-scm.com/): Version control tool
* [Rust](https://www.rust-lang.org/): Programming language and toolchain
* [GCC](https://gcc.gnu.org/): GNU Compiler Collection
* [libpq](https://www.postgresql.org/docs/9.5/libpq.html): PostgreSQL client library
* [OpenSSL (libssl)](https://github.com/openssl/openssl): OpenSSL development library
* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/): Helper tool for managing compiler flags
* [pip](https://pip.pypa.io/): Python package installer

### Archive node

The testing system relies on an EVM **Archive** node to fetch the state from a previous block. Indexing only with Substreams, as done in Tycho's production mode, requires syncing blocks since the protocol's deployment date, which can take a long time. The node skips this requirement by fetching all the required account's storage slots on the block specified in the testing `yaml`file.&#x20;

The node also needs to support the [debug\_storageRangeAt](https://www.quicknode.com/docs/ethereum/debug_storageRangeAt) method, as it's a requirement for our Token Quality Analysis.

### Tycho Indexer

#### Verify the current version

The testing module runs a minified version of [Tycho Indexer](https://github.com/propeller-heads/tycho-indexer). You can ensure that the latest version is correctly setup in your PATH by running the following command on your terminal:

```bash
> tycho-indexer --version
tycho-indexer 0.62.0 # should match the latest version published on GitHub
```

#### Installing or updating the version (Optional)

If the command above does not provide the expected output, you need to (re)install Tycho.

{% tabs %}
{% tab title="Build locally (recommended)" %}
If you're running on a **MacOS** (either Apple Silicon or Intel) - or any architecture that is not supported by pre-built releases, you need to compile the Tycho Indexer:

**Step 1: Clone Tycho-Indexer repo**&#x20;

```bash
git clone git@github.com:propeller-heads/tycho-indexer.git
cd tycho-indexer
```

**Step 2: Build the binary in release mode**&#x20;

```bash
cargo build --release --bin tycho-indexer
```

**Step 3: Link the binary to a directory in your system's PATH:**

```bash
sudo ln -s $(pwd)/target/release/tycho-indexer /usr/local/bin/tycho-indexer
```

> **NOTE**: This command requires `/usr/local/bin` to be included in the system's `PATH.` While this is typically the case, there may be exceptions.
>
> If `/usr/local/bin` is not in your `PATH`, you can either:
>
> 1.  Add it to your `PATH` by exporting it:
>
>     ```sh
>     export PATH="/usr/local/bin:$PATH"
>     ```
> 2. Or create a symlink in any of the following directories (if they are in your `PATH`):
>
> ```bash
> /bin
> /sbin
> /usr/bin
> /usr/sbin
> /usr/local/bin
> /usr/local/sbin
> ```

**Step 4: Verify Installation**

```bash
> tycho-indexer --version
tycho-indexer 0.54.0 # should match the latest version published on GitHub
```
{% endtab %}

{% tab title="Pre-built release (Linux AMD only)" %}
We provide a binary compiled for Linux x86/x64 architecture on our GitHub [releases](https://github.com/propeller-heads/tycho-indexer/releases) page.

{% hint style="warning" %}
This method will only work if you are running on a Linux with an x86/x64 architecture&#x20;
{% endhint %}

**Step 1: Download the pre-built binary**

Navigate to the [Tycho Indexer Releases](https://github.com/propeller-heads/tycho-indexer/releases) page, locate the latest version (e.g.: `0.54.0)` and download the `tycho-indexer-x86_64-unknown-linux-gnu-{version}.tar.gz` file.

**Step 2:  Extract the binary from the tar.gz**

Open a terminal and navigate to the directory where the file was downloaded. Run the following command to extract the contents:

```bash
tar -xvzf tycho-indexer-x86_64-unknown-linux-gnu-{version}.tar.gz
```

**Step 3: Link the binary to a directory in your system's PATH:**

```bash
// Ensure the binary is executable:
sudo chmod +x tycho-indexer
// Create symlink
sudo ln -s $(pwd)/tycho-indexer /usr/local/bin/tycho-indexer
```

> NOTE: This command requires `/usr/local/bin` to be included in the system's `PATH.` While this is typically the case, there may be exceptions.
>
> If `/usr/local/bin` is not in your `PATH`, you can either:
>
> 1.  Add it to your `PATH` by exporting it:
>
>     ```sh
>     export PATH="/usr/local/bin:$PATH"
>     ```
> 2. Or create a symlink in any of the following directories (if they are in your `PATH`):
>
> ```bash
> /bin
> /sbin
> /usr/bin
> /usr/sbin
> /usr/local/bin
> /usr/local/sbin
> ```

**Step 4: Verify Installation**

```bash
> tycho-indexer --version
tycho-indexer 0.54.0 # should match the latest version published on GitHub
```
{% endtab %}
{% endtabs %}

## Test Configuration

Tests are defined in a `yaml` file. A documented template can be found at [`substreams/ethereum-template/integration_test.tycho.yaml`](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/substreams/ethereum-template-factory/integration_test.tycho.yaml). The configuration file should include:

* The target Substreams config file.
* The corresponding SwapAdapter and args to build it.
* The expected protocol types.
* The tests to be run.

Each test will index all blocks between `start-block` and `stop-block`, verify that the indexed state matches the expected state, and optionally simulate transactions using the provided `SwapAdapter`. For more details on the individual test-level configs, see [here](./#test-configuration).

You will also need the VM Runtime file for the adapter contract. Our testing script should be able to build it using your test config. The script to generate this file manually is available under [`evm/scripts/buildRuntime.sh`](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/evm/scripts/buildRuntime.sh).

## Setup testing environment

To set up your test environment, run the [setup environment script](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/testing/setup_env.sh). It will create a Conda virtual env and install all the required dependencies.

```bash
./setup_env.sh
```

This script must be run from within the `tycho-protocol-sdk/testing` directory.

Lastly, you need to activate the conda env:

```bash
conda activate tycho-protocol-sdk-testing
```

## Running Tests

### Step 1: Export Environment Variables

Export the required environment variables for the execution. You can find the available environment variables in the `.env.default` file. Please create a `.env` file in the `testing` directory and set the required environment variables.

#### **Environment Variables**

**RPC\_URL**

* **Description**: The URL for the Ethereum RPC endpoint. This is used to fetch the storage data.&#x20;

{% hint style="warning" %}
The node needs to be an archive node and support [debug\_storageRangeAt](https://www.quicknode.com/docs/ethereum/debug_storageRangeAt) method.
{% endhint %}

* **Example**: `export RPC_URL="https://ethereum-mainnet.core.chainstack.com/123123123123"`

**SUBSTREAMS\_API\_TOKEN**

* **Description**: The JWT token for accessing Substreams services. This token is required for authentication. Please refer to [Substreams Authentication](https://docs.substreams.dev/reference-material/substreams-cli/authentication) guide to setup and validate your token.
* **Example**: `export SUBSTREAMS_API_TOKEN=eyJhbGci...`

### Step 2: Set up tests

If you do not have one already, you must build the wasm file of the package you wish to test. This can be done by navigating to the package directory and running:

```bash
cargo build --target wasm32-unknown-unknown --release
```

Then, run a local Postgres test database using docker-compose.

```bash
docker compose -f ./testing/docker-compose.yaml up -d db
```

### Step 3: Run tests

Run tests for your package. This must be done from the main project directory.

```bash
python ./testing/src/runner/cli.py --package "your-package-name"
```

**Example**

If you want to run tests for `ethereum-balancer-v2`, use:

<pre class="language-bash"><code class="lang-bash"><strong>// Activate conda environment
</strong><strong>conda activate tycho-protocol-sdk-testing
</strong><strong>
</strong>// Setup Environment Variables
export RPC_URL="https://ethereum-mainnet.core.chainstack.com/123123123123"
export SUBSTREAMS_API_TOKEN=eyJhbGci...

// Build Substreams wasm for BalancerV2
cd substreams
cargo build --release --package ethereum-balancer-v2 --target wasm32-unknown-unknown
cd ..

// Run Postgres DB using Docker compose
docker compose -f ./testing/docker-compose.yaml up -d db

// Run the testing file
python ./testing/src/runner/cli.py --package "ethereum-balancer-v2"
</code></pre>

**Testing CLI args**

A list and description of all available CLI args can be found using:

```bash
python ./testing/src/runner/cli.py --help
```

{% hint style="info" %}
For enhanced debugging, running the testing module with the --tycho-logs flag is recommended. It will enable Tycho-indexer logs
{% endhint %}
