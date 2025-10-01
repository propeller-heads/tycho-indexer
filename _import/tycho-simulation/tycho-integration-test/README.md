Continuously simulate swaps in all chains and protocols. By default, the binary tests the ethereum chain.

## How to run

```bash
export RPC_URL=...
cargo run --package tycho-integration-test
```

docker build -f Dockerfile.integration-test -t tycho-integration-test .

docker run -e RPC_URL=https://eth-mainnet.g.alchemy.com/v2/OTD5W7gdTPrzpVot41Lx9tJD9LUiAhbs RUST_LOG=info
tycho-integration-test

docker tag tycho-integration-test 120569639765.dkr.ecr.eu-central-1.amazonaws.com/tycho-integration-test:0.1.0

aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin
120569639765.dkr.ecr.eu-central-1.amazonaws.com
docker push 120569639765.dkr.ecr.eu-central-1.amazonaws.com/tycho-integration-test:0.1.0

docker build --platform linux/amd64 -f Dockerfile.integration-test -t
120569639765.dkr.ecr.eu-central-1.amazonaws.com/tycho-integration-test:0.1.0