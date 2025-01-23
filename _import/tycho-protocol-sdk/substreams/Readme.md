# Substreams Indexing Integrations

Please refer to the official [Substreams Indexing](https://docs.propellerheads.xyz/tycho/for-dexs/protocol-integration-sdk) docs.

## Release

To release a package simply tag a commit with the package name and its version: 
e.g. `ethereum-balancer-0.1.0`. This will create a release and automatically build 
and push the spkg into our registry.

### Note
The CD pipeline will error if the Cargo version is not the same as the version in 
the tag.

Releases are immutable so do not try to delete tags or build the same release twice 
since this will error.

### Pre-release

To create a pre-release for testing in dev you can start CD pipeline manually supplying 
the package you'd like to pre-release. This will create a 
`[package].pre-[commit-sha]` release in our spkg repository which you can use 
to run the substream´.

For forked protocols you'll need to also supply the config file name, e.g. `ethereum-pancakeswap`.

## Test your implementation

To run a full end-to-end integration test you can refer to the [testing script documentation](../testing/README.md).
