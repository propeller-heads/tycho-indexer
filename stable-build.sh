# This is a workaround for building all binaries of 
# the workspaces until "per_package_target" features is 
# stabilised.
set -e

SUBSTREAM_PKGS=$(cargo ws list | grep -i substreams | grep -v -e substreams-common -e substreams-helper)
WORKDIR=$(pwd)
TYCHO_INDEXER=tycho-indexer
TYCHO_CLIENT=tycho-client

for PACKAGE in $SUBSTREAM_PKGS
do
   echo "Building wasm package: $PACKAGE"
   cargo build --package $PACKAGE --target wasm32-unknown-unknown --profile substreams

   YAML_PATH=$(echo $PACKAGE | sed 's/-/\//1' )/substreams.yaml
   echo "Packaging into spkg using $YAML_PATH:"
   substreams pack $YAML_PATH
done

echo "Building tycho: $TYCHO_INDEXER"
cargo build --package $TYCHO_INDEXER --release

echo "Building tycho-client: $TYCHO_CLIENT}"
cargo build --package $TYCHO_CLIENT --release