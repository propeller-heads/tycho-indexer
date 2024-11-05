#!/usr/bin/env sh
# USAGE:
# sudo ./tycho_simulation_py/build_tycho_simulation_wheel.sh
#
# Should be executed from a repo root.
# The `chmod` command must be executed as a root user, that's why we need sudo. The wheel produced by docker image
# is owned by a root user, so we must change its permissions to use it. 

mkdir -p ./tycho_simulation_py/target/wheels/
docker build -t tycho_simulation_py_build -f tycho_simulation_py/tycho_simulation_py.Dockerfile .
docker run -v $(pwd):/prop-builder tycho_simulation_py_build
chmod -R 777 ./tycho_simulation_py/target/wheels/

# Do this if you want to publish the wheel. Note that CI uses this file!
# aws s3 cp ./tycho_simulation_py/target/wheels/tycho_simulation_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl s3://defibot-data/tycho_simulation_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl