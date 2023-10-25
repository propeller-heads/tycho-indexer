#!/usr/bin/env sh
# USAGE:
# sudo ./protosim_py/build_protosim_wheel.sh
#
# Should be executed from a repo root.
# The `chmod` command must be executed as a root user, that's why we need sudo. The wheel produced by docker image
# is owned by a root user, so we must change its permissions to use it. 

mkdir -p ./protosim_py/target/wheels/
docker build -t protosim_py_build -f protosim_py/protosim_py.Dockerfile .
docker run -v .:/prop-builder protosim_py_build
chmod -R 777 ./protosim_py/target/wheels/

# Do this if you want to publish the wheel. Note that CI uses this file!
# aws s3 cp ./protosim_py/target/wheels/protosim_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl s3://defibot-data/protosim_py-0.1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl