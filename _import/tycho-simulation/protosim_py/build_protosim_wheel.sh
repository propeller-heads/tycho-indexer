#!/usr/bin/env sh
# USAGE:
# sudo ./protosim_py/build_protosim_wheel.sh
#
# Should be executed from a repo root.
# The last command must be executed as a root user, that's why we need sudo. The wheel produced by docker image
# is owned by a root user, so we must change its permissions to use it. 

docker build -t protosim_py_build -f protosim_py/protosim_py.Dockerfile .
docker run -v .:/prop-builder protosim_py_build
chmod -R 777 ./protosim_py/target/wheels/