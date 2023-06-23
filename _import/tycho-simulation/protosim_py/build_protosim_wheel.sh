#!/usr/bin/env sh
# Should be executed from a repo root
docker build -t protosim_py_build -f protosim_py/protosim_py.Dockerfile .
docker run -v .:/prop-builder protosim_py_build
