#!/bin/bash

set -e

GDB_VERSION=14.1
apt install -y libgmp-dev libmpfr-dev libpython3-dev
wget https://sourceware.org/pub/gdb/releases/gdb-$GDB_VERSION.tar.gz
tar zxf gdb-$GDB_VERSION.tar.gz
cd gdb-$GDB_VERSION
./configure --with-python=$(which python3)
make
make install
cd ..
# TODO: is this necessary?
# rm -r gdb-$GDB_VERSION.tar.gz gdb-$GDB_VERSION
