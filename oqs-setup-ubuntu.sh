#!/bin/bash

# install dependencies
echo Installing dependencies...
sudo apt install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

# clone, build (static) and install liboqs
echo Building and installing liboqs...
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install

# clone, build (static) and install oqsprovider
echo Building and installing oqsprovider
cd ../..
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir build && cd build
cmake .. -DOQS_PROVIDER_BUILD_STATIC=ON
cmake --build .
sudo cmake --install .

