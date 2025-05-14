#!/bin/bash

# invoke ubuntu build script for oqs
./oqs-setup-ubuntu.sh

# build this project
mkdir build
cd build
cmake ..
cmake --build .
