#!/bin/bash

set -o errexit
set -o nounset

# Compile the client and server
make > /dev/null

# Run the server in the background
./out/server.o &

# Give the server some time to start
sleep 1

# Run the client
echo "Running tests without TCP bypasser..."
./out/client.o

# Load the TCP bypasser eBPF program
cd ../tcp-bypasser && ./load.sh > /dev/null && cd ../evaluate

# Run the server in the background
./out/server.o &

# Give the server some time to start
sleep 1

# Run the client
echo "Running tests with TCP bypasser..."
./out/client.o

# Unload the TCP bypasser eBPF program
cd ../tcp-bypasser && ./unload.sh > /dev/null 2>&1 && cd ../evaluate