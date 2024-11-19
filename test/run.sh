set -xe

# Compile the client and server
make

# Run the server in the background
./out/server.o &

# Give the server some time to start
sleep 1

# Run the client
./out/client.o