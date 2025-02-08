#!/bin/bash

# Exit on error
set -e

# Create namespaces
ip netns add ns1
ip netns add ns2

# Create veth pairs
ip link add veth1 type veth peer name br-veth1
ip link add veth2 type veth peer name br-veth2

# Create the bridge
ip link add name br0 type bridge
ip link set br0 up

# Attach veth peers to the bridge
ip link set br-veth1 master br0
ip link set br-veth2 master br0

# Move veth interfaces to namespaces
ip link set veth1 netns ns1
ip link set veth2 netns ns2

# Assign IP addresses inside namespaces
ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2

# Bring up interfaces inside namespaces
ip netns exec ns1 ip link set veth1 up
ip netns exec ns2 ip link set veth2 up

# Bring up veth interfaces connected to bridge
ip link set br-veth1 up
ip link set br-veth2 up

# Enable loopback interfaces inside namespaces
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up

# Enable forwarding
iptables -A FORWARD -i br0 -o br0 -j ACCEPT

# Test connectivity
echo "Testing connectivity..."
ip netns exec ns1 ping -c 3 10.0.0.2

echo "Setup complete."
