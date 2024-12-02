#!/bin/bash

set -o errexit
set -o nounset

# Create a network namespace called 'blue'
ip netns add blue

# Create a veth pair ('blue-in' and 'blue-out') and move 'blue-in' into the blue namespace
ip link add blue-in type veth peer name blue-out
ip link set blue-in netns blue

# Configure the IP address and bring up the 'blue-in' interface
ip netns exec blue ip addr add 10.0.0.5/16 dev blue-in
ip netns exec blue ip link set blue-in up

# Create a linux bridge on the host and assign an IP address to it
ip link add bridge-main type bridge
ip addr add 10.0.0.6/16 dev bridge-main
ip link set blue-out master bridge-main
ip link set blue-out up
ip link set bridge-main up

# Add a default route in the blue namespace through the bridge
ip netns exec blue ip route add default via 10.0.0.6

# Create a VXLAN tunnel interface to connect to host 2
ip link add vxlan-blue type vxlan id 100 local 192.168.228.132 remote 192.168.228.131 dev eth0

# Attach vxlan-blue to the bridge
ip link set vxlan-blue master bridge-main
ip link set vxlan-blue up



