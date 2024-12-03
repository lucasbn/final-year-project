#!/bin/bash

set -o errexit
set -o nounset

# Create a network namespace called 'red'
ip netns add red

# Create a veth pair ('red-in' and 'red-out') and move 'red-in' into the red namespace
ip link add red-in type veth peer name red-out
ip link set red-in netns red

# Configure the IP address and bring up the 'red-in' interface
ip netns exec red ip addr add 10.0.0.4/16 dev red-in
ip netns exec red ip link set red-in up

# Create a linux bridge on the host and assign an IP address to it
ip link add bridge-main type bridge
ip addr add 10.0.0.1/16 dev bridge-main
ip link set red-out master bridge-main
ip link set red-out up
ip link set bridge-main up

# Add a default route in the red namespace through the bridge
ip netns exec red ip route add default via 10.0.0.1

# Create a VXLAN tunnel interface to connect to host 2
ip link add vxlan-red type vxlan id 100 local 192.168.228.131 remote 192.168.228.132 dev eth0 dstport 4789

# Attach vxlan-red to the bridge
ip link set vxlan-red master bridge-main
ip link set vxlan-red up



