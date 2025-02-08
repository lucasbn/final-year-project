#!/bin/bash

# Exit on error
set -e

# Delete namespaces
ip netns del ns1 || true
ip netns del ns2 || true

# Delete bridge
ip link del br0 || true

# Delete any remaining veth interfaces
ip link del veth1 || true
ip link del veth2 || true
ip link del br-veth1 || true
ip link del br-veth2 || true

echo "Network teardown complete."
