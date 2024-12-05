ip netns delete red
ip link set bridge-main down
ip link delete bridge-main type bridge
ip link delete vxlan-red
iptables -t filter -D FORWARD -i bridge-main -j ACCEPT
