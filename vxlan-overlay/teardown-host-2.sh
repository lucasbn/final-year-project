ip netns delete blue
ip link set bridge-main down
ip link delete bridge-main type bridge
ip link delete vxlan-blue
