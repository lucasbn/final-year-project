#!/bin/bash

set -o errexit
set -o nounset

# Setup

if ! findmnt /sys/fs/bpf > /dev/null; then
  mount -t bpf none /sys/fs/bpf
fi

bpftool prog loadall \
        redirect.bpf.o \
        /sys/fs/bpf \
        pinmaps /sys/fs/bpf

bpftool prog attach \
        pinned /sys/fs/bpf/sk_msg_prog \
        sk_msg_verdict \
        pinned /sys/fs/bpf/sock_map

bpftool cgroup attach \
        /sys/fs/cgroup/ \
        cgroup_sock_ops \
        pinned /sys/fs/bpf/sockops_prog