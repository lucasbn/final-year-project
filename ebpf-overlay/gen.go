package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -I/usr/include/aarch64-linux-gnu -g -Wall -target bpf" overlay src/overlay.bpf.c
