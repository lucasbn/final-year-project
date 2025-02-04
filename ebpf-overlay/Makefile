LIBBPF_HEADERS := ../external/libbpf/src/install-dir/usr/include
LIBBPF_SOURCE  := ../external/libbpf/src/install-dir/usr/lib64
CFLAGS_BPF ?= -I$(LIBBPF_HEADERS) -I/usr/include/aarch64-linux-gnu -Wall -Wextra -Werror -ggdb
CC_BPF ?= clang

DRIVER := driver
BPF_PROG := overlay.bpf.o
BUILD_DIR := build

all: $(DRIVER) $(BPF_PROG)

$(BUILD_DIR)/driver.o: src/driver.cpp
	mkdir -p $(BUILD_DIR)
	g++ $(CFLAGS_BPF) -c $< -o $@

$(DRIVER): $(BUILD_DIR)/driver.o
	mkdir -p $(BUILD_DIR)
	g++ -o build/$@ $^ $(LIBBPF_SOURCE)/libbpf.a -lelf -lz

$(BPF_PROG): src/overlay.bpf.c
	mkdir -p $(BUILD_DIR)
	clang -target bpf $(CFLAGS_BPF) -O2 -c $^ -o $(BUILD_DIR)/$(BPF_PROG)

clean:
	rm -f *.bpf.o