CC_BPF ?= clang
LIBBPF_HEADERS := ../external/libbpf/src/install-dir/usr/include
CFLAGS_BPF ?= -I$(LIBBPF_HEADERS) -I/usr/include/aarch64-linux-gnu -Wall -Wextra -Werror -ggdb

%.bpf.o: %.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -O2 -target bpf -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all clean

all: redirect.bpf.o

clean:
	rm -f *.bpf.o