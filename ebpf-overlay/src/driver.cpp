#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <unistd.h>

extern "C" {
    #include "common.h"
}

int main() {
    // Seed random number generator
    std::srand(std::time(nullptr));

    // Open BPF object
    struct bpf_object *obj = bpf_object__open("build/overlay.bpf.o");
    if (!obj) {
        std::cerr << "Failed to open BPF object" << std::endl;
        return 1;
    }

    // Load and verify BPF programs
    if (bpf_object__load(obj) != 0) {
        std::cerr << "Failed to load BPF object" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    // Get map file descriptor
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ip_port_map");
    if (!map) {
        std::cerr << "Failed to find ip_port_map map" << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    int map_fd = bpf_map__fd(map);


    struct ip_port_pair key = {
        .ip = 1,
        .port = 1,
    };

    struct ip_port_pair value = {
        .ip = 2,
        .port = 2,
    };

    // Insert mapping into the map
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        std::cerr << "Failed to update map" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    while (true) {
        sleep(60);
    }

    // Cleanup
    bpf_object__close(obj);

    return 0;
}