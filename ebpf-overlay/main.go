package main

import (
    "log"
	"net"
	"encoding/binary"
	"github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs overlayObjects 
    if err := loadOverlayObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

	execLink, err := link.Tracepoint("sched", "sched_process_exec", objs.OnProcessExec, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer execLink.Close()

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.OnProcessExit, nil) 
	if err != nil {
		log.Fatal(err)
	}
	defer exitLink.Close()

	bindLink, err := link.Tracepoint("syscalls", "sys_enter_bind", objs.TpSysEnterBind, nil)
    if err != nil {
        log.Fatal("Attaching bind tracepoint:", err)
    }
    defer bindLink.Close()

    connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TpSysEnterConnect, nil)
    if err != nil {
        log.Fatal("Attaching connect tracepoint:", err)
    }
    defer connectLink.Close()

	getSockNameTpLink, err := link.Tracepoint("syscalls", "sys_enter_getsockname", objs.TpSysEnterGetsockname, nil)
    if err != nil {
        log.Fatal("Attaching getsockname tracepoint:", err)
    }
    defer getSockNameTpLink.Close()

	getSockNameKprobeLink, err := link.Kprobe("sys_getsockname", objs.HandleGetsocknameEntry, nil)
	if err != nil {
		log.Fatal("Attaching kprobe to sys_getsockname:", err)
	}
	defer getSockNameKprobeLink.Close()


	// Create an ebpf_namespace with the IP address 10.0.0.1 by creating an
	// entry in the ebpf_ns map
	ip := net.ParseIP("10.0.0.1").To4()
	namespace := overlayEbpfNs{
		Ip: binary.BigEndian.Uint32(ip),
	}
	if err := objs.overlayMaps.EbpfNsMap.Put(uint32(1), namespace); err != nil {
		panic(err)
	}

	// Keep the program alive so that the eBPF programs aren't detached
	for {}
}