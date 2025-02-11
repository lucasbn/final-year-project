package main

import (
	"os"
	"os/signal"
	"syscall"
	"fmt"
    "log"
	"net"
	"encoding/binary"
	"github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

const MapPinPath = "/sys/fs/bpf/pid_enid_map"

// sudo go run main.go [NS_ID] [CMD]
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

	// Pin the map
	if err := objs.overlayMaps.PidEnidMap.Pin(MapPinPath); err != nil {
		log.Fatalf("Failed to pin map: %v", err)
	}
	defer func() {
		if err := objs.overlayMaps.PidEnidMap.Unpin(); err != nil {
			log.Fatalf("Failed to unpin map: %v", err)
		}
	}()

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

	getSockNameEnterLink, err := link.Tracepoint("syscalls", "sys_enter_getsockname", objs.TpSysEnterGetsockname, nil)
    if err != nil {
        log.Fatal("Attaching getsockname enter tracepoint:", err)
    }
    defer getSockNameEnterLink.Close()

	getSockNameExitLink, err := link.Tracepoint("syscalls", "sys_exit_getsockname", objs.TpSysExitGetsockname, nil)
    if err != nil {
        log.Fatal("Attaching getsockname exit tracepoint:", err)
    }
    defer getSockNameExitLink.Close()

	sockStateLink, err := link.Tracepoint("sock", "inet_sock_set_state", objs.SockSetState, nil)
	if err != nil {
		log.Fatal("Failed to attach inet_sock_set_state tracepoint:", err)
	}
	defer sockStateLink.Close()

	// -----------------------------------------------------------------------

	// Create two namespaces and add them to the ebpf_ns map
	ns1 := overlayEbpfNs{
		NsId: 1,
		Veths: [1]uint32{1},
	}

	ns2 := overlayEbpfNs{
		NsId: 2,
		Veths: [1]uint32{3},
	}

	if err := objs.overlayMaps.EbpfNsMap.Put(ns1.NsId, ns1); err != nil {
		panic(err)
	}
	
	if err := objs.overlayMaps.EbpfNsMap.Put(ns2.NsId, ns2); err != nil {
		panic(err)
	}

	// Create two veth pairs and a bridge
	veth1 := overlayEbpfVeth{
		VethId: 1,
		PairVethId: 2,
		BridgeId: 0, // No bridge
		IpAddr: binary.BigEndian.Uint32(net.ParseIP("10.0.0.1").To4()),
		HostInterface: 1, // eth0
	}
	br_veth1 := overlayEbpfVeth{
		VethId: 2,
		PairVethId: 1,
		BridgeId: 1,
		IpAddr: 0, // No IP address
		HostInterface: 0, // No host interface
	}

	veth2 := overlayEbpfVeth{
		VethId: 3,
		PairVethId: 4,
		BridgeId: 0, // No bridge
		IpAddr: binary.BigEndian.Uint32(net.ParseIP("10.0.0.2").To4()),
		HostInterface: 1, // eth0
	}
	br_veth2 := overlayEbpfVeth{
		VethId: 4,
		PairVethId: 3,
		BridgeId: 1,
		IpAddr: 0, // No IP address
		HostInterface: 0, // No host interface
	}

	if err := objs.overlayMaps.EbpfVethMap.Put(veth1.VethId, veth1); err != nil {
		panic(err)
	}
	
	if err := objs.overlayMaps.EbpfVethMap.Put(br_veth1.VethId, br_veth1); err != nil {
		panic(err)
	}

	if err := objs.overlayMaps.EbpfVethMap.Put(veth2.VethId, veth2); err != nil {
		panic(err)
	}

	if err := objs.overlayMaps.EbpfVethMap.Put(br_veth2.VethId, br_veth2); err != nil {
		panic(err)
	}

	br0 := overlayEbpfBridge{
		BridgeId: 1,
		Veths: [2]uint32{2, 4},
	}

	if err := objs.overlayMaps.EbpfBridgeMap.Put(br0.BridgeId, br0); err != nil {
		panic(err)
	}

	// Listen for termination signals (Ctrl+C, SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for a termination signal
	<-sigChan
	fmt.Println("Received termination signal")
}