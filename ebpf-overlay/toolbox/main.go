package main

import (
	"fmt"
	"os"
	"log"
	"os/exec"
	"os/signal"
	"syscall"
	"strconv"

	"github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

const BPFObjectPath = "../overlay_bpfel.o" 

const PinnedMapPath = "/sys/fs/bpf/pid_enid_map"

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}

	// Check that we have at least two arguments (ID + command)
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: <program> <id> <command> [args...]")
		os.Exit(1)
	}

	// Parse the first argument as the ID to be used in the map
	id, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid ID: %v\n", err)
		os.Exit(1)
	}

	// Remaining arguments will form the command to be executed
	cmdArgs := os.Args[2:]

	// Load the map
	pidMap, err := ebpf.LoadPinnedMap(PinnedMapPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map: %v", err)
	}
	defer pidMap.Close()

	// Start the child process with the command and arguments from os.Args
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Avoid zombie processes
	cmd.Stdin = os.Stdin   // Pass parent stdin to child
	cmd.Stdout = os.Stdout // Capture stdout
	cmd.Stderr = os.Stderr // Capture stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start process: %v\n", err)
		os.Exit(1)
	}

	pid := cmd.Process.Pid
	fmt.Printf("Started process with PID %d\n", pid)

	// Add PID to eBPF map with the provided ID as value
	if err := pidMap.Put(uint64(pid), uint32(id)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add PID to eBPF map: %v\n", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	// Defer killing the process when the Go program exits
	defer func() {
		// Remove the PID from the map
		if err := pidMap.Delete(uint64(pid)); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove PID from eBPF map: %v\n", err)
		}

		// Kill the child process if it is still running
		if err := cmd.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to kill process: %v\n", err)
		} else {
			fmt.Println("Child process killed")
		}
	}()

	go func() {
		err := cmd.Wait() // Blocks until the child exits
		if err != nil {
			fmt.Fprintf(os.Stderr, "Child process exited with error: %v\n", err)
		}
		fmt.Println("Child process exited. Terminating parent.")
		os.Exit(0) // Exit the Go program when the child exits
	}()

	// Listen for termination signals (Ctrl+C, SIGTERM)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for a termination signal
	<-sigChan
	fmt.Println("Received termination signal, killing child process...")
}
