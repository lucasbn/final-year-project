# Compile libbpf

```
git submodule update --init --remote --recursive
cd external/libbpf
OBJDIR=build DESTDIR=install-dir make -C src install
```

# Bypassing the TCP/IP stack for local connections

Instead of using the loopback interface to forward packets from one local socket
to another, we can use eBPF to redirect packets to the destination socket before
they traverse the TCP/IP stack in the kernel, and gain a slight performance
benefit.

<img src="images/tcp-bypass.png" alt="TCP Bypassing" width="350" />

First, compile the tcp-bypasser by running `make` in the `/tcp-bypasser`
directory. Then, you can run an experiment with:

```
sudo ./evaluate/test-bypasser.sh
```

This experiment establishes a connection between a client and a server, and then
sends 250,000 requests (1024 bytes) from the client and receives an echoed response
from the server. The average round trip time is then calculated as the sum of
the time it took to send/receive each request and response, divided by the
number of requests (250,000). It repeats the experiment after loading in the
eBPF program.

I'm running the experiment on a virtual machine running Ubuntu 24.10 (ARM) and
get the following results:

```
Average RTT (without bypasser): 42.72 microseconds
Average RTT (with bypasser): 39.32 microseconds
```

Which means roughly an 8% decrease in latency with the bypasser

# Multi-port: dynamically remap port bindings

Network namespaces allow processes within a container to bind to a particular
port, and the "same" port can be bound to across different namespaces. On the
underlying host, we cannot bind different sockets to the same port. Network
namespaces provide a mapping between the port as seen by the container, and
the actual host port that is bound to.

This acheives something similar with three eBPF programs. These eBPF programs
intercept two different syscalls (`bind` and `getsockname`) and modify their
arguments / return values. 

Whenever a `bind` syscall is made, an eBPF program is called (just before the
syscall is handled) which modifies the arguments made to the syscall. If the
port number that the socket is being bound to is 3000, it pick a random port and
overwrite the port number argument. This means that the socket is not bound to
port 3000 and instead bound to a random port. The eBPF program also updates a
mapping from the randomly assigned port to the orignal port (3000).

The other eBPF programs ensure that this remapping is unobservable. They
intercept the `getsockname` syscall: one at entry and one at exit. At entry, we
store the user space pointer at which the `struct sockaddr_in` data is stored
during the execution of the syscall in a map, so that we can access it at exit.
We use the PID as the key for this pointer. Then, at exit, we get this pointer
and updates the `sin_port` field according to our mapping set during the `bind`.