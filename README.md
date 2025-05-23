This repository contains tools and libraries for measuring and optimizing network performance using AF_XDP technology.
## Repository Structure

- **common**: Shared utility library for AF_XDP
  - Provides common functions and data structures for working with AF_XDP sockets
  - Includes helpers for managing UMEM, ring descriptors and zero-copy data transfer

- **Step1**: Ping-pong application (similar to iperf) leveraging AF_XDP
  - Benchmark tool for measuring latency and throughput
  - Implements a client-server model for bidirectional communication testing



## Prerequisites
- Linux Kernel 5.x or higher with XDP support
- XDP-compatible network card
- Development libraries: libbpf, libxdp

## Step1 - Installation
 ```bash
# Clone the repository
git clone https://github.com//EdoardoDd/eBPF_testing.git
cd Step1/receiver_AF_XDP # or sender_AF_XDP

# Install dependencies
./setup.sh

# Compile libraries and applications
make
 ```

## Step1 - Usage
- Configure IP addresses and MAC addresses according to your machines
### Sender
 ```bash
sudo ./sender_user -d <interface> --filename <kern_file> -z -P -t <seconds> -s <packet_size> -r <rate>
```
### Receiver
 ```bash
sudo ./receiver_user -d <interface> --filename <kern_file> -z -P -n
 ```
Where:

- -d <interface>: Network interface to use
- --filename <kern_file>: Kernel BPF program to load (e.g., sender_kern.o)
- -z: Force zero-copy mode
- -P: Run in performance test mode (print stats)
- -N: Install XDP program in native mode
- -t <seconds>: Run test duration in seconds (e.g., 5)
- -s <packet_size>: Set packet size in bytes (e.g., 64)
- -r <rate>: Set rate in packets per second (e.g., 20000)
