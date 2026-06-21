# XDP/eBPF Firewall

A high-performance, kernel-space packet filter built with XDP (eXpress Data Path) and eBPF. Filters traffic by IP, port, and protocol with dynamic rule loading from userspace — dropping packets at the earliest point in the network stack, before the kernel allocates per-packet structures.

Benchmarked at **~67% higher packet-drop throughput than equivalent iptables rules**, with negligible latency added to legitimate traffic.

---

## Why XDP

Traditional firewalls like iptables operate inside the kernel's netfilter framework, which runs *after* the kernel has already allocated a socket buffer (`sk_buff`) for each packet. XDP runs much earlier — at the driver level (or just after, in generic mode), before that allocation happens. For a packet that's going to be dropped anyway, this avoids a large amount of per-packet work.

This makes XDP especially well-suited to:

- DDoS mitigation (dropping malicious floods cheaply)
- High-throughput edge filtering
- Any workload where most packets are rejected

This project implements a working firewall on top of XDP to demonstrate these properties and measure them directly against iptables.

---

## Architecture

The system has two halves: a kernel-space eBPF program that makes per-packet decisions, and a userspace loader that manages it.

```
┌─────────────────────────────────────────────────────────┐
│                      USERSPACE                           │
│                                                          │
│   loader.c (libbpf)                                      │
│     ├── loads & attaches the eBPF program                │
│     ├── reads rules from firewall.conf                   │
│     ├── populates BPF maps                               │
│     └── displays live drop/pass statistics               │
│                          │                               │
│                          │ (BPF maps: shared memory)     │
└──────────────────────────┼───────────────────────────────┘
                           │
┌──────────────────────────┼───────────────────────────────┐
│                      KERNEL (XDP)                         │
│                          ▼                               │
│   xdp_firewall.c                                         │
│     packet → parse headers → consult maps → decide       │
│                                              │           │
│                                    XDP_DROP / XDP_PASS    │
└─────────────────────────────────────────────────────────┘
```

### Packet processing pipeline

For each incoming packet, the eBPF program:

1. Increments the total-packet counter
2. Reads the firewall mode (blocklist vs allowlist)
3. Parses Ethernet → IPv4 → TCP/UDP/ICMP headers, with bounds checks before every access
4. Looks up the source IP in an LPM trie
5. Looks up the destination port in a hash map
6. Applies per-IP rate limiting
7. Returns `XDP_DROP` or `XDP_PASS` and updates statistics

### BPF maps

| Map | Type | Purpose |
|-----|------|---------|
| `ip_rules` | LPM trie | IP filtering with subnet support (e.g. block `10.0.0.0/24`) |
| `port_rules` | Hash | Exact destination-port filtering |
| `rate_counters` | Hash | Per-source-IP packet counters |
| `stats` | Array | Global counters (total / passed / dropped / rate-limited) |
| `config` | Array | Firewall mode flag |

---

## Design Decisions

**LPM trie for IP rules, not a hash map.** A hash map only does exact matches — blocking a `/24` subnet would require inserting 256 individual entries. An LPM (Longest Prefix Match) trie matches on prefixes, so one entry covers an entire subnet, and overlapping rules resolve to the most specific match — exactly how routing tables work.

**Hash map for port rules.** Ports are exact values with no notion of ranges or prefixes, so an O(1) hash lookup is the right structure.

**Array map for statistics and config.** These have a fixed, known number of integer-indexed slots that always exist, making an array the fastest and simplest choice.

**Independent early-return decision logic.** The BPF verifier rejects bitwise operations between two pointers. Combining map-lookup results into a single boolean expression caused the compiler to emit a forbidden pointer-OR. The fix was to restructure each rule check as an independent block that returns immediately, so two lookup results are never alive simultaneously.

**Strict bounds checks before every dereference.** The verifier requires proof that any memory access stays within packet bounds. Every header access is preceded by a `(ptr + 1) > data_end` check — non-negotiable, and it shapes the structure of the program.

---

## Performance

Measured on bare-metal Ubuntu, XDP generic mode, over a veth pair with the target in a separate network namespace. Traffic generated with `hping3`; latency measured with `ping`.

### Throughput (packet drop rate, 10-second flood)

| Firewall | Packets dropped | Drop rate |
|----------|-----------------|-----------|
| **XDP** | ~1,726,000 | **~172,000 pps** |
| iptables | ~1,033,000 | ~103,000 pps |

XDP dropped packets roughly **67% faster** than iptables for the same rule.

### Latency (round-trip, passed traffic)

| Configuration | Avg RTT |
|---------------|---------|
| No firewall (baseline) | 0.047 ms |
| XDP firewall (passing) | 0.060 ms |

XDP adds only **~13 µs** of latency to legitimate traffic it allows through.

> **Note on methodology:** `hping3` was the bottleneck in the throughput test, not either firewall — so both numbers represent a *floor*, not a ceiling. The relative gap is the meaningful result. Native-mode XDP on supported hardware would widen it further, since this was measured in generic (SKB) mode.

---

## Usage

### Build

```bash
# compile the eBPF program (BTF debug info required for libbpf)
clang -O2 -g -target bpf -c xdp_firewall.c -o xdp_firewall.o

# compile the userspace loader
clang -o loader loader.c -lbpf
```

### Configure

Rules live in a simple text file:

```
# firewall.conf
mode blocklist

# block specific IPs or subnets
ip 192.168.1.100
ip 10.0.0.0/24

# block ports
port 22
port 8080
```

`mode` may be `blocklist` (default-allow, drop matches) or `allowlist` (default-deny, pass matches).

### Run

```bash
sudo ./loader <interface> firewall.conf
```

The loader attaches the firewall, loads the rules, and displays live statistics:

```
XDP firewall attached to eth0
mode set to blocklist
Loaded 2 IP rules, 2 port rules
Firewall running. Press Ctrl+C to detach and exit.
[STATS] total: 18423  passed: 18401  dropped: 22  rate-limited: 0
```

Press `Ctrl+C` to detach cleanly.

---

## Testing Environment

Because local-to-local traffic shortcuts through the loopback interface and never reaches XDP, testing uses a veth pair with the target endpoint isolated in a separate network namespace:

```bash
# create veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip link set veth0 up

# isolate the far end in its own namespace
sudo ip netns add testns
sudo ip link set veth1 netns testns
sudo ip netns exec testns ip addr add 10.0.0.2/24 dev veth1
sudo ip netns exec testns ip link set veth1 up

# attach the firewall
sudo ./loader veth0 firewall.conf
```

Traffic to `10.0.0.2` now traverses `veth0`, where the firewall inspects every packet.

---

## Features

- IPv4 filtering by source IP, with subnet support via LPM trie
- Destination-port filtering (TCP and UDP)
- Protocol-aware handling for TCP, UDP, and ICMP
- Blocklist and allowlist modes
- Per-IP rate limiting
- Live drop/pass statistics
- Dynamic rule loading from a config file — no recompilation needed to change rules
- Clean attach/detach lifecycle management

---

## Scope & Future Work

This implementation is a **stateless packet filter** — each packet is judged independently. This is a deliberate scope choice: stateless filtering is exactly what edge DDoS mitigation systems (e.g. Cloudflare's) rely on, and it keeps the data path fast and simple. The following are natural extensions:

- **Stateful connection tracking** — a 5-tuple flow table with TCP state machine, to distinguish established connections from unsolicited ones. The largest extension, and the main reason this is a "filter" rather than a full stateful firewall.
- **Time-windowed rate limiting** — the current rate limiter is a cumulative per-IP counter; a sliding-window or token-bucket algorithm would make it production-grade.
- **Native XDP mode** — current benchmarks are in generic (SKB) mode due to consumer-NIC driver constraints; native mode would significantly raise throughput.
- **Ring-buffer event logging** — streaming per-drop metadata to userspace via `bpf_ringbuf` for real-time observability.

---

## Tech Stack

C (eBPF kernel program + libbpf userspace loader) · XDP · clang/LLVM BPF target · bpftool · Linux network namespaces · hping3 / iperf3 for benchmarking