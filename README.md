# eBPF + XDP Firewall

A programmable, high-performance firewall built with eBPF and XDP on Linux, developed in four levels.

| Level | What it does | Main files |
|-------|--------------|------------|
| 1 | Stateless firewall: drops ICMP, logs to trace pipe | `Task 1/bpf/l1.bpf.c` |
| 2 | Dynamic control plane: add/remove/list blocked IPs at runtime | `Task 2/bpf/l2.bpf.c`, `Task 2/bpf/fwctl/main.go` |
| 3 | Per-IP rate limiting and SYN flood mitigation | `l3.bpf.c` |
| 4 | Stateful connection tracking (XDP ingress + TC egress) | `l4.bpf.c` |

---

## 0. Concepts you need first

- **eBPF** lets you run small, verified, sandboxed programs inside the Linux kernel.
- **XDP** (eXpress Data Path) is a hook in the network driver. An XDP program sees each *incoming* packet before the normal network stack and returns a verdict: `XDP_PASS` (let it through) or `XDP_DROP` (discard it).
- **A `.bpf.o` file is not an executable.** It is BPF bytecode in an ELF file. You cannot run it with `./l1.bpf.o`. It must be **loaded into the kernel** and **attached** to a network interface. That is what every method below does.
- **Maps** are kernel data structures (hash tables) shared between the kernel program and user space. They are how the control plane changes rules without reloading the program.
- **Pinning** a map or program means giving it a file under `/sys/fs/bpf/` so it outlives the process that loaded it and other tools (`bpftool`, `fwctl`) can open it.
- **XDP only sees ingress.** For Level 4 we also attach a **TC egress** program to see outgoing connections.
- **Only one XDP program can be attached to an interface at a time.** Detach the old one before attaching the next.

---

## 1. Prerequisites and setup

Tested on Ubuntu 24.04 (including WSL2).

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev gcc make \
    linux-libc-dev libc6-dev iproute2 linux-tools-common linux-tools-generic \
    golang-go tcpdump hping3
```

Do **not** try to install `linux-headers-$(uname -r)` or a package called `bpftool` on WSL. Those packages do not exist there and one failed package makes apt install nothing.

### Make `bpftool` available

Ubuntu ships it inside the tools package, not on your PATH:

```bash
sudo ln -s $(ls /usr/lib/linux-tools/*/bpftool | head -1) /usr/local/bin/bpftool
bpftool version
```

### Mount the BPF filesystem

```bash
sudo mount -t bpf bpf /sys/fs/bpf
mount | grep bpf
```

(If it is already mounted, this is harmless.)

### Set your interface name

Everything below assumes `eth0`. Check yours:

```bash
ip -br link
```

### Compile command (used for every level)

```bash
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c <file>.bpf.c -o <file>.bpf.o
```

Explanation:
- `-O2` is required; the verifier rejects unoptimised BPF.
- `-g` keeps debug/BTF info.
- `-target bpf` produces BPF bytecode instead of x86 code.
- `-I/usr/include/x86_64-linux-gnu` lets clang find `asm/types.h`.

### Verify the object really contains a program

```bash
llvm-objdump -h <file>.bpf.o
```

You must see a section named `xdp` (and `.maps` for levels that use maps). If you only see `.text` with size 0, the source file was empty or unsaved, so fix that before continuing.

### Safety warning

A bad rule on your only network interface can cut you off. Test on a VM or WSL first, and know how to detach (section 7).

---

## 2. Level 1: Stateless firewall

**Goal:** drop all ICMP (ping) packets and log each drop.

**How it works:** the XDP program parses Ethernet then IPv4 headers, with a bounds check before every read (the verifier requires this). If the IP protocol is ICMP it calls `bpf_printk` and returns `XDP_DROP`.

```bash
cd "Task 1/bpf"
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c l1.bpf.c -o l1.bpf.o
llvm-objdump -h l1.bpf.o
```

### Method A: `ip link` (iproute2)

```bash
sudo ip link set dev eth0 xdpgeneric obj l1.bpf.o sec xdp
```

- `xdpgeneric` is generic (SKB) mode. It works on any interface, including virtual ones, but is slower than native mode.
- `sec xdp` selects the ELF section. If you get "object file doesn't contain sec xdp", try `sec xdp_l1` or omit `sec`, or use Method B.

### Method B: `bpftool` (most reliable)

```bash
sudo bpftool prog loadall l1.bpf.o /sys/fs/bpf/l1
sudo ls /sys/fs/bpf/l1                      # shows the pinned program name
sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/l1/xdp_l1 dev eth0
```

Replace `xdp_l1` with whatever `ls` printed (it can be `xdp` or `xdp_l1` depending on your tool versions). `loadall` loads and pins the program; `net attach` attaches the pinned program to the interface.

### Method C: custom loader binary (`loader.c`)

A small user-space program that loads the object, attaches it, stays running, and detaches cleanly on `Ctrl+C`.

```bash
gcc loader.c -o loader -lbpf -lelf -lz
sudo ./loader l1.bpf.o eth0
```

### Verify

```bash
ip link show eth0                  # look for "xdpgeneric" and "prog/xdp id N"
sudo bpftool net show dev eth0
```

Watch the logs in one terminal:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# alternative:
sudo bpftool prog tracelog
```

`trace_pipe` blocks silently until something is logged. A blank cursor is normal. Press `Ctrl+C` to leave it.

### Test

Packets must arrive **through `eth0`**. Pinging WSL from inside WSL uses loopback and never reaches the program. Ping from another machine (or from Windows):

```powershell
ping <WSL eth0 IP>
```

Find that IP with `ip -4 addr show eth0`. While attached the pings time out and the log shows `DROP icmp from ...`.

---

## 3. Level 2: Dynamic control plane

**Goal:** add, remove and list blocked IPs while the firewall is running, with no reload.

**How it works:**
- `l2.bpf.c` defines a hash map `blocklist` (key = IPv4 address in network byte order, value = 1 byte) with `LIBBPF_PIN_BY_NAME`, so loading with `pinmaps` pins it at `/sys/fs/bpf/blocklist`.
- For every packet the XDP program looks up the source IP in the map. If found, `XDP_DROP`.
- `fwctl` (Go, `cilium/ebpf`) opens the pinned map and calls `Put`, `Delete`, or iterates it. Because the map is live kernel memory, changes apply on the very next packet.

### Build the kernel object

```bash
cd "Task 2/bpf"
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c l2.bpf.c -o l2.bpf.o
llvm-objdump -h l2.bpf.o       # expect xdp, .maps, license sections
```

### Load and attach

```bash
sudo rm -rf /sys/fs/bpf/l2 /sys/fs/bpf/blocklist     # clear stale pins from earlier runs
sudo bpftool prog loadall l2.bpf.o /sys/fs/bpf/l2 pinmaps /sys/fs/bpf
sudo ls /sys/fs/bpf /sys/fs/bpf/l2                   # expect: blocklist, l2/<prog>
sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/l2/xdp_l2 dev eth0
ip link show eth0
```

Use the real pinned name from `ls` in the attach command. bpffs is root-only, so use `sudo` even for `ls`.

### Build the control tool

```bash
cd fwctl
go mod init fwctl                  # only the first time
go get github.com/cilium/ebpf
go mod tidy
go build -o fwctl .
```

Needs Go 1.21 or newer (uses `binary.NativeEndian`).

### Use it

```bash
sudo ./fwctl add 192.168.48.1      # block
sudo ./fwctl list                  # show blocked IPs
sudo ./fwctl del 192.168.48.1      # unblock
```

### Alternative: control the map with `bpftool` only

```bash
sudo bpftool map show pinned /sys/fs/bpf/blocklist
sudo bpftool map update pinned /sys/fs/bpf/blocklist key 192 168 48 1 value 1
sudo bpftool map dump pinned /sys/fs/bpf/blocklist
sudo bpftool map delete pinned /sys/fs/bpf/blocklist key 192 168 48 1
```

The key is the four bytes of the IPv4 address in decimal.

### Test

1. Find the source address WSL actually sees:
   ```bash
   sudo tcpdump -ni eth0 icmp
   ```
   For pings from Windows into WSL this is usually the WSL gateway (`ip route | grep default`), **not** your Windows Wi-Fi address.
2. `sudo ./fwctl add <that IP>`
3. Ping again; it should time out and the log shows `DROP blocklisted ...`.
4. `sudo ./fwctl del <that IP>`; pings work again. The XDP program was never reloaded.

Note: blocking the WSL gateway can also break DNS and internet inside WSL. Remove it when done.

---

## 4. Level 3: Rate limiting and SYN flood mitigation

**Goal:** if a source IP exceeds 100 packets per second, drop its further packets.

**How it works:**
- An LRU hash map `rate_map` keyed by source IP stores `{window_start, count}`.
- Each packet: read `bpf_ktime_get_ns()`. If more than 1 second has passed since `window_start`, start a new window. Otherwise atomically increment `count`. If `count >= 100`, `XDP_DROP`.
- The version provided counts only TCP SYN packets without ACK (`syn && !ack`), which targets SYN floods. To rate-limit all packets, delete the TCP/SYN check block.
- It also checks the Level 2 `blocklist`, so manual blocking still works.
- This is a fixed-window limiter, so a burst of up to about 2x the limit can pass across a window boundary. A token bucket is the stricter alternative.

```bash
cd "Task 3/bpf"
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c l3.bpf.c -o l3.bpf.o
llvm-objdump -h l3.bpf.o

sudo ip link set dev eth0 xdpgeneric off 2>/dev/null     # only one XDP program at a time
sudo rm -rf /sys/fs/bpf/l3
sudo bpftool prog loadall l3.bpf.o /sys/fs/bpf/l3 pinmaps /sys/fs/bpf
sudo ls /sys/fs/bpf/l3
sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/l3/xdp_l3 dev eth0
```

If `blocklist` is already pinned from Level 2, libbpf reuses it, so `fwctl` keeps working with Level 3.

### Test

From another machine or network namespace:

```bash
sudo hping3 -S -p 80 --flood <WSL eth0 IP>
```

Watch drops and counters:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe          # "DROP rate-limit ..." lines
sudo bpftool map dump name rate_map                    # per-IP window_start and count
```

For a gentler test, `hping3 -S -p 80 -i u5000 <ip>` sends about 200 packets per second.

---

## 5. Level 4: Stateful connection tracking

**Goal:** allow inbound traffic only if it belongs to a connection started locally; drop all unsolicited inbound traffic.

**How it works:**
- XDP cannot see outgoing packets, so a **TC egress** program records each outbound TCP/UDP flow into the shared pinned map `conntrack`. The key is `{local_ip, remote_ip, local_port, remote_port, proto}` and the value is a last-seen timestamp.
- The **XDP ingress** program builds the *reversed* key for each incoming packet. If it is in `conntrack` and not older than 120 seconds, it passes and the timestamp is refreshed. Otherwise `XDP_DROP`.
- Non-IPv4 traffic (ARP, IPv6) is passed so the network keeps working. Unsolicited IPv4 that is not TCP/UDP (for example ICMP) is dropped.

```bash
cd "Task 4/bpf"
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c l4.bpf.c -o l4.bpf.o
llvm-objdump -h l4.bpf.o          # expect both an "xdp" and a "tc" section

sudo ip link set dev eth0 xdpgeneric off 2>/dev/null
sudo rm -rf /sys/fs/bpf/l4 /sys/fs/bpf/conntrack
sudo bpftool prog loadall l4.bpf.o /sys/fs/bpf/l4 pinmaps /sys/fs/bpf
sudo ls /sys/fs/bpf/l4            # note both pinned names (e.g. xdp_l4 and tc_egress)
```

Attach the XDP (ingress) program:

```bash
sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/l4/xdp_l4 dev eth0
```

Attach the TC (egress) program:

```bash
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 egress bpf direct-action pinned /sys/fs/bpf/l4/tc_egress
sudo tc filter show dev eth0 egress
```

Use the actual pinned names printed by `ls`. `clsact` is a special qdisc that provides ingress/egress hooks for BPF. `direct-action` lets the program return a TC verdict itself.

### Test

```bash
curl -I https://example.com            # outbound works: reply matches a tracked flow
sudo bpftool map dump pinned /sys/fs/bpf/conntrack    # shows tracked flows
```

From another machine, try to initiate a connection *to* WSL, for example `nc <WSL IP> 8080`. It should be dropped and the log shows `DROP unsolicited from ...`.

**Warning:** this blocks unsolicited inbound traffic, including SSH *into* the machine. Test on a VM, not a remote box you depend on.

---

## 6. Observability cheat sheet

```bash
ip link show eth0                                  # is XDP attached? (xdpgeneric, prog id)
sudo bpftool net show dev eth0                     # attached XDP and TC programs
sudo bpftool prog show                             # all loaded programs
sudo bpftool map show                              # all maps
sudo bpftool map dump pinned /sys/fs/bpf/<map>     # contents of a pinned map
sudo cat /sys/kernel/debug/tracing/trace_pipe      # bpf_printk output
sudo tcpdump -ni eth0                              # what actually arrives on the interface
```

---

## 7. Stopping and cleaning up

Detach XDP (any method):

```bash
sudo ip link set dev eth0 xdpgeneric off
# or
sudo bpftool net detach xdpgeneric dev eth0
```

Detach TC (Level 4):

```bash
sudo tc qdisc del dev eth0 clsact
```

If you used the `loader` binary, just press `Ctrl+C`; it detaches itself.

Remove pinned programs and maps:

```bash
sudo rm -rf /sys/fs/bpf/l1 /sys/fs/bpf/l2 /sys/fs/bpf/l3 /sys/fs/bpf/l4
sudo rm -f  /sys/fs/bpf/blocklist /sys/fs/bpf/conntrack
```

Confirm everything is gone:

```bash
ip link show eth0
sudo ls /sys/fs/bpf
```

Stopping the `trace_pipe` viewer with `Ctrl+C` only stops the log viewer, not the firewall.

---

## 8. Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `bpf/bpf_helpers.h not found` | libbpf headers missing: `sudo apt install libbpf-dev` |
| `asm/types.h not found` | add `-I/usr/include/x86_64-linux-gnu`, install `linux-libc-dev libc6-dev` |
| `Exec format error` running `./x.bpf.o` | `.o` is bytecode; load it with bpftool/ip/loader instead |
| `object file doesn't contain sec xdp` | the compile produced no program (empty or unsaved `.c`), or try another `sec` name or bpftool |
| `ls: Permission denied` in `/sys/fs/bpf` | bpffs is root-only: use `sudo` |
| `bpf obj get (...): No such file or directory` | wrong pinned name, or load did not succeed: `sudo ls /sys/fs/bpf/<dir>` |
| `loadall` fails: file exists | stale pins: `sudo rm -rf /sys/fs/bpf/<dir>` and retry |
| Attach fails "already attached" | detach first: `ip link set dev eth0 xdpgeneric off` |
| Pings still succeed after blocking | program not attached, or wrong source IP (use `tcpdump`), or traffic is on loopback |
| `trace_pipe` shows nothing | no matching traffic yet; try `sudo bpftool prog tracelog` |
| Verifier error "invalid access" | add a bounds check (`ptr + 1 > data_end`) before each header read |
| XDP attach unsupported on WSL | the WSL kernel may not support it; use an Ubuntu VM for testing |

---

## 9. Suggested repository layout

```
.
├── README.md
├── Task 1/bpf/{l1.bpf.c, loader.c}
├── Task 2/bpf/{l2.bpf.c, fwctl/{main.go, go.mod, go.sum}}
├── Task 3/bpf/l3.bpf.c
├── Task 4/bpf/l4.bpf.c
└── .gitignore            # *.o, compiled binaries (fwctl, loader)
```

Do not commit `.o` files or compiled binaries. Rename folders to avoid spaces (`task1`, `task2`, ...) so scripts do not need quoting.

## 10. Possible improvements

- Token-bucket rate limiting, and auto-ban entries that expire.
- Track TCP state (SYN, ESTABLISHED, FIN/RST) in conntrack instead of just "seen outbound recently".
- IPv6, fragments, IP options and VLAN support.
- Native XDP mode on real hardware (`xdpdrv`) for full performance.
- Per-CPU maps or atomic counters to reduce contention.
