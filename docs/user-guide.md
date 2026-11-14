# Genesis user guide

`genesis` sends one file. `genesisd` receives files until it is stopped. Both are thin clients of `libgenesis_core.so`. The web UI in `web/` is a separate process that runs the `genesis` binary and shows its progress.

Build and install:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$HOME/.local"
```

The unit test and the `genesis-perf` summary both run under `ctest` on a non-sanitizer build. Sanitizer builds skip the perf budget because instrumentation changes the timing.

## genesis

```text
genesis send [options] FILE HOST[:PORT]
genesis send [options] --ssh USER@HOST[:SSHPORT] FILE REMOTE_NAME
genesis recv [options] [-o FILE]
genesis discover [--timeout-ms MS]
genesis stun
genesis dht HOST[:PORT]
genesis showmount [HOST[:PORT]]
genesis tree HOST[:PORT]:/EXPORT[/PATH]
genesis vfs-serve [--export NAME=PATH[,ro]]
genesis mount [mount.genesis options] SPEC MOUNTPOINT
genesis version
```

`FILE` may be `-` to read standard input. The receiver then learns the length from the final checksum frame. `genesis recv -o -` writes the payload to standard output.

Progress is one line on standard error: a bar, percent, bytes, effective rate, and ETA. The rate is half the lifetime average and half a 2 second exponential average, so one short stall does not rewrite the ETA. Times of an hour or more are printed as `h:mm:ss`.

`-v` prints one line when the handshake finishes (`transfer init`, peer, file, FEC, NACK, link, feature bitmask, resume offset) and one line at the end (`transfer end`, packet totals, average transmit packets per second, FEC and NACK packet counts, retransmission count, and FEC/NACK byte overhead as a percent of wire bytes sent and received). The same flag prints each DHT node actually inserted, as `near` or `far`, id, address, and RTT. `genesisd -v` writes those lines to stderr. `genesisd --daemon -v` writes them to syslog with ident `genesisd` instead, because the double-fork closes the terminal. The syslog socket is opened before the chroot.

## Resume

If a receive is interrupted, the bytes already flushed and a sidecar `FILE.genesis` (the sender's file name and size) let the next run continue. The receiver tells the sender the largest chunk-aligned prefix that was actually flushed. The preallocated tail does not count. The sender reads and hashes that prefix, both sides cover it in the final digest, and the rest of the file is the only thing on the wire. A different name or size starts over. Delete the destination and the sidecar to force a full copy. When the file size is known, the receiver `ftruncate`s it to that size. `posix_fallocate` reserves the unwritten tail when it is at most 1 GiB, so a full disk fails at the start on filesystems that support the call. Larger files stay sparse. Standard output is never preallocated.

## Talking to genesisd

Without `--control`, `send` and `recv` call the library in this process. With `--control`, the same command is sent to a running daemon and the progress lines come back from it.

```sh
genesisd --control /tmp/genesis.sock -p 37420 --recv-dir /tmp/in
genesis --control /tmp/genesis.sock recv -o /tmp/in/file.bin -p 37420
genesis --control /tmp/genesis.sock send -p 37420 ./file.bin 192.168.4.100
```

The spec is a filesystem path, `unix:/path`, or `host:port`. `recv` uses the daemon's UDP port. `send` opens its own socket in the daemon process. One control command runs at a time. `--ssh` stays in the local process.

`export` lines in the daemon config publish directories. `mount.genesis HOST:PORT:/NAME MOUNTPOINT` mounts one. `--control PATH` on the mount helper uses the daemon socket instead of UDP. The operations and the SSH form are in `docs/VFS.md`.

### Options

| Option | Meaning |
| --- | --- |
| `-c FILE` | key=value config, applied before the flags that follow it |
| `-b HOST` | local bind address |
| `-p PORT` | peer port for send, listen port for recv. Default 37420 |
| `--listen PORT` | local port for a sender. Default is ephemeral |
| `--profile auto\|gbe\|wifi\|cellular` | also `LOCAL_LAN_10G` and `CELLULAR_5G` |
| `--link auto\|ethernet\|wifi\|cellular` | overrides interface detection |
| `--fec auto\|on\|off` | Reed-Solomon parity |
| `--nack auto\|on\|off` | explicit missing-sequence reports |
| `--fec-k N` | data shards per group, 1..16 |
| `--fec-r N` | parity shards, 1..4 |
| `--mss N` | plaintext datagram budget |
| `--window N` | packets in flight, 16..512 |
| `--jitter-ms N` | force the reassembly hold. 0 keeps the link default |
| `--via HOST:PORT` | extra path. Repeat to stripe and fail over |
| `--psk HEX` | 32-byte pre-shared key, hex |
| `--expect-pub HEX` | require this X25519 public key |
| `--timeout SEC` | give up. 0 waits |
| `--ssh USER@HOST` | start the remote receiver over SSH |
| `--ssh-port N` | SSH port when it is not 22 |
| `--remote-bin PATH` | remote `genesis` for `--ssh`. The path cannot contain spaces |
| `-o FILE` | receive path. `-` is stdout |
| `-v` | verbose log, repeatable |

`--ssh` prints `ready PORT` from the remote receiver and then sends. The remote command is built without a shell.

### FEC, NACK, and the link

The handshake carries a feature bitmask. FEC is bit 0 and NACK is bit 9. A feature runs only when both peers set the bit.

`auto` asks the default route, then RTT:

| Link | How it is recognized | FEC | NACK | Initial pace | Jitter hold |
| --- | --- | --- | --- | --- | --- |
| Ethernet | `eth*`, `en*`, or RTT under 2 ms | off | on | 80 Mbit/s | 2 ms |
| Wi-Fi | `wl*`, `wlan*` | on | on | 20 Mbit/s | 8 ms |
| Cellular | `wwan*`, `rmnet*`, `ppp*`, or a long RTT | off | off | 5 Mbit/s | 40 ms |

Ethernet is the preferred guess when the interface is unknown. A named interface is not reclassified just because the RTT looks like another medium. Wi-Fi and wired paths are expected to drop packets, so they keep NACK. Wi-Fi sends parity. An ethernet peer accepts that parity and does not send parity to another ethernet peer. Cellular is expected to jitter without dropping, so parity and NACK stay off and a late packet is not called a loss until the hold expires.

Force a combination when comparing the path:

```sh
genesis recv --fec off --nack off -o /tmp/out.bin -p 37420
genesis send --fec off --nack off -p 37420 ./file.bin 192.168.4.100

genesis recv --fec on --nack on --profile wifi -o /tmp/out.bin -p 37421
genesis send --fec on --nack on --profile wifi -p 37421 ./file.bin 192.168.4.100
```

The summary's wire byte count grows when parity or retransmission is doing work. Goodput is the payload rate.

### Several paths

```sh
genesis send --via 192.168.4.101:37420 --via 10.1.0.5:37420 \
  -p 37420 ./file.bin 192.168.4.100
```

Groups are spread across the primary address and each `--via` target. After four failed sends on one path, that block moves to a path that is still answering. The file is reassembled by byte offset on the receiver, so the receiver is a single `genesis recv` or `genesisd` bound to `0.0.0.0` if more than one local address is in use. A path that fails three blocks is marked down. The transfer fails only after every path has exhausted retransmission.

### DHT

`genesisd` and an active transfer answer `GDHT` find-node queries on the same UDP socket.

```sh
genesis dht 192.168.4.100
genesis dht 192.168.4.100:37420 --timeout-ms 1500
```

Each line is `near` or `far`, a 32-character node id, `address:port`, and `rtt_us`. Near means the RTT is under 30 ms or the id shares a long prefix with the requester. Far is the rest of the table. The table is 16 buckets of 8 nodes.

### Discovery and STUN

```sh
genesis stun
genesis discover --timeout-ms 2000
```

STUN uses the host and port in the config (`stun.l.google.com:19302` by default). Discovery listens on `239.255.42.19:37421`. Neither opens a firewall port.

## genesisd

The daemon stays in the foreground unless `--daemon` is passed. systemd and OpenRC should use the foreground.

```text
genesisd [--foreground] [-c FILE] [--chroot DIR] [--user USER] [--pid FILE] [--recv-dir DIR]
genesisd --daemon --pid /run/genesisd.pid -c /etc/genesis/genesis.conf
```

| Option | Meaning |
| --- | --- |
| `-c FILE` | same keys as the CLI |
| `--chroot DIR` | `chroot` after the socket is bound. Fails closed when not root |
| `--user USER` | `initgroups`, `setgid`, `setuid` after chroot |
| `--pid FILE` | pid file written by `--daemon` |
| `--recv-dir DIR` | directory for received names. `..` and absolute names are rejected |
| `--foreground` | stay attached. This is the default |
| `--daemon` | double fork. Do not combine with a process supervisor |

SIGINT and SIGTERM ask the poll loop to return. The handler does not call into the engine.

Packets are accepted from any peer that completes the handshake. The file name comes from the sender and is joined to `--recv-dir` only when the lexical check passes.

### Config file

```text
bind_host = 0.0.0.0
bind_port = 37420
node_name = genesis
profile = auto
enable_fec = auto
enable_nack = auto
enable_dht = 1
jitter_ms = 0
link = auto
window_packets = 128
recv_dir = /var/lib/genesis/incoming
transfer_timeout_s = 0
```

`#` comments are ignored. `enable_fec` and `enable_nack` take `auto`, `on`, `off`, `1`, or `0`. `routes` is a comma-separated `host:port` list, the same as repeating `--via`.

### Init scripts

`packaging/systemd/genesisd.service` is `Type=simple` and passes `--foreground`. `packaging/openrc/genesisd` uses `supervise-daemon` the same way. Installing the files does not enable the service.

An unprivileged process cannot chroot. The jail call returns an error instead of pretending the process is confined. Run the daemon as a dedicated user and point `recv_dir` at a directory that user owns.

## Web control

`web/` is a small Go program. It does not link the core. It executes `genesis` and reads the progress line.

```sh
cd web
go build -o genesis-web .
./genesis-web -listen 127.0.0.1:8787 -genesis ../build/genesis
```

Open `http://127.0.0.1:8787`. The form starts `genesis send` or `genesis recv` with the FEC, NACK, profile, window, and port you set. The page subscribes to `/events` and updates the bar from the CLI. Only one transfer runs at a time. The listen address defaults to localhost.

`-daemon` is not required under a supervisor. `packaging/systemd/genesis-web.service` and `packaging/openrc/genesis-web` keep the process in the foreground. The OpenRC script has a `start_sysv` helper that backgrounds it for a SysV-only host.

## Performance check

```sh
./build/genesis-perf
```

The program transfers 4 MiB inside the process and prints:

```text
perf_ok=1
perf_bytes=4194304
perf_cpu_us=...
perf_bps=...
perf_rss_kb=...
perf_user_us=...
perf_sys_us=...
perf_retx=0
```

`perf_bps` is payload bytes per CPU second, not a socket rate. The check fails under 8 MB/s or above 64 MB RSS. Release CI saves this text as `perf-summary.txt`. Address and thread sanitizer jobs run the unit tests only.

## What the engine already does for the brief

The data plane is UDP. The pacer is user-space BBR, not the kernel. SSH can start the remote receiver without opening a firewall port. STUN discovers a mapped address. A lost route does not discard the file. A stream is a send from stdin. The shared library is the piece an embedded port links; the socket, jail, and web UI stay on POSIX.
