# Usage

## Receiver

```sh
genesis recv -o /tmp/incoming.bin -p 37420
genesis recv -c /etc/genesis/genesis.conf -o /tmp/incoming.bin
```

`-p` is the local UDP port. The sender must be able to reach it. `--listen` is the same port if you also need `-p` to mean something else. It does not.

## Sender

```sh
genesis send -p 37420 ./clip.bin 192.168.4.100
genesis send ./clip.bin 192.168.4.100:37420
```

The sender binds an ephemeral port unless `--listen` is set. `-p` is the peer port.

stderr shows a bar, the percent, the amount, the recent rate, and the ETA. The summary line has the SHA-256, the average rate, the final pacing rate, and the bytes written to the socket.

## SSH control plane

```sh
genesis send --ssh foxx@euphoria --ssh-port 222 \
  --remote-bin /home/foxx/repos/My\ Projects/genesis_codes_ai_assessment/build-rel/genesis \
  ./clip.bin clip.bin
```

The remote process prints `ready <udp-port>` on stdout. The local process sends to that port on the SSH host. User, host, and the remote file name are restricted to letters, digits, and `/._-+` so the remote command is not a shell injection. SSH itself is still a shell on the far side. Do not point `--remote-bin` at a path you do not trust.

## Config

```text
profile = auto
fec_k = 8
fec_r = 1
plain_mss = 1200
window_packets = 512
expect_pub_hex = <64 hex chars>
psk = <64 hex chars>
recv_dir = /var/lib/genesis/incoming
```

`profile` accepts `auto`, `gbe`, `cellular`, `LOCAL_LAN_10G`, and `CELLULAR_5G`.

## Daemon

```sh
genesisd --foreground -c /etc/genesis/genesis.conf
genesisd --daemon --pid /run/genesisd.pid --chroot /var/lib/genesis --user genesis
```

Foreground is the default. The peer's file name is joined under `recv_dir` only if `genesis_path_is_safe` accepts it.

A partial destination is continued when `FILE.genesis` names the same source file and size. The resumed offset is a multiple of the sender's chunk. Delete the file and the sidecar to start over.

```sh
genesisd --control /tmp/genesis.sock -p 37420 --recv-dir /tmp/in
genesis --control /tmp/genesis.sock recv -o /tmp/in/clip.bin -p 37420
genesis --control /tmp/genesis.sock send -p 37420 ./clip.bin 192.168.4.100
```

Without `--control`, `send` and `recv` call the library in this process. `--ssh` stays on that path.

## Filesystem exports

```sh
genesis vfs-serve -p 37420 --export "photos=/home/foxx/photos,rw"
genesis showmount 192.168.4.100:37420
mount.genesis 192.168.4.100:37420:/photos /mnt/photos
mount.genesis --control /tmp/genesis.sock photos /mnt/photos
mount.genesis --ssh user@host --remote-export /home/user/photos photos /mnt/photos
```

`export = name path [ro|rw]` in the daemon config publishes the same directory. `docs/VFS.md` is the full description.

## NAT and a tunnel

```sh
genesis introduce -p 37420
genesis path --via HOST:37420 --name laptop --peer artc0 --room lab --bench 4194304
genesis tun --via HOST:37420 --name laptop --peer artc0 --room lab --tun gn0 --addr 10.88.73.1/30
```

`docs/NAT.md` covers the punch, the relay, the path report, and the proxy in front of `mount.genesis`.

## Discovery and STUN

```sh
genesis stun
genesis discover --timeout-ms 2000
```

STUN uses `stun_host` and `stun_port` from the config. The default host is `stun.l.google.com:19302`.

## Loss on a test interface

`scripts/traffic_sim.sh eth0 30 1` adds netem delay and loss. It needs `CAP_NET_ADMIN` and it is not part of `ctest`. Clear it with `scripts/traffic_sim.sh eth0 clear`.
