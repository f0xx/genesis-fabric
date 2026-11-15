# NAT traversal and TUN

A peer that can be reached from the internet introduces the others. Each side registers on that UDP port. The introducer replies with the address it actually saw, which is the reflexive address after every NAT on the path. The two sides then send a punch at those addresses. If a punch answer arrives, later datagrams go directly. If it does not, the introducer forwards them. The forward only happens between two names that registered in the same room while both are still live, and the inner datagram has to be a genesis frame.

The punch and the relay use a header whose magic is `GNAT`, not `GCX1`. A file engine that does not know it leaves the datagram alone. `genesisd` answers `GNAT` on its UDP socket, and `genesis introduce` is that socket by itself.

```sh
genesis introduce -b 0.0.0.0 -p 37420
genesis path --via 134.17.5.46:37420 --name artc0 --room lab
genesis path --via 134.17.5.46:37420 --name laptop --peer artc0 --room lab --bench 4194304
```

The report is RTT min/avg/max, jitter, the largest UDP payload that round-tripped, the IPv4 MTU that payload implies, punch counts, and goodput in bits per second. `mode direct` means the punch opened a mapping. `mode relay` means the datagrams still cross the introducer. `--relay` skips the punch. STUN, when it answers, is printed next to the reflexive address the introducer observed. A keepalive registration keeps the same cookie, so the return path stays valid.

`--listen PORT` and `--target HOST:PORT` are a UDP proxy. A mount or a file transfer aimed at the local port is carried to the peer, so `mount.genesis` does not need its own NAT code:

```sh
genesis vfs-serve -b 127.0.0.1 -p 44000 --export box=/srv/export
genesis path --via 10.7.0.10:37420 --name artc0 --room lab --target 127.0.0.1:44000
genesis path --via 134.17.5.46:37420 --name laptop --peer artc0 --room lab --listen 45000
mount.genesis 127.0.0.1:45000:/box /mnt/lab
```

## TUN and TAP

`genesis tun` opens `/dev/net/tun`. `--tun` is an IP device, `--tap` is Ethernet. `--addr A.B.C.D/N` assigns that address and brings the device up. The device is not persistent: it disappears when the process exits. Creating it needs `CAP_NET_ADMIN`.

Packets are sequenced and acknowledged. A missing packet is sent again after 150 ms, and a slot that is still unacknowledged after about 1.2 s is released so one stalled flow does not block the device. The tunnel MTU follows the measured payload. The same path report is printed before the device is handed to the kernel.
