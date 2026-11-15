# Genesis

UDP file transfer for a LAN, a routed path, or a punched NAT mapping. The protocol engine is `libgenesis_core.so`. `genesis` and `genesisd` are thin C++20 programs that talk to it through `include/genesis/api.h`.

The data plane is UDP. Congestion control is a user-space BBRv3-style pacer. It does not change the kernel congestion control, and it does not open router ports.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizers are one at a time:

```sh
cmake -S . -B build-asan -DGENESIS_SANITIZER=address
cmake -S . -B build-tsan -DGENESIS_SANITIZER=thread -DGENESIS_IO_URING=OFF
```

`-march=native` is off unless `-DGENESIS_NATIVE_ARCH=ON`, so a binary built here can be copied to another machine of the same ABI. CMake 3.16 is the minimum, which covers the Alpine host used in CI and on `artc0`.

`liburing` is optional. The data path uses `sendto` / `recvfrom`. A `sendmmsg` helper is in the socket class for bursts. io_uring is initialized when the library is present so the stats flag can report it; UDP reads are not issued with `readv`.

## Install

`cmake --install` places `genesis`, `genesisd`, the shared library, `genesis/api.h`, a systemd unit, an OpenRC script, and `genesis.conf.example`. The unit files are not enabled.

## Use

```sh
genesis recv -o /tmp/out.bin -p 37420
genesis send -p 37420 ./file.bin 192.168.4.100
```

Progress (bar, percent, rate, ETA) is written to stderr. A config file is `-c path` with `key = value` lines. An interrupted receive continues from the last flushed chunk when the destination and its `.genesis` sidecar are still there. `--control PATH` or `--control HOST:PORT` sends that same `send` or `recv` to a running `genesisd` instead of calling the library. `export` lines publish directories, and `mount.genesis` mounts one over the same protocol. The operator manual is `docs/user-guide.md`. See also `config/genesis.conf.example`, `docs/USAGE.md`, and `docs/VFS.md`.

## Layout

| Path | Role |
| --- | --- |
| `src/core` | Wire format, handshake, FEC, BBR, crypto, STUN, mesh. No sockets. |
| `src/posix` | UDP, session, config jail, daemonize |
| `src/embedded` | Entropy hook for a socket-free static library |
| `apps/cli`, `apps/daemon` | Thin clients |
| `apps/mount` | `mount.genesis`, the FUSE client |
| `tests/test_main.cpp` | Vectors, FEC, engine, jail, VFS, SPSC ring |
| `packaging` | systemd and OpenRC, not installed into the running system by the build |
| `docker` | Alpine image that builds and runs `ctest` |

## Further reading

- `docs/ARCHITECTURE.md`
- `docs/PROTOCOL.md`
- `docs/SECURITY.md`
- `docs/CHROOT_AUDIT.md`
- `docs/EMBEDDED.md`
- `docs/USAGE.md`
- `docs/VFS.md`
- `docs/NAT.md`
