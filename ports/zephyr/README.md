# Zephyr

Link `genesis_core_embedded` from the Zephyr CMake app and do not compile `src/posix`. Install entropy with `genesis::embedded_set_random` before `Engine::start`. Feed `on_datagram` from the UDP receive callback and transmit whatever `pop` returns. Details are in `docs/EMBEDDED.md`.
