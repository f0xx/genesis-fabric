# Bare metal

Compile the core translation units with a freestanding C++20 compiler. Do not link `src/posix`. Time comes from a hardware timer converted to microseconds. Entropy comes from the board TRNG through `genesis::embedded_set_random`. The read and write callbacks are memory or flash, not `FILE`. Details are in `docs/EMBEDDED.md`.
