# ESP-IDF

Add the core sources, or link a prebuilt `libgenesis_core_embedded.a`, with `-Isrc/core`. Provide entropy through `esp_fill_random` via `genesis::embedded_set_random`. The Wi-Fi or Ethernet event task calls `tick` and drains `pop`. Details are in `docs/EMBEDDED.md`.
