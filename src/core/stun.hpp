#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

struct StunResult {
    bool ok = false;
    uint8_t family = 1;
    uint16_t port = 0;
    uint8_t addr[16]{};
    int addr_len = 0;
};

/* Build a Binding Request. transaction_id is 12 bytes. */
size_t stun_binding_request(uint8_t* dst, size_t cap, const uint8_t tid[12]);

/* Parse a Binding Success. Returns false if the cookie, length, or tid do not match. */
bool stun_parse_binding_response(const uint8_t* msg, size_t len, const uint8_t tid[12], StunResult& out);

/* XOR-MAPPED-ADDRESS and XOR-RELAYED-ADDRESS share this layout. */
bool stun_parse_xor_addr(const uint8_t* attr, size_t len, uint16_t* port, uint8_t* addr, int* addr_len);

uint32_t stun_fingerprint(const uint8_t* msg, size_t len_before_attr);

/* MESSAGE-INTEGRITY over the STUN prefix. key_len is 16 for the TURN MD5 long-term key
 * or 20-plus for a short-term password. */
bool stun_add_integrity_and_fingerprint(uint8_t* msg, size_t* len, size_t cap, const uint8_t* key,
                                       size_t key_len);
bool stun_check_integrity(const uint8_t* msg, size_t len, const uint8_t* key, size_t key_len);

size_t turn_allocate_request(uint8_t* dst, size_t cap, const uint8_t tid[12]);

}  // namespace genesis
