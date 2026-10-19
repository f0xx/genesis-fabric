#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

struct Sha256 {
    Sha256();
    void update(const uint8_t* data, size_t len);
    void final(uint8_t out[32]);
    static void hash(const uint8_t* data, size_t len, uint8_t out[32]);

    uint32_t state[8]{};
    uint64_t bits = 0;
    uint8_t block[64]{};
    size_t n = 0;
};

struct Sha1 {
    Sha1();
    void update(const uint8_t* data, size_t len);
    void final(uint8_t out[20]);
    static void hash(const uint8_t* data, size_t len, uint8_t out[20]);

    uint32_t state[5]{};
    uint64_t bits = 0;
    uint8_t block[64]{};
    size_t n = 0;
};

struct Md5 {
    Md5();
    void update(const uint8_t* data, size_t len);
    void final(uint8_t out[16]);
    static void hash(const uint8_t* data, size_t len, uint8_t out[16]);

    uint32_t state[4]{};
    uint64_t bits = 0;
    uint8_t block[64]{};
    size_t n = 0;
};

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]);
void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[20]);

/* HKDF-SHA256 (RFC 5869). */
bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);

void chacha20_xor(uint8_t* dst, const uint8_t* src, size_t len, const uint8_t key[32],
                  const uint8_t nonce[12], uint32_t counter);

/* RFC 8439 ChaCha20-Poly1305. cipher_cap must be >= plain_len + 16. */
bool aead_encrypt(uint8_t* cipher, size_t cipher_cap, size_t* cipher_len, const uint8_t* plain,
                  size_t plain_len, const uint8_t* aad, size_t aad_len, const uint8_t key[32],
                  const uint8_t nonce[12]);
bool aead_decrypt(uint8_t* plain, size_t plain_cap, size_t* plain_len, const uint8_t* cipher,
                  size_t cipher_len, const uint8_t* aad, size_t aad_len, const uint8_t key[32],
                  const uint8_t nonce[12]);

/* X25519 (RFC 7748). Scalar is clamped internally. */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t pubkey[32], const uint8_t scalar[32]);
void x25519_keypair(uint8_t pubkey[32], uint8_t secret[32]);

bool random_bytes(uint8_t* dst, size_t n);

/* Returns 0 when the Curve25519 field arithmetic matches known products. */
int field_selftest();

uint32_t crc32_ieee(const uint8_t* data, size_t len);

}  // namespace genesis
