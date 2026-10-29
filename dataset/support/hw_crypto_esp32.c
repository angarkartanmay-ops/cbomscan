#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define REG32(a) (*(volatile uint32_t *)(a))

#define SHA_TEXT_BASE        0x3FF03000u
#define SHA_256_START_REG    0x3FF03090u
#define SHA_256_CONTINUE_REG 0x3FF03094u
#define SHA_256_LOAD_REG     0x3FF03098u
#define SHA_256_BUSY_REG     0x3FF0309Cu

#define AES_START_REG        0x3FF01000u
#define AES_IDLE_REG         0x3FF01004u
#define AES_MODE_REG         0x3FF01008u
#define AES_KEY_BASE         0x3FF01010u
#define AES_TEXT_BASE        0x3FF01030u

static void esp_sha_hw_wait(void)
{
    while (REG32(SHA_256_BUSY_REG) != 0) {
    }
}

static void esp_sha_hw_block(const uint8_t *blk, int first)
{
    for (int i = 0; i < 16; i++) {
        uint32_t w = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) |
                     ((uint32_t)blk[4 * i + 2] << 8) | blk[4 * i + 3];
        REG32(SHA_TEXT_BASE + 4u * (uint32_t)i) = w;
    }
    REG32(first ? SHA_256_START_REG : SHA_256_CONTINUE_REG) = 1;
    esp_sha_hw_wait();
}

int esp_sha_hw_sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t blk[64];
    size_t off = 0;
    int first = 1;
    uint64_t bits = (uint64_t)len * 8u;
    while (len - off >= 64) {
        esp_sha_hw_block(in + off, first);
        first = 0;
        off += 64;
    }
    size_t rem = len - off;
    memset(blk, 0, sizeof(blk));
    memcpy(blk, in + off, rem);
    blk[rem] = 0x80;
    if (rem >= 56) {
        esp_sha_hw_block(blk, first);
        first = 0;
        memset(blk, 0, sizeof(blk));
    }
    for (int i = 0; i < 8; i++) {
        blk[63 - i] = (uint8_t)(bits >> (8 * i));
    }
    esp_sha_hw_block(blk, first);
    REG32(SHA_256_LOAD_REG) = 1;
    esp_sha_hw_wait();
    for (int i = 0; i < 8; i++) {
        uint32_t w = REG32(SHA_TEXT_BASE + 4u * (uint32_t)i);
        out[4 * i] = (uint8_t)(w >> 24);
        out[4 * i + 1] = (uint8_t)(w >> 16);
        out[4 * i + 2] = (uint8_t)(w >> 8);
        out[4 * i + 3] = (uint8_t)w;
    }
    return 0;
}

int esp_aes_hw_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    for (int i = 0; i < 4; i++) {
        uint32_t k;
        memcpy(&k, key + 4 * i, 4);
        REG32(AES_KEY_BASE + 4u * (uint32_t)i) = k;
    }
    REG32(AES_MODE_REG) = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t t;
        memcpy(&t, in + 4 * i, 4);
        REG32(AES_TEXT_BASE + 4u * (uint32_t)i) = t;
    }
    REG32(AES_START_REG) = 1;
    while (REG32(AES_IDLE_REG) != 1) {
    }
    for (int i = 0; i < 4; i++) {
        uint32_t t = REG32(AES_TEXT_BASE + 4u * (uint32_t)i);
        memcpy(out + 4 * i, &t, 4);
    }
    return 0;
}
