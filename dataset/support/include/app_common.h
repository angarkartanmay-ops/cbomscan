#ifndef APP_COMMON_H
#define APP_COMMON_H

#include <stddef.h>
#include <stdint.h>

extern volatile uint32_t g_sink;
int app_entropy(void *ctx, unsigned char *out, size_t len);
int app_rng(void *ctx, unsigned char *out, size_t len);
void app_consume(const void *p, size_t n);
void app_common_run(void);
int esp_sha_hw_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
int esp_aes_hw_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif
