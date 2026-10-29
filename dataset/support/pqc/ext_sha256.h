/* hash-sigs external SHA-256 hook (EXT_SHA256_H): route SHA256_* to mbedTLS instead of OpenSSL. */
#include "mbedtls/sha256.h"
typedef mbedtls_sha256_context SHA256_CTX;
static inline void SHA256_Init(SHA256_CTX *c) { mbedtls_sha256_init(c); mbedtls_sha256_starts(c, 0); }
static inline void SHA256_Update(SHA256_CTX *c, const void *d, unsigned int n) { mbedtls_sha256_update(c, d, n); }
static inline void SHA256_Final(unsigned char *o, SHA256_CTX *c) { mbedtls_sha256_finish(c, o); mbedtls_sha256_free(c); }
