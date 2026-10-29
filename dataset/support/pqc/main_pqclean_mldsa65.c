#include <stdint.h>
#include <stddef.h>
#include "api.h"
volatile uint32_t g_sink;
static uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES], sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
static uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES], msg[64];
int app_main(void)
{
    size_t siglen = 0;
    int r = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
    r |= PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, msg, sizeof(msg), sk);
    r |= PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk);
    g_sink ^= (uint32_t)r ^ (uint32_t)siglen;
    return r;
}
