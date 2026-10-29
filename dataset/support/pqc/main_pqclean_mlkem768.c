#include <stdint.h>
#include "api.h"
volatile uint32_t g_sink;
static uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES], sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
static uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES], ss1[32], ss2[32];
int app_main(void)
{
    int r = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    r |= PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss1, pk);
    r |= PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    g_sink ^= (uint32_t)r ^ ss2[0];
    return r;
}
