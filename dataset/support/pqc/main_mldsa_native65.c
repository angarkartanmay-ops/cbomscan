#include <stdint.h>
#include <stddef.h>
#include "mldsa_native.h"
volatile uint32_t g_sink;
static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)], sk[MLDSA_SECRETKEYBYTES(65)], sig[MLDSA_BYTES(65)], msg[64];
static uint8_t seed[MLDSA_SEEDBYTES], rnd[MLDSA_RNDBYTES];
int app_main(void)
{
    int r = PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, sk, seed);
    r |= PQCP_MLDSA_NATIVE_MLDSA65_signature_internal(sig, msg, sizeof(msg), NULL, 0, rnd, sk, 0);
    r |= PQCP_MLDSA_NATIVE_MLDSA65_verify(sig, msg, sizeof(msg), NULL, 0, pk);
    g_sink ^= (uint32_t)r;
    return r;
}
