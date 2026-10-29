#include <stdint.h>
#include "mlkem_native.h"
volatile uint32_t g_sink;
static uint8_t pk[MLKEM_PUBLICKEYBYTES(768)], sk[MLKEM_SECRETKEYBYTES(768)], ct[MLKEM_CIPHERTEXTBYTES(768)];
static uint8_t ss1[32], ss2[32], coins64[64], coins32[32];
int app_main(void)
{
    int r = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(pk, sk, coins64);
    r |= PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(ct, ss1, pk, coins32);
    r |= PQCP_MLKEM_NATIVE_MLKEM768_dec(ss2, ct, sk);
    g_sink ^= (uint32_t)r ^ ss2[0];
    return r;
}
