#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "compat.h"
#include "app_common.h"

static unsigned char s_sig[256];
static unsigned char s_csr[512];

int app_main(void)
{
    mbedtls_rsa_context rsa;
    mbedtls_ctr_drbg_context drbg;
    unsigned char h[32];
    app_common_run();
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, app_entropy, NULL, (const unsigned char *)"id", 2);
    C_RSA_INIT(&rsa);
    C_GEN_KEYPAIR_RSA(&rsa, mbedtls_ctr_drbg_random, &drbg);
    C_SHA256(s_csr, sizeof(s_csr), h);
    C_RSA_PKCS1_SIGN(&rsa, mbedtls_ctr_drbg_random, &drbg, MBEDTLS_MD_SHA256, 32, h, s_sig);
    app_consume(s_sig, sizeof(s_sig));
    mbedtls_rsa_free(&rsa);
    return 0;
}
