#include <string.h>
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/des.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "compat.h"
#include "app_common.h"

static unsigned char s_sig[256];

int app_main(void)
{
    unsigned char m5[16], s1[20], key[24] = {1}, iv[8] = {0}, pt[64] = {0}, ct[64];
    mbedtls_des3_context d3;
    mbedtls_rsa_context rsa;
    mbedtls_ctr_drbg_context drbg;
    app_common_run();
    C_MD5(pt, sizeof(pt), m5);
    C_SHA1(pt, sizeof(pt), s1);
    mbedtls_des3_init(&d3);
    mbedtls_des3_set3key_enc(&d3, key);
    mbedtls_des3_crypt_cbc(&d3, MBEDTLS_DES_ENCRYPT, sizeof(pt), iv, pt, ct);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, app_entropy, NULL, NULL, 0);
    C_RSA_INIT(&rsa);
    C_GEN_KEYPAIR_RSA(&rsa, mbedtls_ctr_drbg_random, &drbg);
    C_RSA_PKCS1_SIGN(&rsa, mbedtls_ctr_drbg_random, &drbg, MBEDTLS_MD_SHA1, 20, s1, s_sig);
    app_consume(m5, sizeof(m5));
    app_consume(ct, sizeof(ct));
    app_consume(s_sig, sizeof(s_sig));
    mbedtls_rsa_free(&rsa);
    return 0;
}
