#include <string.h>
#include "mbedtls/dhm.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/sha1.h"
#include "compat.h"
#include "app_common.h"

static const unsigned char s_p[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
static const unsigned char s_g[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

int app_main(void)
{
    mbedtls_dhm_context dhm;
    mbedtls_mpi P, G;
    mbedtls_aes_context aes;
    unsigned char pub[256], key[16], iv[16] = {0}, pt[64] = {0}, ct[64], mac[20];
    app_common_run();
    mbedtls_dhm_init(&dhm);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_read_binary(&P, s_p, sizeof(s_p));
    mbedtls_mpi_read_binary(&G, s_g, sizeof(s_g));
    mbedtls_dhm_set_group(&dhm, &P, &G);
    C_DHM_MAKE_PUBLIC(&dhm, 256, pub, sizeof(pub), app_rng, NULL);
    memcpy(key, pub, sizeof(key));
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(pt), iv, pt, ct);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, sizeof(key), ct, sizeof(ct), mac);
    app_consume(ct, sizeof(ct));
    app_consume(mac, sizeof(mac));
    mbedtls_dhm_free(&dhm);
    return 0;
}
