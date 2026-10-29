#include <string.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "compat.h"
#include "app_common.h"

int app_main(void)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q, Qp;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_gcm_context gcm;
    unsigned char secret[32], keys[32], iv[12] = {0}, tag[16], pt[64] = {0}, ct[64];
    app_common_run();
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, app_entropy, NULL, (const unsigned char *)"tls", 3);
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&Qp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ecp_copy(&Qp, &Q);
    C_ECDH_COMPUTE(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_mpi_write_binary(&z, secret, sizeof(secret));
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, secret, 32,
                 (const unsigned char *)"key", 3, keys, 32);
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, keys, 128);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(pt), iv, sizeof(iv), NULL, 0, pt, ct, 16, tag);
    app_consume(ct, sizeof(ct));
    app_consume(tag, sizeof(tag));
    mbedtls_gcm_free(&gcm);
    mbedtls_ecp_group_free(&grp);
    return 0;
}
