#include <string.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/sha512.h"
#include "compat.h"
#include "app_common.h"

int app_main(void)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q;
    mbedtls_chachapoly_context cp;
    unsigned char secret[32], key[64], nonce[12] = {0}, tag[16], pt[48] = {0}, ct[48];
    app_common_run();
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_gen_public(&grp, &d, &Q, app_rng, NULL);
    C_ECDH_COMPUTE(&grp, &z, &Q, &d, app_rng, NULL);
    mbedtls_mpi_write_binary(&z, secret, sizeof(secret));
    C_SHA512(secret, sizeof(secret), key);
    mbedtls_chachapoly_init(&cp);
    mbedtls_chachapoly_setkey(&cp, key);
    mbedtls_chachapoly_encrypt_and_tag(&cp, sizeof(pt), nonce, NULL, 0, pt, ct, tag);
    app_consume(ct, sizeof(ct));
    app_consume(tag, sizeof(tag));
    mbedtls_ecp_group_free(&grp);
    return 0;
}
