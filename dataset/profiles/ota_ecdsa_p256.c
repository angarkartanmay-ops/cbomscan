#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "compat.h"
#include "app_common.h"
#include "embedded_keys.h"

static unsigned char s_image[2048];
static unsigned char s_sig[72];

int app_main(void)
{
    unsigned char hash[32];
    mbedtls_pk_context pk;
    app_common_run();
    C_SHA256(s_image, sizeof(s_image), hash);
    mbedtls_pk_init(&pk);
    int ret = C_PK_PARSE_PUB(&pk, p256_pub_der, sizeof(p256_pub_der));
    if (ret == 0) {
        ret = C_PK_VERIFY_EC(&pk, MBEDTLS_MD_SHA256, hash, 32, s_sig, sizeof(s_sig));
    }
    mbedtls_pk_free(&pk);
    g_sink ^= (uint32_t)ret;
    return ret;
}
