#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "compat.h"
#include "app_common.h"
#include "embedded_keys.h"

static unsigned char s_image[4096];
static unsigned char s_sig[104];

int app_main(void)
{
    unsigned char hash[48] = {0}, blk[16], key[16] = {3};
    mbedtls_pk_context pk;
    app_common_run();
    esp_sha_hw_sha256(s_image, sizeof(s_image), hash);
    esp_aes_hw_encrypt_block(key, hash, blk);
    app_consume(blk, sizeof(blk));
    mbedtls_pk_init(&pk);
    int ret = C_PK_PARSE_PUB(&pk, p384_pub_der, sizeof(p384_pub_der));
    if (ret == 0) {
        ret = C_PK_VERIFY_EC(&pk, MBEDTLS_MD_SHA384, hash, 48, s_sig, sizeof(s_sig));
    }
    mbedtls_pk_free(&pk);
    g_sink ^= (uint32_t)ret;
    return ret;
}
