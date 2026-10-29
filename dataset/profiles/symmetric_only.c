#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "compat.h"
#include "app_common.h"

int app_main(void)
{
    mbedtls_aes_context aes;
    unsigned char key[32] = {7}, nc[16] = {0}, sb[16], pt[96] = {0}, ct[96], mac[32], h[64];
    size_t off = 0;
    app_common_run();
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_ctr(&aes, sizeof(pt), &off, nc, sb, pt, ct);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, sizeof(key), ct, sizeof(ct), mac);
    C_SHA512(ct, sizeof(ct), h);
    app_consume(ct, sizeof(ct));
    app_consume(mac, sizeof(mac));
    app_consume(h, sizeof(h));
    mbedtls_aes_free(&aes);
    return 0;
}
