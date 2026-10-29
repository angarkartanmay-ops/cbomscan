#ifndef CBOMSCAN_COMPAT_H
#define CBOMSCAN_COMPAT_H

#include "mbedtls/version.h"

#if MBEDTLS_VERSION_MAJOR >= 3
#define C_MD5(i, n, o) mbedtls_md5((i), (n), (o))
#define C_SHA1(i, n, o) mbedtls_sha1((i), (n), (o))
#define C_SHA256(i, n, o) mbedtls_sha256((i), (n), (o), 0)
#define C_SHA512(i, n, o) mbedtls_sha512((i), (n), (o), 0)
#define C_RSA_INIT(ctx) mbedtls_rsa_init((ctx))
#define C_PK_PARSE_PUB(ctx, k, n) mbedtls_pk_parse_public_key((ctx), (k), (n))
#define C_ECDH_COMPUTE(grp, z, q, d, rng, prng) mbedtls_ecdh_compute_shared((grp), (z), (q), (d), (rng), (prng))
#define C_RSA_PKCS1_SIGN(ctx, rng, prng, md, hlen, h, sig) mbedtls_rsa_pkcs1_sign((ctx), (rng), (prng), (md), (hlen), (h), (sig))
#define C_RSA_PSS_VERIFY(ctx, md, hlen, h, sig) mbedtls_rsa_rsassa_pss_verify((ctx), (md), (hlen), (h), (sig))
#define C_GEN_KEYPAIR_RSA(ctx, rng, prng) mbedtls_rsa_gen_key((ctx), (rng), (prng), 2048, 65537)
#define C_DHM_MAKE_PUBLIC(ctx, x, out, olen, rng, prng) mbedtls_dhm_make_public((ctx), (x), (out), (olen), (rng), (prng))
#define C_SET_PADDING_PSS(ctx) mbedtls_rsa_set_padding((ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256)
#define C_PK_VERIFY_EC(pk, md, h, hl, s, sl) mbedtls_pk_verify((pk), (md), (h), (hl), (s), (sl))
#else
#define C_MD5(i, n, o) mbedtls_md5_ret((i), (n), (o))
#define C_SHA1(i, n, o) mbedtls_sha1_ret((i), (n), (o))
#define C_SHA256(i, n, o) mbedtls_sha256_ret((i), (n), (o), 0)
#define C_SHA512(i, n, o) mbedtls_sha512_ret((i), (n), (o), 0)
#define C_RSA_INIT(ctx) mbedtls_rsa_init((ctx), MBEDTLS_RSA_PKCS_V15, 0)
#define C_PK_PARSE_PUB(ctx, k, n) mbedtls_pk_parse_public_key((ctx), (k), (n))
#define C_ECDH_COMPUTE(grp, z, q, d, rng, prng) mbedtls_ecdh_compute_shared((grp), (z), (q), (d), (rng), (prng))
#define C_RSA_PKCS1_SIGN(ctx, rng, prng, md, hlen, h, sig) mbedtls_rsa_pkcs1_sign((ctx), (rng), (prng), MBEDTLS_RSA_PRIVATE, (md), (hlen), (h), (sig))
#define C_RSA_PSS_VERIFY(ctx, md, hlen, h, sig) mbedtls_rsa_rsassa_pss_verify((ctx), NULL, NULL, MBEDTLS_RSA_PUBLIC, (md), (hlen), (h), (sig))
#define C_GEN_KEYPAIR_RSA(ctx, rng, prng) mbedtls_rsa_gen_key((ctx), (rng), (prng), 2048, 65537)
#define C_DHM_MAKE_PUBLIC(ctx, x, out, olen, rng, prng) mbedtls_dhm_make_public((ctx), (x), (out), (olen), (rng), (prng))
#define C_SET_PADDING_PSS(ctx) mbedtls_rsa_set_padding((ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256)
#define C_PK_VERIFY_EC(pk, md, h, hl, s, sl) mbedtls_pk_verify((pk), (md), (h), (hl), (s), (sl))
#endif

#endif
