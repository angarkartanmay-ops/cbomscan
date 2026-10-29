/* LMS/HSS signature verification via Cisco hash-sigs (verify-only build).
 * LMS_KEY=<array name from lms_pubkeys.h> embeds a public key in the image;
 * LMS_NOKEY reads the key from a flash-mapped address at run time instead (nothing embedded). */
#include <stdint.h>
#include <string.h>
#include "hss.h"
#include "lms_pubkeys.h"
volatile uint32_t g_sink;
static unsigned char sig[3000], msg[64];
#ifdef LMS_NOKEY
static unsigned char pk[60];
static const volatile unsigned char *g_key_src = (const volatile unsigned char *)0x3F800000u;
#else
#define pk LMS_KEY
#endif
int app_main(void)
{
#ifdef LMS_NOKEY
    for (int i = 0; i < 60; i++) pk[i] = g_key_src[i];
#endif
    bool ok = hss_validate_signature(pk, msg, sizeof(msg), sig, sizeof(sig), NULL);
    g_sink ^= (uint32_t)ok;
    return ok ? 0 : 1;
}
