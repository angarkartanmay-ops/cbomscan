#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#define JSMN_STATIC
#include "jsmn.h"
#include "printf.h"
#include "miniz.h"
#include "app_common.h"

volatile uint32_t g_sink;
static uint32_t s_seed = 0x1234567u;

void _putchar(char c)
{
    g_sink ^= (uint32_t)(unsigned char)c;
}

int app_entropy(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        s_seed = s_seed * 1103515245u + 12345u;
        out[i] = (unsigned char)(s_seed >> 16);
    }
    return 0;
}

int app_rng(void *ctx, unsigned char *out, size_t len)
{
    return app_entropy(ctx, out, len);
}

void app_consume(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc = (acc << 5) ^ (acc >> 27) ^ b[i];
    }
    g_sink ^= acc;
}

int app_telemetry_json(char *out, size_t cap, int temp, int hum)
{
    return snprintf_(out, cap, "{\"temp\":%d,\"hum\":%d,\"dev\":\"%s\",\"up\":%lu}", temp, hum, "node-07",
                     (unsigned long)g_sink);
}

static int tok_eq(const char *js, const jsmntok_t *t, const char *s)
{
    return t->type == JSMN_STRING && (int)strlen(s) == t->end - t->start &&
           strncmp(js + t->start, s, (size_t)(t->end - t->start)) == 0;
}

int app_parse_config(const char *txt)
{
    jsmn_parser p;
    jsmntok_t t[16];
    jsmn_init(&p);
    int n = jsmn_parse(&p, txt, strlen(txt), t, 16);
    for (int i = 1; i + 1 < n; i++) {
        if (tok_eq(txt, &t[i], "interval")) {
            return atoi(txt + t[i + 1].start);
        }
    }
    return 60;
}

unsigned long app_compress_log(const unsigned char *in, unsigned long n, unsigned char *out, unsigned long cap)
{
    mz_ulong dlen = cap;
    if (mz_compress(out, &dlen, in, n) != MZ_OK) {
        return 0;
    }
    g_sink ^= (uint32_t)mz_crc32(MZ_CRC32_INIT, out, dlen);
    g_sink ^= (uint32_t)mz_adler32(MZ_ADLER32_INIT, out, dlen);
    return dlen;
}

void app_common_run(void)
{
    char buf[128];
    unsigned char z[256];
    int n = app_telemetry_json(buf, sizeof(buf), 23, 41);
    printf_("boot %d\n", n);
    g_sink ^= (uint32_t)app_parse_config("{\"interval\":30}");
    g_sink ^= (uint32_t)app_compress_log((const unsigned char *)buf, (unsigned long)n, z, sizeof(z));
}
