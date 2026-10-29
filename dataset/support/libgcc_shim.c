#include <stdint.h>

typedef unsigned long long u64;
typedef long long s64;

static uint32_t udiv32(uint32_t n, uint32_t d, uint32_t *rem)
{
    uint32_t q = 0, r = 0;
    for (int i = 31; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1u);
        if (r >= d) {
            r -= d;
            q |= 1u << i;
        }
    }
    if (rem) {
        *rem = r;
    }
    return q;
}

static u64 udiv64(u64 n, u64 d, u64 *rem)
{
    u64 q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1u);
        if (r >= d) {
            r -= d;
            q |= (u64)1 << i;
        }
    }
    if (rem) {
        *rem = r;
    }
    return q;
}

uint32_t __udivsi3(uint32_t n, uint32_t d) { return udiv32(n, d, 0); }

uint32_t __umodsi3(uint32_t n, uint32_t d)
{
    uint32_t r;
    udiv32(n, d, &r);
    return r;
}

int32_t __divsi3(int32_t a, int32_t b)
{
    int neg = (a < 0) ^ (b < 0);
    uint32_t q = udiv32(a < 0 ? (uint32_t)-a : (uint32_t)a, b < 0 ? (uint32_t)-b : (uint32_t)b, 0);
    return neg ? -(int32_t)q : (int32_t)q;
}

u64 __udivdi3(u64 n, u64 d) { return udiv64(n, d, 0); }

u64 __umoddi3(u64 n, u64 d)
{
    u64 r;
    udiv64(n, d, &r);
    return r;
}

s64 __divdi3(s64 a, s64 b)
{
    int neg = (a < 0) ^ (b < 0);
    u64 q = udiv64(a < 0 ? (u64)-a : (u64)a, b < 0 ? (u64)-b : (u64)b, 0);
    return neg ? -(s64)q : (s64)q;
}

s64 __moddi3(s64 a, s64 b)
{
    u64 r;
    udiv64(a < 0 ? (u64)-a : (u64)a, b < 0 ? (u64)-b : (u64)b, &r);
    return a < 0 ? -(s64)r : (s64)r;
}

u64 __umulsidi3(uint32_t a, uint32_t b)
{
    uint32_t al = a & 0xFFFFu, ah = a >> 16, bl = b & 0xFFFFu, bh = b >> 16;
    u64 ll = (u64)(al * bl);
    u64 lh = (u64)(al * bh);
    u64 hl = (u64)(ah * bl);
    u64 hh = (u64)(ah * bh);
    return ll + (lh << 16) + (hl << 16) + (hh << 32);
}

u64 __muldi3(u64 a, u64 b)
{
    uint32_t al = (uint32_t)a, ah = (uint32_t)(a >> 32), bl = (uint32_t)b, bh = (uint32_t)(b >> 32);
    return __umulsidi3(al, bl) + ((u64)(al * bh + ah * bl) << 32);
}
