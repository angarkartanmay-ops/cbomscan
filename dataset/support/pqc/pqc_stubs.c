/* Non-secure randombytes for the dataset builds (PQClean API). Images are for static analysis only. */
#include <stddef.h>
#include <stdint.h>
static uint32_t s_rng = 0x2468ACEu;
int PQCLEAN_randombytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        s_rng = s_rng * 1103515245u + 12345u;
        out[i] = (uint8_t)(s_rng >> 16);
    }
    return 0;
}
