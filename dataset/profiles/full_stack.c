#include "app_common.h"

int full_ota_rsa(void);
int full_ota_ecdsa(void);
int full_tls(void);
int full_x25519(void);
int full_legacy(void);
int full_ffdh(void);
int full_sym(void);
int full_hw(void);

int app_main(void)
{
    int r = 0;
    r |= full_ota_rsa();
    r |= full_ota_ecdsa();
    r |= full_tls();
    r |= full_x25519();
    r |= full_legacy();
    r |= full_ffdh();
    r |= full_sym();
    r |= full_hw();
    return r;
}
