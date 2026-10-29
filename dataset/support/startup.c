#include <stdint.h>

extern int app_main(void);
extern uint32_t _bss_start, _bss_end;

void __attribute__((section(".iram1.entry"), noreturn)) call_start_cpu0(void)
{
    for (uint32_t *p = &_bss_start; p < &_bss_end; p++) {
        *p = 0;
    }
    app_main();
    for (;;) {
    }
}

void _exit(int code)
{
    (void)code;
    for (;;) {
    }
}
