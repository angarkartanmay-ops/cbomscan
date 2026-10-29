#include <stdint.h>

typedef struct {
    uint32_t magic_word;
    uint32_t secure_version;
    uint32_t reserv1[2];
    char version[32];
    char project_name[32];
    char time[16];
    char date[16];
    char idf_ver[32];
    uint8_t app_elf_sha256[32];
    uint16_t min_efuse_blk_rev_full;
    uint16_t max_efuse_blk_rev_full;
    uint8_t mmu_page_size;
    uint8_t reserv3[3];
    uint32_t reserv2[18];
} app_desc_t;

#ifndef CBOM_PROJECT
#define CBOM_PROJECT "cbomscan-sample"
#endif
#ifndef CBOM_VERSION
#define CBOM_VERSION "1.0.0"
#endif

const __attribute__((section(".rodata_desc"), used)) app_desc_t esp_app_desc = {
    .magic_word = 0xABCD5432u,
    .secure_version = 0,
    .version = CBOM_VERSION,
    .project_name = CBOM_PROJECT,
    .time = "00:00:00",
    .date = "Oct 29 2026",
    .idf_ver = "v6.0-sim",
    .min_efuse_blk_rev_full = 0,
    .max_efuse_blk_rev_full = 199,
    .mmu_page_size = 16,
};
