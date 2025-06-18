#pragma once

#include <cstdint>


using byte = unsigned char;


namespace pe {

/*
 *  NOTE: Padding implies both literal padding and simply fields that are irrelevant.
 */

const constexpr byte msdos_magic[0x2] = {0x4d, 0x5a};
const constexpr byte nt_magic[0x4] = {0x50, 0x45, 0x0, 0x0};

const constexpr byte mach_x86[0x2] = {0x01, 0x4c};
const constexpr byte mach_x86_64[0x2] = {0x88, 0x64};

const constexpr byte img_opt_pe_magic[0x2] = {0x01, 0x0b};
const constexpr byte img_opt_pep_magic[0x2] = {0x02, 0x0b};

using msdos_stub = struct {
    byte magic[0x2];
    byte _pad_0[0x3a];
    uint32_t e_lfanew;
} __attribute__((packed));

using img_hdr = struct {
    byte mach[0x2];    //ignored by windows PE loader
    uint16_t sect_num;
    byte _pad_0[0x4];
    uint32_t symtab_ptr;
    uint32_t sym_num;
    uint16_t opt_hdr_sz;
    byte _pad_1[0x2];
} __attribute__((packed));

using img_opt_hdr64 = struct {
    byte magic[2];
    byte _pad_0[2];
    uint32_t text_sz;
    uint32_t data_sz;
    uint32_t bss_sz;
    byte _pad_1[0x14];
    uint32_t file_align;
    uint32_t _pad_2[0x10];
    uint32_t img_sz;
    uint32_t hdr_sz;
    byte _pad_3[0xb0];
} __attribute__((packed));

using img_opt_hdr = struct {
    byte magic[2];
    byte _pad_0[2];
    uint32_t text_sz;
    uint32_t data_sz;
    uint32_t bss_sz;
    byte _pad_1[0x14];
    uint32_t file_align;
    uint32_t _pad_2[0x10];
    uint32_t img_sz;
    uint32_t hdr_sz;
    byte _pad_3[0xa0];
} __attribute__((packed));

using nt_hdr64 = struct {
    byte magic[0x4];
    img_hdr img_hdr;
    img_opt_hdr64 img_opt_hdr64;
} __attribute__((packed));

using nt_hdr = struct {
    byte magic[0x4];
    img_hdr img_hdr;
    img_opt_hdr img_opt_hdr;
} __attribute__((packed));

using sect_hdr = struct {
    char name[0x8];
    byte _pad_0[0x8];
    uint32_t file_sz;
    uint32_t file_off;
    byte _pad_1[0x10];
} __attribute__((packed));

} //end namespace `pe`
