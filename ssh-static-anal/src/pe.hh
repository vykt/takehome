#pragma once

#include <optional>
#include <vector>
#include <cstdint>
#include "cmn.hh"


namespace pe {

// -- [PE headers]

const constexpr byte msdos_magic[0x2] = {0x4d, 0x5a};
const constexpr byte nt_magic[0x4] = {0x50, 0x45, 0x0, 0x0};

const constexpr byte mach_x86[0x2] = {0x4c, 0x01};
const constexpr byte mach_x86_64[0x2] = {0x64, 0x86};

const constexpr byte img_opt_pe_magic[0x2] = {0x01, 0x0b};
const constexpr byte img_opt_pep_magic[0x2] = {0x02, 0x0b};

using msdos_hdr = struct {
    byte magic[0x2];
    byte _pad_0[0x3a];
    uint32_t e_lfanew;
} __attribute__((packed));

using img_hdr = struct {
    byte mach[0x2];
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
    byte _pad_2[0x10];
    uint32_t img_sz;
    uint32_t hdr_sz;
    byte _pad_3[0xb0];
} __attribute__((packed));

using img_opt_hdr32 = struct {
    byte magic[2];
    byte _pad_0[2];
    uint32_t text_sz;
    uint32_t data_sz;
    uint32_t bss_sz;
    byte _pad_1[0x14];
    uint32_t file_align;
    byte _pad_2[0x10];
    uint32_t img_sz;
    uint32_t hdr_sz;
    byte _pad_3[0xa0];
} __attribute__((packed));

using nt_hdr64 = struct {
    byte magic[0x4];
    img_hdr img_h;
    img_opt_hdr64 img_opt_h64;
} __attribute__((packed));

using nt_hdr32 = struct {
    byte magic[0x4];
    img_hdr img_h;
    img_opt_hdr32 img_opt_h32;
} __attribute__((packed));

using nt_hdr = union {
    nt_hdr64 v64;
    nt_hdr32 v32;
};

using sect_hdr = struct {
    char name[0x8];
    byte _pad_0[0x8];
    uint32_t file_sz;
    uint32_t file_off;
    byte _pad_1[0x10];
} __attribute__((packed));


// --- [Misc.]

struct scan_ent {

    _PRIVATE:
    off_t off;
    uint32_t sz;
    const char * name;

    public:
    scan_ent(off_t _off, size_t _sz, const char * _name) noexcept : off(_off), sz(_sz), name(_name) {}
    inline off_t get_off() const noexcept { return this->off; }
    inline size_t get_sz() const noexcept { return this->sz; }    
    inline const char * get_name() const noexcept { return this->name; }
};

const constexpr int omit_sect_num = 3;
const constexpr char * omit_sect[omit_sect_num] = {
    ".pdata",
    ".xdata",
    ".reloc"
};

std::optional<std::vector<scan_ent>> get_scan_set();

} //end namespace `pe`
