#include <optional>
#include <vector>

#include <cstring>
#include <cstddef>

#include <unistd.h>

#include "cmn.hh"
#include "pe.hh"


#define _NOT_A_EXEC 1
[[nodiscard]] static int _process_msdos_hdr(byte * file_map, pe::msdos_hdr *& msdos_hdr) noexcept {

    msdos_hdr = reinterpret_cast<pe::msdos_hdr *>(file_map);
    if (memcmp(msdos_hdr->magic, pe::msdos_magic, sizeof(pe::msdos_magic)) != 0) {
        cmn::err = cmn::err_exec;
        return _NOT_A_EXEC;
    }
    
    return 0;
}


#define _IS_MACH64 1
#define _IS_MACH32 2
[[nodiscard]] static int _process_pe_hdrs(byte * file_map, pe::nt_hdr *& nt_hdr, const off_t off) noexcept {

    bool is_64bit;

    nt_hdr = reinterpret_cast<pe::nt_hdr *>(file_map + off);
    if (memcmp(nt_hdr->v64.magic, pe::nt_magic, sizeof(pe::nt_magic)) != 0) {
        cmn::err = cmn::err_pe;
        return -1;
    }

    if (memcmp(nt_hdr->v64.img_hdr.mach, pe::mach_x86_64, sizeof(pe::mach_x86_64)) == 0) return _IS_MACH64;
    else if (memcmp(nt_hdr->v32.img_hdr.mach, pe::mach_x86, sizeof(pe::mach_x86)) == 0) return _IS_MACH32;
    else return -1;    

    return 0;
}


[[nodiscard]] static std::optional<pe::scan_ent>
    _process_sect_hdr(byte * file_map, const off_t off) noexcept {

    pe::sect_hdr * sect_hdr = reinterpret_cast<pe::sect_hdr *>(file_map + off);

    //skip ommitted sections
    for (int i = 0; i < pe::omit_sect_num; i += 1)
        if (strncmp(reinterpret_cast<const char *>(file_map + off), pe::omit_sect[i], 0x8) == 0) return std::nullopt;

    return pe::scan_ent(reinterpret_cast<off_t>(file_map + sect_hdr->file_off), sect_hdr->file_sz);
}


std::optional<std::vector<pe::scan_ent>> pe::get_scan_set(byte * file_map) {

    int mach;
    int sect_hdr_num;
    off_t sect_hdr_start_off;

    std::vector<pe::scan_ent> scan_set;
    std::optional<pe::scan_ent> ent;

    pe::msdos_hdr * msdos_hdr;
    pe::nt_hdr * nt_hdr;

    if (_process_msdos_hdr(file_map, msdos_hdr) == -1) return std::nullopt;
    if ((mach = _process_pe_hdrs(file_map, nt_hdr, msdos_hdr->e_lfanew)) == -1) return std::nullopt;

    //find start of section headers
    if (mach == _IS_MACH64) {
        sect_hdr_num = nt_hdr->v64.img_hdr.sect_num;
        sect_hdr_start_off = nt_hdr->v64.img_opt_hdr64.hdr_sz;
    } else {
        sect_hdr_num = nt_hdr->v32.img_hdr.sect_num;
        sect_hdr_start_off = nt_hdr->v32.img_opt_hdr32.hdr_sz;
    }

    for (int i = 0; i < sect_hdr_num; i += 1) {

        ent = _process_sect_hdr(file_map, sect_hdr_start_off + (sizeof(pe::sect_hdr) * i));
        if (ent.has_value()) scan_set.push_back(*ent);
    }

    return scan_set;
} 
