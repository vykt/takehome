#include <optional>
#include <vector>
#include <iostream>

#include <cstring>
#include <cstddef>

#include <unistd.h>

#include "cmn.hh"
#include "pe.hh"


#define _NOT_A_EXEC 1
[[nodiscard]] static int _process_msdos_hdr(pe::msdos_hdr *& msdos_hdr) noexcept {

    msdos_hdr = reinterpret_cast<pe::msdos_hdr *>(cmn::state.map);
    if (memcmp(msdos_hdr->magic, pe::msdos_magic, sizeof(pe::msdos_magic)) != 0) {
        cmn::err = cmn::err_exec;
        return _NOT_A_EXEC;
    }
    
    return 0;
}


#define _IS_MACH64 1
#define _IS_MACH32 2
[[nodiscard]] static int _process_pe_hdrs(pe::nt_hdr *& nt_hdr, const off_t off) noexcept {

    nt_hdr = reinterpret_cast<pe::nt_hdr *>(cmn::state.map + off);
    if (memcmp(nt_hdr->v64.magic, pe::nt_magic, sizeof(pe::nt_magic)) != 0) {
        cmn::err = cmn::err_pe;
        return -1;
    }

    if (memcmp(nt_hdr->v64.img_h.mach, pe::mach_x86_64, sizeof(pe::mach_x86_64)) == 0) return _IS_MACH64;
    else if (memcmp(nt_hdr->v32.img_h.mach, pe::mach_x86, sizeof(pe::mach_x86)) == 0) return _IS_MACH32;
    else return -1;    

    return 0;
}


[[nodiscard]] static std::optional<pe::scan_ent>
    _process_sect_hdr(const off_t off) noexcept {

    const char * sym;
    pe::sect_hdr * sect_hdr = reinterpret_cast<pe::sect_hdr *>(cmn::state.map + off);
    if (cmn::verbose) std::cout << "Found section: " << sect_hdr->name << std::endl;

    //skip ommitted sections
    for (int i = 0; i < pe::omit_sect_num; i += 1) {
        sym = reinterpret_cast<const char *>(cmn::state.map + off);
        if (strncmp(sym, pe::omit_sect[i], 0x8) == 0) return std::nullopt;
    }

    return pe::scan_ent(sect_hdr->file_off, sect_hdr->file_sz);
}


std::optional<std::vector<pe::scan_ent>> pe::get_scan_set() {

    int mach;
    int sect_hdr_num;
    off_t sect_hdr_start_off;

    std::vector<pe::scan_ent> scan_set;
    std::optional<pe::scan_ent> ent;

    pe::msdos_hdr * msdos_hdr;
    pe::nt_hdr * nt_hdr;

    if (_process_msdos_hdr(msdos_hdr) == -1) return std::nullopt;
    if ((mach = _process_pe_hdrs(nt_hdr, msdos_hdr->e_lfanew)) == -1) return std::nullopt;

    //find start of section headers
    if (mach == _IS_MACH64) {
        sect_hdr_num = nt_hdr->v64.img_h.sect_num;
        sect_hdr_start_off = nt_hdr->v64.img_opt_h64.hdr_sz;
    } else {
        sect_hdr_num = nt_hdr->v32.img_h.sect_num;
        sect_hdr_start_off = (uintptr_t) &nt_hdr->v32.img_opt_h32 - (uintptr_t) msdos_hdr
                             + nt_hdr->v32.img_h.opt_hdr_sz;
    }

    for (int i = 0; i < sect_hdr_num; i += 1) {
        ent = _process_sect_hdr(sect_hdr_start_off + (sizeof(pe::sect_hdr) * i));
        if (ent.has_value()) scan_set.push_back(*ent);
    }

    if (cmn::verbose) {
        std::cout << "scan_set size: " << scan_set.size() << std::hex << std::endl;
        for (auto it = scan_set.cbegin(); it != scan_set.cend(); ++it)
            std::cout << "off: 0x" << it->get_off() << " sz: 0x" << it->get_sz() << std::endl;
        std::cout << std::dec;
    }
    return scan_set;
} 
