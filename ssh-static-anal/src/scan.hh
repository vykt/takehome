#pragma once

#include <vector>

#include "cmn.hh"
#include "pe.hh"


namespace scan {

const constexpr int is_ssh = 1;
const constexpr int is_not_ssh = 2;

[[nodiscard]] int do_scan(byte * file_map, const std::vector<pe::scan_ent> & scan_set) noexcept;

} //end namespace `scan`
