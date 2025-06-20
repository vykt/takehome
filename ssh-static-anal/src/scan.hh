#pragma once

#include <vector>

#include "cmn.hh"
#include "pe.hh"


namespace scan {

const constexpr int sig_sz = 8;
const constexpr char * sig[sig_sz] = {
    "SSH",
    "SSH-1",
    "SSH-2",
    "3des-cbc",                      //required by RFC 4253
    "aes128-cbc",                    //recommended by RFC 4253
    "diffie-hellman-group14-sha256", //"strongly recommended" by RFC 8268
    "diffie-hellman-group\?\?-sha512",
    "rsa-sha2-256"                   //required by RFC 8268
    /* [...] */
};
const constexpr int sig_len[sig_sz] = {
    3,
    5,
    5,
    8,
    10,
    29,
    31,
    12
};
const constexpr int sig_wgt[sig_sz] = {
    2,
    4,
    4,
    2,
    2,
    4,
    4,
    4
};
const constexpr int sig_thresh = 10; 

[[nodiscard]] int do_scan(const std::vector<pe::scan_ent> & scan_set, bool sig_found[sig_sz]) noexcept;

} //end namespace `scan`
