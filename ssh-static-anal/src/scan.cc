#include <vector>

#include "cmn.hh"
#include "pe.hh"
#include "scan.hh"


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

static void _scan_sect(byte * file_map, bool sig_found[sig_sz], const pe::scan_ent & ent) {

    char cur;
    off_t sig_off[sig_sz] = {0};
    
    //for each byte in section
    for (off_t i = 0; i < ent.get_sz(); ++i) {

        //for each signature being scanned for
        cur = *(file_map + ent.get_off() + i);
        for (int j = 0; i < sig_sz; ++j) {
            //match case
            if (cur == sig[j][sig_off[j]]) {
                if (sig_off[j] == sig_len[j]) { sig_found[j] = true; sig_found[j] = 0; }
            //non-match case
            } else {
                sig_off[j] = 0;
            }
        }
    }

    return;   
}

[[nodiscard]] int scan::do_scan(byte * file_map, const std::vector<pe::scan_ent> & scan_set) noexcept {

    int ret;
    int wgt;
    bool done;
    bool sig_found[sig_sz] = {0};

    //process scan set
    for (auto it = scan_set.cbegin(); it != scan_set.cend(); ++it) {

        _scan_sect(file_map, sig_found, *it);
        done = true;
        for (int i = 0; i < sig_sz; ++i) if (sig_found[i] ==  false) done = false;
        if (done) break;
    }

    //determine if ssh
    wgt = 0;
    for (int i = 0; i < sig_sz; ++i) if (sig_found[i]) wgt += sig_wgt[i];

    return wgt >= sig_thresh ? scan::is_ssh : scan::is_not_ssh;
}
