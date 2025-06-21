#include <vector>
#include <iostream>

#include "cmn.hh"
#include "pe.hh"
#include "scan.hh"


static void _scan_sect(bool sig_found[scan::sig_sz], const pe::scan_ent & ent) {

    char cur;
    off_t sig_off[scan::sig_sz] = {0};
    
    //for each byte in section
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wsign-compare"
    for (off_t i = 0; i < ent.get_sz(); ++i) {
    #pragma GCC diagnostic pop

        //for each signature being scanned for
        cur = *(cmn::state.map + ent.get_off() + i);
        for (int j = 0; j < scan::sig_sz; ++j) {

            //match case
            if (cur == scan::sig[j][sig_off[j]]) {
                if (sig_off[j] == (scan::sig_len[j] - 1)) { sig_found[j] = true; sig_off[j] = 0; }
                else sig_off[j] += 1;
            //non-match case
            } else {
                sig_off[j] = 0;
            }
        }
    }

    return;   
}


void dbg_scan_sect(bool sig_found[scan::sig_sz], const pe::scan_ent & ent) {_scan_sect(sig_found, ent);}

[[nodiscard]] int scan::do_scan(const std::vector<pe::scan_ent> & scan_set, bool sig_found[scan::sig_sz]) noexcept {

    int wgt;
    bool done;

    //process scan set
    for (auto it = scan_set.cbegin(); it != scan_set.cend(); ++it) {

        _scan_sect(sig_found, *it);
        done = true;
        for (int i = 0; i < sig_sz; ++i) if (sig_found[i] == false) done = false;
        if (done) break;
    }

    //return total weight
    wgt = 0;
    for (int i = 0; i < sig_sz; ++i) if (sig_found[i]) wgt += sig_wgt[i];
    return wgt;
}
