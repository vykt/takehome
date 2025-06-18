#include "cmn.hh"
#include "pe.hh"
#include "hrc.hh"

#include <iostream>

#include <getopt.h>
#include <unistd.h>


static struct option _long_opts[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {0,0,0,0}
};


[[nodiscard]] static int _process_args(const int argc, char ** argv) noexcept {
    
    int opt, opt_idx;

    while (((opt = getopt_long(argc, argv, "v", _long_opts, &opt_idx)) != -1)
           && (opt != 0)) { if (opt == 'v') cmn::verbose = true; } 

    if (optind + 1 != argc) {
        std::cerr << "Provide a target file to scan. Use: ./ssh-anal [-v] <file>";
        return -1;
    }
    cmn::tgt_path = argv[optind];

    return 0;
}


int main(int argc, char ** argv) {

    if (_process_args(argc, argv)) exit(-1);
}
