#include "cmn.hh"
#include "pe.hh"

#include <optional>
#include <vector>
#include <iostream>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>


static struct option _long_opts[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {0,0,0,0}
};


[[nodiscard]] static const char * _process_args(const int argc, char ** argv) noexcept {
    
    int opt, opt_idx;

    while (((opt = getopt_long(argc, argv, "v", _long_opts, &opt_idx)) != -1)
           && (opt != 0)) { if (opt == 'v') cmn::verbose = true; } 

    if (optind + 1 != argc) {
        std::cerr << "Provide a target file to scan. Use: ./ssh-anal [-v] <file>" << std::endl;
        return nullptr;
    }

    return argv[optind];
}


[[nodiscard]] static int _setup_file(const char * file_path) noexcept {

    struct stat file_stat;

    cmn::state.fd = open(file_path, O_RDONLY);
    if (cmn::state.fd == -1) {
        std::cerr << "Failed to open " << file_path << " for reading." << std::endl;
        return -1;
    }

    if (stat(file_path, &file_stat)) {
        std::cerr << "Failed to stat " << file_path << "." << std::endl;
        goto _setup_file_fail;
    }
    cmn::state.map_sz = file_stat.st_size;

    cmn::state.map = reinterpret_cast<byte *>(mmap(nullptr, file_stat.st_size, PROT_READ, MAP_PRIVATE, cmn::state.fd, 0x0));
    if (!cmn::state.map) {
        std::cerr << "Failed to mmap " << file_path << "." << std::endl;
        goto _setup_file_fail;
    }

    return 0;

    _setup_file_fail:
    if(close(cmn::state.fd)) std::cerr << "Failed to close opened fd on " << file_path << "." << std::endl;
    return -1;
}


static void _teardown_file() noexcept {

    if (munmap(cmn::state.map, cmn::state.map_sz)) std::cerr << "Failed to unmap the target." << std::endl;
    if (close(cmn::state.fd)) std::cerr << "Failed to close the fd on the target." << std::endl;

    return;
}


int main(int argc, char ** argv) {

    const char * file_path;

    file_path = _process_args(argc, argv);
    if (!file_path) exit(-1);
    
    if (_setup_file(file_path)) exit(-1);

    std::optional<std::vector<pe::scan_ent>> scan_set = pe::get_scan_set();

    _teardown_file();
}
