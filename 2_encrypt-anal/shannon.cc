#include <iostream>

#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

using byte = unsigned char;

static uintptr_t _freq[UINT8_MAX + 1] = {0};

using file_state = struct {

    int fd;
    byte * map;
    size_t map_sz;

};
static file_state _state;

using _magic = struct {
    byte buf[8];
    int len;
    const char * name;
};
const constexpr int _magics_sz = 8;
static _magic _magics[_magics_sz] = {
    {{0x1f, 0x9d}, 2, "tar"},                          //tar
    {{0x42, 0x5a, 0x68}, 3, "bzip2"},                  //bzip2
    {{0x4c, 0x5a, 0x49, 0x50}, 4, "lzip"},             //lzip
    {{0x50, 0x4b, 0x03, 0x04}, 4, "zip"},              //zip et al.
    {{0x50, 0x4b, 0x05, 0x06}, 4, "zip (empty)"},      //zip - empty
    {{0x50, 0x4b, 0x07, 0x08}, 4, "zip (spanned)"},    //zip - spanned
    {{0x1f, 0x8b}, 2, "gzip"},                         //gzip
    {{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, 6, "7-zip"} //7-zip
    /* others as required */
};

const constexpr double _thresh = 7.5;


[[nodiscard]] static int _setup_file(const char * file_path) noexcept {

    struct stat file_stat;

    _state.fd = open(file_path, O_RDONLY);
    if (_state.fd == -1) {
        std::cerr << "Failed to open " << file_path << " for reading." << std::endl;
        return -1;
    }

    if (stat(file_path, &file_stat)) {
        std::cerr << "Failed to stat " << file_path << "." << std::endl;
        goto _setup_file_fail;
    }
    _state.map_sz = file_stat.st_size;

    _state.map = reinterpret_cast<byte *>(mmap(nullptr, file_stat.st_size, PROT_READ, MAP_PRIVATE, _state.fd, 0x0));
    if (!_state.map) {
        std::cerr << "Failed to mmap " << file_path << "." << std::endl;
        goto _setup_file_fail;
    }

    return 0;

    _setup_file_fail:
    if(close(_state.fd)) std::cerr << "Failed to close opened fd on " << file_path << "." << std::endl;
    return -1;
}


static void _teardown_file() noexcept {

    if (munmap(_state.map, _state.map_sz)) std::cerr << "Failed to unmap the target." << std::endl;
    if (close(_state.fd)) std::cerr << "Failed to close the fd on the target." << std::endl;

    return;
}


[[nodiscard]] static double _shannon() noexcept {

    //get freqs
    memset(_freq, 0, (UINT8_MAX + 1) * (sizeof(uintptr_t)));
    for (byte * i = _state.map; i < (_state.map + _state.map_sz); ++i) {
        _freq[*i] += 1;
    }

    //calc entropy
    double H = 0.0;
    double px;
    for (int i = 0; i < UINT8_MAX + 1; ++i) {
        if (_freq[i] > 0) {
            px = _freq[i] / (double) _state.map_sz;
            H += px * log2(px);
        }
    }
    H = std::abs(H);

    return H;
}


[[nodiscard]] static int _is_compressed() noexcept {

    bool is_match;

    //for each compressed format
    for (int i = 0; i < _magics_sz; ++i) {

        is_match = true;
        for (int j = 0; j < _magics[i].len; ++j) {
            if (_state.map[j] != _magics[i].buf[j]) {is_match = false; break;}
        }
        if (is_match) return i;
    }

    return -1;
}


int main(int argc, char ** argv) {

    int magic_idx;
    double entropy;

    if (argc < 2) {
        std::cerr << "use: shannon <file_0> [file_n]" << std::endl;
        exit(-1);
    } 

    for (int i = 1; i < argc; ++i) {

        if (_setup_file(argv[i])) exit(-1);

        std::cout << "File: " << argv[i] << std::endl;
        if ((magic_idx = _is_compressed()) > -1) {
            std::cout << "File's magic matches: " << _magics[magic_idx].name << std::endl;
        }

        entropy = _shannon();
        std::cout << "Entropy: " << entropy << " | Encrypted: "
                  << ((magic_idx == -1 && entropy >= _thresh) ? "likely" : "unlikely")
                  << std::endl;

        if (i != (argc - 1)) std::cout << std::endl;
        _teardown_file();
    }

    return 0;
}
