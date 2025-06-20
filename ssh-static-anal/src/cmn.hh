#pragma once

#include <string>


#ifdef DEBUG
    #define _PRIVATE public
    #define _PROTECTED public
#else
    #define _PRIVATE private
    #define _PROTECTED protected
#endif


using byte = unsigned char;


namespace cmn {

extern bool verbose;

using file_state = struct _file_state {
    int fd;
    byte * map;
    size_t map_sz;
};
extern file_state state;

extern __thread int err;
const constexpr int err_exec = 1;
const constexpr int err_pe = 2;

} //end namespace `cmn`
