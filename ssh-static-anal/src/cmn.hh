#pragma once

#include <string>


#ifdef DEBUG
    #define _PRIVATE public
    #define _PROTECTED public
#else
    #define _PRIVATE private
    #define _PROTECTED protected
#endif


namespace cmn {

extern bool verbose;
extern const char * tgt_path;

extern int err;
const constexpr int err_exec = 1;
const constexpr int err_pe = 2;

} //end namespace `cmn`
