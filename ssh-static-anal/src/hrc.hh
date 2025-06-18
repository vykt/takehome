#pragma once

namespace hrc {

//set of sections to scan
const constexpr char * sect[] = {
    ".text",
    ".rdata",
    ".data",
    ".rsrc",
    ".tls"
};
    
} //end namespace `hrc`
