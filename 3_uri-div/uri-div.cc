#include <iostream>
#include <string>
#include <regex>

#include <cstring>
#include <unistd.h>


//RFC 3986 Appendix B (pg. 50-51)
const constexpr char * _rfc_regex = R"(^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)";
static std::regex _uri_re(_rfc_regex);
using _uri_reg_match = enum {
    SCHEME = 2,
    AUTHORITY = 4,
    PATH = 5,
    QUERY = 7,
    FRAGMENT = 9 
};

//split authority into user:auth & host:port
const constexpr char * _authority_regex = R"(^((?:[^@\?])*)?@?((?:[^$\/\?])*))";
static std::regex _authority_re(_authority_regex);
using _authority_reg_match = enum {
    USER_HOST = 1,
    HOST = 2
};


[[nodiscard]] static int _divide_authority(
                            const std::string & auth_str) {

    std::smatch match;
    if (!std::regex_search(auth_str, match, _authority_re) || match.size() != 3) {
        std::cerr << "\nAuthority regex error." << std::endl;
        return -1;
    }

    if (!match.str(2).empty()) {
        std::cout << "\n - User & pass: " << match.str(USER_HOST)
                  << "\n - Host & port: " << match.str(HOST);
    } else {
        std::cout << "\n - Host & port: " << match.str(USER_HOST);
    }


    return 0;
}


[[nodiscard]] static int _divide_uri(const std::string & uri_str) {

    bool is_valid;

    std::cout << "URI: " << uri_str << "\n" 
              << std::string(5 + uri_str.length(), '-') << std::endl;

    std::smatch match;
    if (!std::regex_search(uri_str, match, _uri_re)) {
        std::cerr << "\tURI regex error." << std::endl;
        return -1;
    }
    
    if (match.str(SCHEME).empty()) {
        std::cout << "WARN: Not a valid generic URI\n";
        if (match.str(PATH).empty()) std::cout << "ERR:  Not a valid relative URI\n";
    }

    std::cout << "Scheme:    " << match.str(SCHEME)
              << "\nAuthority: " << match.str(AUTHORITY);
    if (_divide_authority(match.str(AUTHORITY))) return -1;
    if (strncmp(match.str(SCHEME).c_str(), "mailto", 6) == 0)
        std::cout << "\n - NOTE: `mailto`'s authority component is part of the Path component by design.";

    std::cout << "\nPath:      " << match.str(PATH)
              << "\nQuery:     " << match.str(QUERY)
              << "\nFragment:  " << match.str(FRAGMENT) << std::endl;

    return 0;
}


int main(int argc, char ** argv) {

    if (argc < 2) {
        std::cerr << "Use: uri-div \"<URI_1>\" \"[URI_N]\"" << std::endl;
        return -1;
    }

    for (int i = 1; i < argc; ++i) {
        if (i != 1) std::cout << "\n";
        try {
            if (_divide_uri(argv[i])) {}; //no need to handle        
        } catch (const std::regex_error & excp) {
            std::cerr << "Argument \"" << argv[i] << "\" caused throw: "
                      << excp.what() << std::endl;
            return -1;
        }
    }

    return 0;
}

