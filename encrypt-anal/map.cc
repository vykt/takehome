#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


const constexpr char * file_basename = "putty.exe";

int main() {

    int ret, fd;
    unsigned char * file_map;

    struct stat st;
    ret = stat(file_basename, &st);
    if (ret != 0) return -1;

    fd = open(file_basename, O_RDONLY);
    if (fd == -1) return -1; 

    file_map = (unsigned char *) mmap(
                   nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_map == nullptr) return -1;

    //[...]

    ret = munmap(file_map, st.st_size);
    if (ret != 0) return -1;

    ret = close(fd);
    if (ret != 0) return -1; 

    return 0;
}
