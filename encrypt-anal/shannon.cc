#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>


static int _freq[UINT8_MAX + 1] = {0};
#define BUF_SZ 4096


int main() {

    //track entropy change
    for (int x = 0; x <= BUF_SZ; x += (BUF_SZ / 32)) {

        //build evenly distributed pseudo buffer
        unsigned char buf[BUF_SZ];
        for (int i = 0; i < BUF_SZ; ++i) {
            buf[i] = i;
        }

        //reduce entropy
        memset(buf, 'a', x);

        //get freqs
        memset(_freq, 0, (UINT8_MAX + 1) * (sizeof(int)));
        for (int i = 0; i < BUF_SZ; ++i) {
            _freq[buf[i]] += 1;
        }

        //calc entropy
        double H = 0.0;
        double px;
        for (int i = 0; i < UINT8_MAX + 1; ++i) {
            if (_freq[i] > 0) {
                px = _freq[i] / (double) BUF_SZ;
                H += px * log2(px);
            }
        }
        H *= -1;

        printf("x: %d | H: %f\n", x, H);

    }

    return 0;
}
