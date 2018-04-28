#include <stdio.h>
#include <string.h>
#include "taintgrind.h"

int main() {
    unsigned char input[30];
    unsigned char totaintIn[30];
    size_t n = 30;
    totaintIn[0] = 'a';
    totaintIn[1] = 'b';
    totaintIn[2] = 'c';
    totaintIn[3] = 0;
    TNT_TAINT(totaintIn, 30);
    memcpy( input, totaintIn, n );
    return 0;
}
