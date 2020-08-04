#include <stdio.h>
#include "taintgrind.h"
int get_sign(int x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}
int main(int argc, char **argv)
{
    int a = 1000, b, c[10], i;
    unsigned int t;
    // Defines int a as tainted
    TNT_TAINT(&a,sizeof(a));
    b = get_sign(a);
    c[5] = a;
    c[7] = a & 8;

    TNT_IS_TAINTED(t, &a, sizeof(a));
    if (t)
        printf("a is_tainted: %08x\n", t);

    TNT_IS_TAINTED(t, &b, sizeof(b));
    if (t)
        printf("b is_tainted: %08x\n", t);

    for(i=0; i<10; i++) {
        TNT_IS_TAINTED(t, &c[i], sizeof(c[i]));
        if (t)
            printf("c[%d] is_tainted: %08x\n", i, t);
    }
    return 0;
}
