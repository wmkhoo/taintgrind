#include "taintgrind.h"
int get_sign(long x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}
int main(int argc, char **argv)
{
    // Turns on printing
    //TNT_START_PRINT();
    long a = 1000;
    // Defines int a as tainted
    TNT_TAINT(&a,sizeof(a));
    int s = get_sign(a);
    // Turns off printing
    //TNT_STOP_PRINT();
    return s;
}
