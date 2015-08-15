#include "taintgrind.h"
int get_sign(char x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}
int main(int argc, char **argv)
{
    // Turns on printing
    TNT_START_PRINT();
    char a = 10;
    // Defines int a as tainted
    TNT_MAKE_MEM_TAINTED(&a,1);
    int s = get_sign(a);
    // Turns off printing
    TNT_STOP_PRINT();
    return s;
}
