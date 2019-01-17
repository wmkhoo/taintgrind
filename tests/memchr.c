#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "taintgrind.h"

int main() {
    int n = 100;
    int found = 0;
    char * str = malloc(n);
    char * str2;
    memset(str,'a',n);
    TNT_TAINT(str,n);

    for (int k = 0; k < 10; k++) {
        str2 = memchr(str,'p',strlen(str));
	if (str2 != NULL ) {
	    found = 1;
	}
    }

    return 0;
}
