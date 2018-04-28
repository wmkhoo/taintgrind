#include "taintgrind.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_sign(int x){
	if (x == 0){
		return 0;
	}
	if (x < 0){
		return -1;
	}
	return 1;
}

int main(int argc, char **argv){
	int a = atoi(argv[1]);
	//Defines int as tainted
	TNT_TAINT_NAMED(&a,4,"myint");
	int s = get_sign(a);
	return s;
}
