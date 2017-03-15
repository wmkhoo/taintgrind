//#include "taintgrind.h"
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

	// Turns on printing
	TNT_START_PRINT();

	//Defines int as tainted
	TNT_MAKE_MEM_TAINTED_NAMED(&a,4,"myint");
	int s = get_sign(a);

	// Turns off printing
	TNT_STOP_PRINT();
	return s;
}
