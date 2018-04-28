/* misprint.c */
#include <stdio.h>
#include <stdlib.h>
#include "taintgrind.h"

void hello_function()
{
    printf("INFO: Hello World!\n");
}

/* 
 * $ VAL=`readelf -s misprint | grep secret_function | awk '{print $2}'` && printf "%d\n" 0x$VAL
 */
void secret_function()
{
    printf("INFO: Oh no! The application is compromised!\n");
}

int main(int argc, char** argv)
{

    int i;
    int val;
    int iter;
    int buffer[10];
    int canary;
    void (*func)(void);

    if (argc != 3) { return(1); }

    iter = atoi(argv[1]);
    val = atoi(argv[2]);

    TNT_TAINT( &val, sizeof(val));

    /* It should print Hello World! */
    func = &hello_function; 

    canary = 123; //UNINTIALIZED;

    /* If iter > 10 then a buffer overflow will occur */
    for (i = 0; i < iter; i++)
        buffer[i] = val;

    /* 
     * ... if the buffer overflow is "severe enough", 
     * it may overwrite the function pointer with user data, 
     * e.g. a pointer to the secret function
     */
    func();

    return(0);
}
