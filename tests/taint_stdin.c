#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

long getSizeOfInput(FILE *input, char *buffer){
   long retvalue = 0;
   int c;

   if (input != stdin) {
//      if (-1 == fseek(input, 0L, SEEK_END)) {
//         fprintf(stderr, "Error seek end: %s\n", strerror(errno));
//         exit(EXIT_FAILURE);
//      }
//      if (-1 == (retvalue = ftell(input))) {
//         fprintf(stderr, "ftell failed: %s\n", strerror(errno));
//         exit(EXIT_FAILURE);
//      }
//      if (-1 == fseek(input, 0L, SEEK_SET)) {
//         fprintf(stderr, "Error seek start: %s\n", strerror(errno));
//         exit(EXIT_FAILURE);
//      }
   } else {
      /* for stdin, we need to read in the entire stream until EOF */
      while (EOF != (c = fgetc(input))) {
         buffer[retvalue] = c;
         retvalue++;
      }
   }
   buffer[retvalue] = 0;
   return retvalue;
}

int main(int argc, char **argv) {
   FILE *input;
   char buffer[256];

   if (argc > 1) {
//      if(!strcmp(argv[1],"-")) {
         input = stdin;
//      } else {
//         input = fopen(argv[1],"r");
//         if (NULL == input) {
//            fprintf(stderr, "Unable to open '%s': %s\n",
//                  argv[1], strerror(errno));
//            exit(EXIT_FAILURE);
//         }
//      }
   } else {
      input = stdin;
   }

   printf("Size of file: %ld\n", getSizeOfInput(input, buffer));
   printf("%s\n", buffer);

   return EXIT_SUCCESS;
}
