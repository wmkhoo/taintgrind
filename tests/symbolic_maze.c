#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "taintgrind.h"

#define H 7
#define W 11
#define ITERS 28

static char maze[H][W] = {
   "+-+---+---+",
   "| |     |#|",
   "| | --+ | |",
   "| |   | | |",
   "| +-- | | |",
   "|     |   |",
   "+-----+---+"
};

int main(int argc, char **argv)
{
   int x = 1;
   int y = 1;
   int ox;
   int oy;
   int i = 0;
   char program[ITERS];

   if (read(0, program, ITERS) != ITERS) {
      return 3;
   }
   TNT_TAINT(program, ITERS);

   maze[y][x] = 'X';

   while (i < ITERS) {
      ox = x;
      oy = y;

      switch (program[i]) {
         case 'w':
            y--;
            break;
         case 's':
            y++;
            break;
         case 'a':
            x--;
            break;
         case 'd':
            x++;
            break;
         default:
            return 4;
      }

      if (maze[y][x] == '#') {
         return 1;
      }

      if (maze[y][x] != ' ' &&
          !((y == 2 && maze[y][x] == '|' && x > 0 && x < W))) {
         x = ox;
         y = oy;
      }

      if (ox == x && oy == y) {
         return 10 + i;
      }

      maze[y][x] = 'X';
      i++;
   }

   return 5;
}
