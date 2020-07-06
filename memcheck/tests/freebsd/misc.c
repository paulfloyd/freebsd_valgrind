/* 
 * Tests miscellaneous syscalls
 * 
 * uuidgen
 * genrandom
 * 
 */

#include <sys/types.h>
#include <sys/uuid.h>
#include <sys/random.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../../config.h"

int main(void)
{
   struct uuid s;
   if (-1 == uuidgen(&s, 1))
   {
      perror("uuidgen failed:");
   }
   
   struct uuid v[10];
   if (-1 == uuidgen(v, 10))
   {
      perror("uuidgen failed:");
   }
   
#if (FREEBSD_VERS >= FREEBSD_12)

   char buf[100];
   if (-1 == getrandom(buf, 100, GRND_NONBLOCK))
   {
      perror("getrandom failed:");
   }
   
#endif   
   
   // error section
   struct uuid* ps = malloc(2*sizeof(struct uuid));
   uuidgen(ps, 3);
   int badint;
   uuidgen(&s, badint);
   
#if (FREEBSD_VERS >= FREEBSD_12)

   char* buf2 = malloc(100);
   free(buf2);
   
   getrandom(buf2, 100, 0);
   getrandom(buf, badint, badint);
   
#endif   
   
   free(ps);
   
}
