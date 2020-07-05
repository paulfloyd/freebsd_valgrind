#include <sys/statvfs.h>
#include <stdlib.h>

int main()
{
   struct statvfs fs;

   // OK
   statvfs("/", &fs);
   
   struct statvfs* pfs;
   
   pfs = malloc(sizeof(struct statvfs));
   free(pfs);
   
   // invalid write
   statvfs("/", pfs);

   pfs = malloc(sizeof(struct statvfs) - 3);
   statvfs("/", pfs);
   
   free(pfs);
   

}
