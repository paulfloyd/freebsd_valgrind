#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
 
 int main()
 {
     const char* filename = strdup("chflags.tst");
     int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
     
     fchflags(fd, UF_APPEND);
     
     // a couple of errors while the file is open
     int* pfd = malloc(sizeof(int));
     unsigned long* pflags = malloc(sizeof(unsigned long));
     
     *pfd = fd;
     *pflags = UF_NODUMP;
     
     free(pfd);
     
     fchflags(*pfd, UF_REPARSE);
     
     free(pflags);
     
     fchflags(fd, *pflags);

     close(fd);
     
     chflags(filename, UF_SYSTEM);
     lchflags(filename, UF_SYSTEM);
     
     chflags(filename, *pflags);
     lchflags(filename, *pflags);
     
     free((void*)filename);
     
     chflags(filename, UF_SYSTEM);
     lchflags(filename, UF_SYSTEM);

 }
