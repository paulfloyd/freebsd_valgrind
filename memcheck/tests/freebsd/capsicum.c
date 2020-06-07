#include <sys/capsicum.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>

int main(void)
{
    u_int mode;
    if (-1 == cap_getmode(&mode)) {
        perror("cap_getmode() failed:");
        exit(1);
    } else {
        assert(mode == 0U);
    }
    
    // example from man cap_rights_get
    cap_rights_t setrights, getrights;
    int fd;

    memset(&setrights, 0, sizeof(setrights));
    memset(&getrights, 0, sizeof(getrights));

    fd = open("capsicum.c", O_RDONLY);
    if (fd < 0)
       err(1, "open() failed");

    cap_rights_init(&setrights, CAP_FSTAT, CAP_READ);
    if (cap_rights_limit(fd, &setrights) < 0 && errno != ENOSYS)
        err(1, "cap_rights_limit() failed");

    if (cap_rights_get(fd, &getrights) < 0 && errno != ENOSYS)
       err(1, "cap_rights_get() failed");

    assert(memcmp(&setrights, &getrights, sizeof(setrights)) == 0);
    
   //close(fd);

   cap_enter();
    
   if (-1 == cap_getmode(&mode)) {
      perror("cap_getmode() failed:");
      exit(1);
   } else {
      assert(mode != 0U);
   }

   // error section
    
   int *px = malloc(sizeof(int));
   int x = px[0];
    
   cap_getmode(NULL);
    
   cap_rights_get(0, NULL);
   cap_rights_get(x, &getrights);
   cap_rights_t* badrights = malloc(sizeof(cap_rights_t));
   cap_rights_init(badrights, CAP_FSTAT, CAP_READ);
   free(badrights);
   cap_rights_get(0, badrights);
    
   cap_rights_limit(x, &setrights);
   
   cap_rights_limit(fd, badrights);
   
   int fd2 = open("foo", O_RDWR);
   if (fd2 >= 0)
       err(1, "open in write mode should have failed");
}
