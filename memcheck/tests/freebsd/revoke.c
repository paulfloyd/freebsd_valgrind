#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
 
 int main()
 {
     const char* filename = strdup("revoke.tst");
     int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
     
     revoke(filename);
     free(filename);
     revoke(filename);
 }
