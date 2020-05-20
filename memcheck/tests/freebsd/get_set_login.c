#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    // can't go wrong?
    char* me = getlogin();
    
    // setlogin needs root privs
    char* bogus = strdup("nobody");
    setlogin(bogus);
    free(bogus);
    setlogin(bogus);
}
