/*
 * Test this family of functions
 *    extattr_get_fd, extattr_set_fd, extattr_delete_fd, extattr_list_fd,
 *    extattr_get_file, extattr_set_file, extattr_delete_file,
 *    extattr_list_file, extattr_get_link, extattr_set_link,
 *    extattr_delete_link, extattr_list_link - system calls to manipulate VFS
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <string.h>

int main()
{
    ssize_t n;
    char buff[64];
    // valid calls even though "test1" does not exist
    n = extattr_get_file("test1", EXTATTR_NAMESPACE_USER, "bar", NULL, 0);
    (void)extattr_get_file("test1", EXTATTR_NAMESPACE_USER, "bar", buff, sizeof(buff));
    
    // now some invalid calls
    int uninit;
    (void)extattr_get_file("test1", uninit, "bar", buff, sizeof(buff));
    
    char* badbuff = malloc(64);
    free(badbuff);
    (void)extattr_get_file("test1", EXTATTR_NAMESPACE_USER, "bar", badbuff, 64);
    
    char* badstring = strdup("test2");
    free(badstring);
    (void)extattr_get_file(badstring, EXTATTR_NAMESPACE_USER, "bar", buff, sizeof(buff));
    (void)extattr_get_file("test1", EXTATTR_NAMESPACE_USER, badstring, buff, sizeof(buff));
    
    extattr_get_file("test1", EXTATTR_NAMESPACE_USER, "bar", buff, uninit);

}
