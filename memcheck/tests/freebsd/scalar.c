/* Basic syscall test, see memcheck/tests/x86-linux/scalar.c for more info. */

#include <unistd.h>
#include <fcntl.h>
#include "scalar.h"
#include "config.h"

/* Helper functions.  These are necessary if we've got two tests for a single
   syscall.  In that case, Memcheck can sometimes merge error messages.  Doing
   each test in its own function prevents that. */


int main(void)
{
   /* Uninitialised, but we know px[0] is 0x0. */
   /* PJF why ? */
   long *px = malloc(sizeof(long));
   x0 = px[0];
   
   /* SYS_syscall                 0 */
   /* does this need a specific test? There are two diffeent IDs for syscall, see 198 */
   
   /* SYS_exit                    1 */
   /* obviously an exit syscall needs to be last */
   GO(SYS_exit, "below");
   
   /* SYS_fork                    2 */
   /* @todo PJF add scalar_fork,c */
    GO(SYS_fork, "@todo");

   /* SYS_read                    3 */
   GO(SYS_read, "1+3s 0m");
   SY(SYS_read+x0, 0, x0, x0 + 1); FAILx(EFAULT);
   
   /* SYS_write                   4 */
   GO(SYS_write, "3s 1m");
   SY(SYS_write, x0 + 2, x0, x0 + 1); FAIL;
   
   /* SYS_open                    5 */
   GO(SYS_open, "(2-args) 2s 1m");
   SY(SYS_open, x0, x0); FAIL;

   // Only 1s 0m errors -- the other 2s 1m have been checked in the previous
   // open test, and if we test them they may be commoned up but they also
   // may not.
   GO(SYS_open, "(3-args) 1s 0m");    
   SY(SYS_open, "scalar.c", O_CREAT|O_EXCL, x0); FAIL;

   /* SYS_close                   6 */
   GO(SYS_close, "1s 0m");
   SY(SYS_close, x0-1); FAIL;
   
   /* SYS_waitpid                 7 */
   GO(SYS_wait4, "4s 2m");
   SY(SYS_wait4, x0, x0+1, x0, x0+1); FAIL;
   
   /* old creat                     8 */

   /* SYS_link                      9 */
   GO(SYS_link, "2s 2m");
   SY(SYS_link, x0, x0); FAIL;

   /* SYS_unlink                    10 */
   GO(SYS_unlink, "1s 1m");
   SY(SYS_unlink, x0); FAIL;
   
   /* obs execv                     11 */
   
   /* chdir                         12 */
   GO(SYS_chdir, "1s 1m");
   SY(SYS_chdir, x0); FAIL;
   
   /* fchdir                        13 */
   GO(SYS_fchdir, "1s 0m");
   SY(SYS_fchdir, x0-1); FAIL;

   /* SYS_freebsd11_mknod           14 */
   /* @todo PJF will need conditional compilation */
   GO(SYS_freebsd11_mknod, "3s 1m");
   SY(SYS_freebsd11_mknod, x0, x0, x0); FAIL;

   /* chmod                         15 */
   GO(SYS_chmod, "2s 1m");
   SY(SYS_chmod, x0, x0); FAIL;
   
   /* chown                         16 */
   GO(SYS_chown, "3s 1m");
   SY(SYS_chown, x0, x0, x0); FAIL;
   
   /* break                         17 */
   GO(SYS_break, "ni");
   SY(SYS_break); SUCC;
   
   /* freebsd4 getfsstat            18 */

   /* old lseek                     19 */

   /* getpid                        20 */
   GO(SYS_getpid, "0s 0m");
   SY(SYS_getpid); SUCC;
}
