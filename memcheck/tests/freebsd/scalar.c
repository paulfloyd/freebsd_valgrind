/* Basic syscall test, see memcheck/tests/x86-linux/scalar.c for more info. */

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

   /* SYS_read                    3 */
   GO(SYS_read, "1+3s 0m");
   SY(SYS_read+x0, 0, x0, x0 + 1); FAILx(EFAULT);
   
   /* SYS_write                   4 */
   GO(SYS_write, "3s 1m");
   SY(SYS_write, x0 + 2, x0, x0 + 1); FAIL;
}
