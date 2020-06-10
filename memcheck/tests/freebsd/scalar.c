/* Basic syscall test, see memcheck/tests/x86-linux/scalar.c for more info. */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <ufs/ufs/quota.h>
#include <machine/sysarch.h>
#include "scalar.h"
#include "config.h"
#include "../../memcheck.h"

/* Helper functions.  These are necessary if we've got two tests for a single
   syscall.  In that case, Memcheck can sometimes merge error messages.  Doing
   each test in its own function prevents that. */


int main(void)
{
   /* Uninitialised, but we know px[0] is 0x0. */
   /* PJF why ? */
   long *px = malloc(2*sizeof(long));
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
   
   /* old creat                   8 */

   /* SYS_link                    9 */
   GO(SYS_link, "2s 2m");
   SY(SYS_link, x0, x0); FAIL;

   /* SYS_unlink                  10 */
   GO(SYS_unlink, "1s 1m");
   SY(SYS_unlink, x0); FAIL;
   
   /* obs execv                   11 */
   
   /* chdir                       12 */
   GO(SYS_chdir, "1s 1m");
   SY(SYS_chdir, x0); FAIL;
   
   /* fchdir                      13 */
   GO(SYS_fchdir, "1s 0m");
   SY(SYS_fchdir, x0-1); FAIL;

   /* SYS_freebsd11_mknod         14 */
   /* @todo PJF will need conditional compilation */
#if (FREEBSD_VERS >= FREEBSD_12)
   GO(SYS_freebsd11_mknod, "3s 1m");
   SY(SYS_freebsd11_mknod, x0, x0, x0); FAIL;
#else
   GO(SYS_mknod, "3s 1m");
   SY(SYS_mknod, x0, x0, x0); FAIL;
#endif

   /* chmod                       15 */
   GO(SYS_chmod, "2s 1m");
   SY(SYS_chmod, x0, x0); FAIL;
   
   /* chown                       16 */
   GO(SYS_chown, "3s 1m");
   SY(SYS_chown, x0, x0, x0); FAIL;
   
   /* break                       17 */
   GO(SYS_break, "ni");
   SY(SYS_break); SUCC;
   
   /* freebsd4 getfsstat          18 */

   /* old lseek                   19 */

   /* getpid                      20 */
   GO(SYS_getpid, "0s 0m");
   SY(SYS_getpid); SUCC;
   
   /* mount	                      21 */
   /* data not read otherwise this would ne 3m */
   GO(SYS_mount, "4s 2m");
   SY(SYS_mount, x0, x0, x0, x0); FAIL;

   /* unmount                     22 */
   GO(SYS_unmount, "1s 1m");
   SY(SYS_unmount, x0); FAIL;

   /* setuid                      23 */
   GO(SYS_setuid, "1s 0m");
   SY(SYS_setuid, x0-1); FAIL;

   /* getuid                      24 */
   GO(SYS_getuid, "0s 0m");
   SY(SYS_getuid); SUCC;

   /* geteuid                     25 */
   GO(SYS_geteuid, "0s 0m");
   SY(SYS_geteuid); SUCC;

   /* ptrace                      26 */
   // XXX: memory pointed to be arg3 goes unchecked... otherwise would be 1m
   GO(SYS_ptrace, "4s 0m");
   SY(SYS_ptrace, x0+PTRACE_EXEC, x0, x0, x0); FAIL;

   /* recvmsg                     27 */
   GO(SYS_recvmsg, "3s 0m");
   SY(SYS_recvmsg, x0, x0, x0); FAIL;
   
   /* sendmsg                     28 */
   GO(SYS_sendmsg, "3s 0m");
   SY(SYS_sendmsg, x0, x0, x0); FAIL;

   /* recvfrom                    29 */
   GO(SYS_recvfrom, "5s 0m");
   SY(SYS_recvfrom, x0, x0, x0, x0, x0); FAIL;

   /* accept                      30 */
   GO(SYS_accept, "3s 0m");
   SY(SYS_accept, x0, x0, x0); FAIL;

   /* getpeername                 31 */
   GO(SYS_getpeername, "3s 1m");
   SY(SYS_getpeername, x0, x0, x0); FAIL;

   /* getsockname                 32 */
   GO(SYS_getsockname, "3s 1m");
   SY(SYS_getsockname, x0, x0, x0); FAIL;

   /* access                      33 */
   GO(SYS_geteuid, "0s 0m");
   SY(SYS_geteuid); SUCC;

   /* chflags                     34 */
   GO(SYS_chflags, "2s 1m");
   SY(SYS_chflags, x0, x0); FAIL;
   
   /* fchflags                    35 */
   GO(SYS_fchflags, "2s 0m");
   SY(SYS_fchflags, x0+10, x0); FAIL;
   
   /* sync                        36 */
   GO(SYS_sync, "0s 0m");
   SY(SYS_sync); SUCC;

   /* kill                        37 */
   GO(SYS_kill, "2s 0m");
   SY(SYS_kill, x0, x0); SUCC;

   /* old stat                    38 */

   /* getppid                     39 */
   GO(SYS_getppid, "0s 0m");
   SY(SYS_getppid); SUCC;
   
   /* old lstat                   40 */

   /* dup                         41 */
   GO(SYS_dup, "1s 0m");
   SY(SYS_dup, x0-1); FAIL;

   /* freebsd10_pipe              42 */
#if (FREEBSD_VERS >= FREEBSD_11)   
   GO(SYS_freebsd10_pipe, "0s 0m");
   SY(SYS_freebsd10_pipe, x0); SUCC;
#else
   GO(SYS_pipe, "0s 0m");
   SY(SYS_pipe, x0); SUCC;
#endif
   
   /* getegid                     43 */
   GO(SYS_getegid, "0s 0m");
   SY(SYS_getegid); SUCC;

   /* profil                      44 */
   GO(SYS_profil, "ni");
   SY(SYS_profil, x0, x0, x0, x0);

   /* ktrace                      45 */
   GO(SYS_ktrace, "ni");
   SY(SYS_ktrace, x0, x0, x0, x0);

   /* old sigaction               46 */

   /* getgid                      47 */
   GO(SYS_getgid, "0s 0m");
   SY(SYS_getgid); SUCC;

   /* old sigprocmask             48 */

   /* getlogin                    49 */
   GO(SYS_getlogin, "0s 0m");
   SY(SYS_getlogin); SUCC;
   
   /* setlogin                    50 */
   GO(SYS_setlogin, "1s 1m");
   SY(SYS_setlogin, x0); FAIL;   

   /* acct                        51 */
   GO(SYS_acct, "1s 1m");
   SY(SYS_acct, x0-1); FAIL;

   /* 4.3 sigpending              52 */
   
   /* sigaltstack                 53 */
   {
      struct our_sigaltstack {
              char *ss_sp;
              size_t ss_size;
              int ss_flags;
      } ss;
      ss.ss_sp     = NULL;
      ss.ss_flags  = 0;
      ss.ss_size   = 0;
      VALGRIND_MAKE_MEM_NOACCESS(& ss, sizeof(struct our_sigaltstack));
      GO(SYS_sigaltstack, "2s 2m");
      SY(SYS_sigaltstack, x0+&ss, x0+&ss); SUCC;
   }

   /* SYS_ioctl                   54 */
   #include <termios.h>
   GO(SYS_ioctl, "3s 1m");
   SY(SYS_ioctl, x0, x0+TIOCGWINSZ, x0); FAIL;
   
   /* SYS_reboot                  55 */
   /* how to test that and be sure of not rebooting? */

   /* SYS_revoke                  56 */
   GO(SYS_revoke, "1s 1m");
   SY(SYS_revoke, x0); FAIL;

   /* SYS_symlink                 57 */
   GO(SYS_symlink, "2s 2m");
   SY(SYS_symlink, x0, x0); FAIL;
   
   /* SYS_readlink                58 */
   GO(SYS_readlink, "3s 2m");
   SY(SYS_readlink, x0+1, x0+1, x0+1); FAIL;
   
   /* SYS_execve                  59 */
   GO(SYS_execve, "3s 1m");
   SY(SYS_execve, x0 + 1, x0 + 1, x0); FAIL;

   /* SYS_umask                   60 */
   GO(SYS_umask, "1s 0m");
   SY(SYS_umask, x0+022); SUCC;
   
   /* SYS_chroot                  61 */
   GO(SYS_chroot, "1s 1m");
   SY(SYS_chroot, x0); FAIL;
   
   /* 4.3 fstat                   62 */

   /* 4.3 getgerninfo             63 */

   /* 4.3 getpagesize             64 */
   
   /* SYS_msync                   65 */
   GO(SYS_msync, "3s 1m");
   SY(SYS_msync, x0, x0+1, x0); FAIL;
   
   /* SYS_vfork                   66 */
    GO(SYS_vfork, "other");
   // (see scalar_vfork.c)

   /* obsol vread                 67 */

   /* obsol vwrite                68 */

   /* SYS_sbrk                    69 */
   GO(SYS_sbrk, "1s 1m");
   SY(SYS_sbrk, x0); FAIL;

   /* not implemented SYS_sstk    70 */
   
   /* 4.3 mmap                    71 */

   /* 4.2 vadvise                 72 */
   
   /* SYS_munmap                  73 */
   GO(SYS_munmap, "2s 0m");
   SY(SYS_munmap, x0, x0); FAIL;
   
   /* SYS_mprotect                74 */
   GO(SYS_mprotect, "3s 0m");
   /* PJF why does this succeed? */
   SY(SYS_mprotect, x0+1, x0, x0); SUCC;
   
   /* SYS_madvise                 75 */
   GO(SYS_madvise, "3s 0m");
   SY(SYS_madvise, x0, x0+1, x0); FAILx(EINVAL);
   
   /* obsol vhangup               76 */
   
   /* obsol vlimit                77 */
   
   /* SYS_mincore                 78 */
   GO(SYS_mincore, "3s 1m");
   SY(SYS_mincore, x0, x0+40960, x0); FAIL;
   
   /* SYS_getgroups               79 */
   GO(SYS_getgroups, "2s 1m");
   SY(SYS_getgroups, x0+1, x0+1); FAIL;

   /* SYS_setgroups               80 */
   GO(SYS_setgroups, "2s 1m");
   SY(SYS_setgroups, x0+1, x0+1); FAIL;
   
   /* SYS_getpgrp                 81 */
   GO(SYS_getpgrp, "0s 0m");
   SY(SYS_getpgrp); SUCC;

   /* SYS_setpgid                 82 */
   GO(SYS_setpgid, "2s 0m");
   SY(SYS_setpgid, x0, x0-1); FAIL;
   
   /* SYS_setitimer               83 */
   GO(SYS_setitimer, "3s 2m");
   SY(SYS_setitimer, x0, x0+1, x0+1); FAIL;
   
   /* 4.3 wait                    84 */
   
   /* SYS_swapon                  85 */
   GO(SYS_swapon, "1s 1m");
   SY(SYS_swapon, x0); FAIL;

   /* SYS_getitimer               86 */
   GO(SYS_getitimer, "2s 1m");
   SY(SYS_getitimer, x0, x0, x0); FAIL;
   
   /* 4.3 gethostname             87 */

   /* 4.3 sethostname             88 */
   
   /* SYS_getdtablesize           89 */
   GO(SYS_getdtablesize, "0s 0m");
   SY(SYS_getdtablesize); SUCC;

   /* SYS_dup2                    90 */
   GO(SYS_dup2, "2s 0m");
   SY(SYS_dup2, x0-1, x0); FAIL;
   
   /* unimpl getdopt              91 */

   /* SYS_fcntl                   92 */
   /* takes varargs so two versions of test */
   GO(SYS_fcntl, "(GETFD) 2s 0m");
   SY(SYS_fcntl, x0-1, x0+F_GETFD, x0); FAILx(EBADF);

   GO(SYS_fcntl, "(DUPFD) 1s 0m");
   SY(SYS_fcntl, -1, F_DUPFD, x0); FAILx(EBADF);
   
   /* SYS_select                  93 */
   GO(SYS_select, "5s 4m");
   SY(SYS_select, x0+8, x0+0xffffffee, x0+1, x0+1, x0+1); FAIL;
   
   /* unimpl setdopt              94 */
   
   /* SYS_fsync                   95 */
   GO(SYS_fsync, "1s 0m");
   SY(SYS_fsync, x0-1); FAIL;
   
   /* SYS_setpriority             96 */
   GO(SYS_setpriority, "3s 0m");
   SY(SYS_setpriority, x0-1, x0, x0); FAIL;
   
   /* SYS_socket                  97 */
   GO(SYS_socket, "3s 0m");
   SY(SYS_socket, x0, x0, x0); FAIL;
   
   /* SYS_connect                  98 */
   /* needs a socket for the 1m ? */
   GO(SYS_connect, "3s 0m");
   SY(SYS_connect, x0, x0, x0); FAIL;
   
   
   /* 4.3 accept                  99 */

   /* SYS_getpriority             100 */
   GO(SYS_getpriority, "2s 0m");
   SY(SYS_getpriority, x0-1, x0); FAIL;

   /* 4.3 send                    101 */
   /* 4.3 recv                    102 */
   /* 4.3 sigreturn               103 */

   /* SYS_bind                    104 */
   GO(SYS_bind, "3s 0m");
   /* as connect, needs a socket */
   SY(SYS_bind, x0, x0, x0); FAIL;

   /* SYS_setsockopt              105 */
   GO(SYS_setsockopt, "5s 0m");
   SY(SYS_setsockopt, x0, x0, x0, x0, x0); FAIL;

   /* SYS_listen                  106 */
   GO(SYS_listen, "2s 0m");
   SY(SYS_listen, x0, x0); FAIL;

   /* obsol vtimes                107 */

   /* 4.3 sigvec                  108 */

   /* 4.3 sigblock                109 */

   /* 4.3 sigsetmask              110 */

   /* 4.3 sigsuspend              111 */

   /* 4.3 sigstack                112 */

   /* 4.3 recvmsg                 113 */

   /* 4.3 sendmsg                 114 */

   /* 4.3 vtrace                  115 */

   /* SYS_gettimeofday            116 */
   GO(SYS_gettimeofday, "2s 2m");
   SY(SYS_gettimeofday, x0+1, x0+1); FAIL;
   
   /* SYS_getrusage               117 */
   GO(SYS_getrusage, "2s 1m");
   SY(SYS_getrusage, x0, x0); FAIL;
   
   /* SYS_getsockopt              118 */
   GO(SYS_setsockopt, "5s 1m");
   SY(SYS_setsockopt, x0, x0, x0, x0, x0); FAIL;

   /* unimpl resuba               119 */

   /* SYS_readv                   120 */
   GO(SYS_readv, "3s 1m");
   SY(SYS_readv, x0, x0, x0+1); FAIL;
   
   /* SYS_writev                  121 */
   GO(SYS_writev, "3s 1m");
   SY(SYS_writev, x0, x0, x0+1); FAIL;
   
   /* SYS_settimeofday            122 */
   GO(SYS_settimeofday, "2s 2m");
   SY(SYS_settimeofday, x0+1, x0+1); FAIL;
   
   /* SYS_fchown                  123 */
   GO(SYS_fchown, "3s 0m");
   SY(SYS_fchown, x0-1, x0, x0); FAIL;

   /* SYS_fchmod                  124 */
   GO(SYS_fchmod, "2s 0m");
   SY(SYS_fchmod, x0-1, x0); FAIL;
   
   /* 4.3 recvfrom                125 */
   
   /* SYS_setreuid                126 */
   GO(SYS_setreuid, "2s 0m");
   SY(SYS_setreuid, x0-1, x0-1); SUCC;
   
   /* SYS_setregid                127 */
   GO(SYS_setregid, "2s 0m");
   SY(SYS_setregid, x0-1, x0-1); SUCC;

   /* SYS_rename                  128 */
   GO(SYS_rename, "2s 2m");
   SY(SYS_rename, x0, x0); FAIL;
   
   /* 4.3 truncate                129 */
   
   /* 4.3 ftruncate               130 */
   
   /* SYS_flock                   131 */
   GO(SYS_flock, "2s 0m");
   SY(SYS_flock, x0, x0); FAIL;

   /* SYS_mkfifo                  132 */
   GO(SYS_mkfifo, "2s 1m");
   SY(SYS_mkfifo, x0, x0); FAIL;

   /* SYS_sendto                  133 */
   GO(SYS_sendto, "6s 0m");
   SY(SYS_sendto, x0, x0, x0, x0, x0, x0); FAIL;
   
   /* SYS_shutdown                134 */
   /* don't really want to to this */
   
   /* SYS_socketpair              135 */
   GO(SYS_socketpair, "4s 1m");
   SY(SYS_socketpair, x0, x0, x0, x0); FAIL;

   /* SYS_mkdir                   136 */
   GO(SYS_mkdir, "2s 1m");
   SY(SYS_mkdir, x0, x0); FAIL;
   
   /* SYS_rmdir                   137 */
   GO(SYS_rmdir, "1s 1m");
   SY(SYS_rmdir, x0); FAIL;
   
   /* SYS_utimes                  138 */
   GO(SYS_utimes, "2s 2m");
   SY(SYS_utimes, x0, x0+1); FAIL;
   
   /* 4.2 sigreturn               139 */

   /* SYS_adjtime                 140 */
   GO(SYS_adjtime, "2s 1m");
   /* succeeds? need non-null arg2 for 2m */
   SY(SYS_adjtime, x0, x0); SUCC;

   /* 4.3 getpeername             141 */
   
   /* 4.3 gethostid               142 */
   
   /* 4.3 sethostid               143 */

   /* 4.3 getrlimit`              144 */
   
   /* 4.3 setrlimit               145 */
   
   /* 4.3 killpg                  146 */
   
   /* SYS_setsid                  147 */
   GO(SYS_setsid, "0s 0m");
   SY(SYS_setsid); SUCC;

   /* SYS_quotactl                148 */
   GO(SYS_quotactl, "(Q_QUOTAOFF) 2s 0m");
   SY(SYS_quotactl, x0, x0+Q_QUOTAOFF, x0, x0); FAIL;
   
   GO(SYS_quotactl, "(Q_QUOTAON) 4s 2m");
   SY(SYS_quotactl, x0, x0+Q_QUOTAON, x0, x0); FAIL;
   
   
   /* 4.3 quota                   149 */
   
   /* 4.3 getsockname             150 */
   
   /* bsd/os sem_lock             151 */

   /* bsd/os sem_wakeup           152 */
   
   /* bsd/os asyncdaemon          153 */
   
   /* SYS_nlm_syscall             154 */
   
   // BSDXY(__NR_nfssvc,        sys_nfssvc),            // 155

   /* 4.3 getdirentries           156 */
   
   /* freebsd 4 statfs            157 */
   
   /* freebsd 4 fstatfs           158 */
   
   /* nosys                       159 */

   /* SYS_lgetfh                  160 */
   GO(SYS_lgetfh, "2s 2m");
   SY(SYS_lgetfh, x0, x0); FAIL;

   /* SYS_getfh                   161 */
   GO(SYS_getfh, "2s 2m");
   SY(SYS_getfh, x0, x0); FAIL;

#if (FREEBSD_VERS <= FREEBSD_10)
   /* SYS_getdomainname          162 */
   GO(SYS_freebsd4_getdomainname, "2s 1m");
   SY(SYS_freebsd4_getdomainname, x0, x0); FAIL;
   
   /* SYS_setdomainname           163 */
   GO(SYS_freebsd4_setdomainname, "2s 0m");
   SY(SYS_freebsd4_setdomainname, x0, x0); FAIL;

   /* SYS_uname                   164 */
   GO(SYS_freebsd4_uname, "1s 1m");
   SY(SYS_freebsd4_uname, x0); FAIL;
#endif
   
   /* SYS_sysarch                 165 */
#if defined (VGP_x86_freebsd)
   GO(SYS_sysarch, "2s 1m");
   SY(SYS_sysarch, x0+I386_GET_GSBASE, x0); FAIL;
   
   GO(SYS_sysarch, "2s 0m");
   SY(SYS_sysarch, x0+I386_SET_GSBASE, x0); FAIL;
#elif defined(VGP_amd64_freebsd)
   GO(SYS_sysarch, "2s 1m");
   SY(SYS_sysarch, x0+AMD64_GET_FSBASE, x0); SUCC;
   
   GO(SYS_sysarch, "2s 0m");
   SY(SYS_sysarch, x0+AMD64_SET_FSBASE, x0); FAIL;
#else
#error "freebsd platform not defined"
#endif
   
   /*
   
// BSDXY(__NR_rtprio,           sys_rtprio),            // 166

   // nosys                                                167

   // nosys                                                168
   
// BSDXY(__NR_semsys,           sys_semsys),            // 169

// BSDXY(__NR_msgsys,           sys_msgsys),            // 170

// BSDXY(__NR_shmsys,           sys_shmsys),            // 171

   // nosys                                                172
   
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDXY(__NR_freebsd6_pread,   sys_freebsd6_pread),    // 173
   BSDX_(__NR_freebsd6_pwrite,  sys_freebsd6_pwrite),   // 174
#endif

   // nosys                                                175

   // BSDXY(__NR_ntp_adjtime,   sys_ntp_adjtime),       // 176
   
   // bsd/os sfork                                         177
   
   // bsd/os getdescriptor                                 178
   
   // bsd/os setdescriptor                                 179

   // nosys                                                180
   
   GENX_(__NR_setgid,           sys_setgid),            // 181
   
   BSDX_(__NR_setegid,          sys_setegid),           // 182
   
   BSDX_(__NR_seteuid,          sys_seteuid),           // 183

   // unimpl lfs_bmapv                                     184
   
   // unimpl lfs_markv                                     185
   
   // unimpl lfs_segclean                                  186
   
   // unimpl lfs_segwait                                   187

 #if (FREEBSD_VERS >= FREEBSD_12)
   BSDXY(__NR_freebsd11_stat,   sys_stat),              // 188
   
   BSDXY(__NR_freebsd11_fstat,  sys_freebsd11_fstat),   // 189
   
   BSDXY(__NR_freebsd11_lstat,  sys_lstat),             // 190
   
 #else
   BSDXY(__NR_stat,             sys_stat),              // 188
   
   BSDXY(__NR_fstat,            sys_fstat),             // 189
   
   BSDXY(__NR_lstat,            sys_lstat),             // 190
 #endif
 
   BSDX_(__NR_pathconf,         sys_pathconf),          // 191

   BSDX_(__NR_fpathconf,        sys_fpathconf),         // 192
   
   // nosys                                                193
   
   GENXY(__NR_getrlimit,        sys_getrlimit),         // 194
   
   GENX_(__NR_setrlimit,        sys_setrlimit),         // 195

   BSDXY(__NR_getdirentries,    sys_getdirentries),     // 196
   
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDX_(__NR_freebsd6_mmap,    sys_freebsd6_mmap),     // 197
#endif
   // __syscall (handled specially)                     // 198
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDX_(__NR_freebsd6_lseek,    sys_freebsd6_lseek),    // 199
   
   BSDX_(__NR_freebsd6_truncate, sys_freebsd6_truncate), // 200
   
   BSDX_(__NR_freebsd6_ftruncate, sys_freebsd6_ftruncate), // 201
#endif
   BSDXY(__NR___sysctl,         sys___sysctl),          // 202
   
   GENX_(__NR_mlock,            sys_mlock),             // 203

   GENX_(__NR_munlock,          sys_munlock),           // 204
   
   BSDX_(__NR_undelete,         sys_undelete),          // 205
   
   BSDX_(__NR_futimes,          sys_futimes),           // 206
   
   GENX_(__NR_getpgid,          sys_getpgid),           // 207

   // netbsd newreboot                                     208
   GENXY(__NR_poll,             sys_poll),              // 209
   
   BSDX_(__NR_lkmnosys0,        sys_lkmnosys0),         // 210
   
   BSDX_(__NR_lkmnosys1,        sys_lkmnosys1),         // 211

   BSDX_(__NR_lkmnosys2,        sys_lkmnosys2),         // 212
   
   BSDX_(__NR_lkmnosys3,        sys_lkmnosys3),         // 213
   
   BSDX_(__NR_lkmnosys4,        sys_lkmnosys4),         // 214
   
   BSDX_(__NR_lkmnosys5,        sys_lkmnosys5),         // 215

   BSDX_(__NR_lkmnosys6,        sys_lkmnosys6),         // 216
   
   BSDX_(__NR_lkmnosys7,        sys_lkmnosys7),         // 217
   
   BSDX_(__NR_lkmnosys8,        sys_lkmnosys8),         // 218
   
// BSDXY(__NR_nfs_fhopen,       sys_nfs_fhopen),        // 219

   BSDXY(__NR_freebsd7___semctl, sys_freebsd7___semctl), // 220
   
   BSDX_(__NR_semget,           sys_semget),            // 221
   
   BSDX_(__NR_semop,            sys_semop),             // 222
   // unimpl semconfig                                     223

// BSDXY(__NR_msgctl,           sys_msgctl),            // 224
// BSDX_(__NR_msgget,           sys_msgget),            // 225
// BSDX_(__NR_msgsnd,           sys_msgsnd),            // 226
// BSDXY(__NR_msgrcv,           sys_msgrcv),            // 227

   BSDXY(__NR_shmat,            sys_shmat),             // 228
   BSDXY(__NR_freebsd7_shmctl,  sys_freebsd7_shmctl),   // 229
   BSDXY(__NR_shmdt,            sys_shmdt),             // 230
   BSDX_(__NR_shmget,           sys_shmget),            // 231

   BSDXY(__NR_clock_gettime,    sys_clock_gettime),     // 232
   BSDX_(__NR_clock_settime,    sys_clock_settime),     // 233
   BSDXY(__NR_clock_getres,     sys_clock_getres),      // 234
   // unimpl timer_create                                  235

   // unimpl timer_delete                                  236
   // unimpl timer_settime                                 237
   // unimpl timer_gettime                                 238
   // unimpl timer_getoverrun                              239

   GENXY(__NR_nanosleep,        sys_nanosleep),         // 240
   // nosys                                                241
   // nosys                                                242
   // nosys                                                243

   // nosys                                                244
   // nosys                                                245
   // nosys                                                246
   // nosys                                                247

// BSDXY(__NR_ntp_gettime,      sys_ntp_gettime),       // 248
   // nosys                                                249
   BSDXY(__NR_minherit,         sys_minherit),          // 250
   BSDX_(__NR_rfork,            sys_rfork),             // 251

   // openbsd_poll                                      // 252
   BSDX_(__NR_issetugid,        sys_issetugid),         // 253
   GENX_(__NR_lchown,           sys_lchown),            // 254
   // nosys                                                255

   // nosys                                                256
   
   // nosys                                                257
   
   // nosys                                                258
   
   // nosys                                                259
 
   // nosys                                                260
   
   // nosys                                                261
   
   // nosys                                                262
   
   // nosys                                                263

   // nosys                                                264
   
   // nosys                                                265
   // nosys                                                266
   // nosys                                                267

   // nosys                                                268
   // nosys                                                269
   // nosys                                                270
   // nosys                                                271

   GENXY(__NR_getdents,         sys_getdents),          // 272
   // nosys                                                273
   BSDX_(__NR_lchmod,           sys_lchmod),            // 274
   // netbsd_lchown                                     // 275

   BSDX_(__NR_lutimes,          sys_lutimes),           // 276
   // netbsd msync                                         277
   // netbsd stat                                          278
   // netbsd fstat                                         279

   // netbsd lstat                                         280
   // nosys                                                281
   // nosys                                                282
   // nosys                                                283

   // nosys                                                284
   // nosys                                                285
   // nosys                                                286
   // nosys                                                287

   // nosys                                                288
   // nosys                                                289
   
   // nosys                                                290
   
   // nosys                                                291

   // nosys                                                292
   
   // nosys                                                293
   
   // nosys                                                294
   
   // nosys                                                295

   // nosys                                                296
   
   // freebsd 4 fhstatfs                                   297
   BSDXY(__NR_fhopen,           sys_fhopen),            // 298
   
   BSDXY(__NR_fhstat,           sys_fhstat),            // 299

// BSDX_(__NR_modnext,          sys_modnext),           // 300
   BSDXY(__NR_modstat,          sys_modstat),           // 301
// BSDX_(__NR_modfnext,         sys_modfnext),          // 302
   BSDX_(__NR_modfind,          sys_modfind),           // 303

   BSDX_(__NR_kldload,          sys_kldload),           // 304
   
   BSDX_(__NR_kldunload,        sys_kldunload),         // 305
   
   BSDX_(__NR_kldfind,          sys_kldfind),           // 306
   
   BSDX_(__NR_kldnext,          sys_kldnext),           // 307

// BSDXY(__NR_kldstat,          sys_kldstat),           // 308
// BSDX_(__NR_kldfirstmod,      sys_kldfirstmod),       // 309
   GENX_(__NR_getsid,           sys_getsid),            // 310
   BSDX_(__NR_setresuid,        sys_setresuid),         // 311

   BSDX_(__NR_setresgid,        sys_setresgid),         // 312
   
   // obsol signanosleep                                   313
   
   // BSDXY(__NR_aio_return,    sys_aio_return),        // 314
   
   // BSDXY(__NR_aio_suspend,   sys_aio_suspend),       // 315

   // BSDXY(__NR_aio_cancel,    sys_aio_cancel),        // 316
   
   // BSDXY(__NR_aio_error,     sys_aio_error),         // 317
   
   // freebsd 6 aio_read                                   318
   
   // freebsd 6 aio_write                                  319
   
   // freebsd 6 lio_listio                                 320
   
   BSDX_(__NR_yield,            sys_yield),             // 321
   
   // obs thr_sleep                                        322
   
   // obs thr_wakeup                                       323

   GENX_(__NR_mlockall,         sys_mlockall),          // 324
   
   BSDX_(__NR_munlockall,       sys_munlockall),        // 325
   
   BSDXY(__NR___getcwd,         sys___getcwd),          // 326
   
// BSDXY(__NR_sched_setparam,   sys_sched_setparam),    // 327

// BSDXY(__NR_sched_getparam,   sys_sched_getparam),    // 328
// BSDX_(__NR_sched_setscheduler, sys_sched_setscheduler), // 329
// BSDX_(__NR_sched_getscheduler, sys_sched_getscheduler), // 330
   BSDX_(__NR_sched_yield,      sys_sched_yield),       // 331

   BSDX_(__NR_sched_get_priority_max, sys_sched_get_priority_max), // 332
   BSDX_(__NR_sched_get_priority_min, sys_sched_get_priority_min), // 333
// BSDXY(__NR_sched_rr_get_interval, sys_sched_rr_get_interval), // 334
   BSDX_(__NR_utrace,           sys_utrace),            // 335

   // freebsd 4 sendfile                                   336
   BSDXY(__NR_kldsym,           sys_kldsym),            // 337
// BSDX_(__NR_jail,             sys_jail),              // 338
   // unimpl pioctl                                        339

   BSDXY(__NR_sigprocmask,      sys_sigprocmask),       // 340
   BSDX_(__NR_sigsuspend,       sys_sigsuspend),        // 341
   // freebsd 4 sigaction                                  342
   BSDXY(__NR_sigpending,       sys_sigpending),        // 343

   // freebsd sigreturn                                    344
   BSDXY(__NR_sigtimedwait,     sys_sigtimedwait),      // 345
   BSDXY(__NR_sigwaitinfo,      sys_sigwaitinfo),       // 346
   BSDXY(__NR___acl_get_file,   sys___acl_get_file),    // 347

   BSDX_(__NR___acl_set_file,   sys___acl_set_file),    // 348
   BSDXY(__NR___acl_get_fd,     sys___acl_get_fd),      // 349
   BSDX_(__NR___acl_set_fd,     sys___acl_set_fd),      // 350
   BSDX_(__NR___acl_delete_file, sys___acl_delete_file), // 351

   BSDX_(__NR___acl_delete_fd,  sys___acl_delete_fd),   // 352
   BSDX_(__NR___acl_aclcheck_file, sys___acl_aclcheck_file), // 353
   BSDX_(__NR___acl_aclcheck_fd, sys___acl_aclcheck_fd), // 354
   // BSDXY(__NR_extattrctl,    sys_extattrctl),        // 355

   // BSDXY(__NR_extattr_set_file, sys_extattr_set_file), // 356
   BSDXY(__NR_extattr_get_file, sys_extattr_get_file),  // 357
   // BSDXY(__NR_extattr_delete_file, sys_extattr_delete_file), // 358
   // BSDXY(__NR_aio_waitcomplete, sys_aio_waitcomplete), // 359

   BSDXY(__NR_getresuid,        sys_getresuid),         // 360
   BSDXY(__NR_getresgid,        sys_getresgid),         // 361
   BSDX_(__NR_kqueue,           sys_kqueue),            // 362
   BSDXY(__NR_kevent,           sys_kevent),            // 363

   // nosys                                                364
   // nosys                                                365
   // nosys                                                366
   // nosys                                                367

   // nosys                                                368
   // nosys                                                369
   // lkmressys                                            370
   // extattr_set_fd                                       371

   // extattr_get_fd                                       372
   // extattr_delete_fd                                    373
   // __setugid                                            374
   // nfsclnt                                              375

   BSDX_(__NR_eaccess,          sys_eaccess),           // 376
   // afs_syscall                                          377
   // nmount                                               378
   // kse_exit                                             379

   // kse_wakeup                                           380
   // kse_create                                           381
   // kse_thr_interrupt                                    382
   // kse_release                                          383

   // __mac_get_proc                                       384
   // __mac_set_proc                                       385
   // __mac_get_fd                                         386
   // __mac_get_file                                       387

   // __mac_set_fd                                         388
   // __mac_set_file                                       389
   BSDXY(__NR_kenv,             sys_kenv),              // 390
   BSDX_(__NR_lchflags,         sys_lchflags),          // 391

   BSDXY(__NR_uuidgen,          sys_uuidgen),           // 392
   BSDXY(__NR_sendfile,         sys_sendfile),          // 393
   // mac_syscall                                          394

#if (FREEBSD_VERS >= FREEBSD_12)
   BSDXY(__NR_freebsd11_getfsstat, sys_freebsd11_getfsstat), // 395
   BSDXY(__NR_freebsd11_statfs, sys_statfs),            // 396
   BSDXY(__NR_freebsd11_fstatfs, sys_fstatfs),          // 397
   BSDXY(__NR_freebsd11_fhstatfs, sys_fhstatfs),        // 398
#else
   BSDXY(__NR_getfsstat,        sys_getfsstat),         // 395
   BSDXY(__NR_statfs,           sys_statfs),            // 396
   BSDXY(__NR_fstatfs,          sys_fstatfs),           // 397
   BSDXY(__NR_fhstatfs,         sys_fhstatfs),          // 398
#endif

   // nosys                                                399

   // ksem_close                                           400
   // ksem_post                                            401
   // ksem_wait                                            402
   // ksem_trywait                                         403

   // ksem_init                                            404
   // ksem_open                                            405
   // ksem_unlink                                          406
   // ksem_getvalue                                        407

   // ksem_destroy                                         408
   
   // __mac_get_pid                                        409
   
   // __mac_get_link                                       410
   
   // __mac_set_link                                       411

   // extattr_set_link                                     412
   
   // extattr_get_link                                     413
   
   // extattr_delete_link                                  414
   
   // __mac_execve                                         415

   BSDXY(__NR_sigaction,        sys_sigaction),         // 416
   BSDX_(__NR_sigreturn,        sys_sigreturn),         // 417
   // __xstat                                              418
   // __xfstat                                             419

   // __xlstat                                             420
   BSDXY(__NR_getcontext,       sys_getcontext),        // 421
   BSDX_(__NR_setcontext,       sys_setcontext),        // 422
   BSDXY(__NR_swapcontext,      sys_swapcontext),       // 423

   // swapoff                                              424
   
   BSDXY(__NR___acl_get_link,   sys___acl_get_link),    // 425
   
   BSDX_(__NR___acl_set_link,   sys___acl_set_link),    // 426
   
   BSDX_(__NR___acl_delete_link, sys___acl_delete_link), // 427

   BSDX_(__NR___acl_aclcheck_link, sys___acl_aclcheck_link), // 428
   BSDXY(__NR_sigwait,          sys_sigwait),           // 429
   // thr_create                                           430
   BSDX_(__NR_thr_exit,         sys_thr_exit),          // 431

   BSDXY(__NR_thr_self,         sys_thr_self),          // 432
   BSDXY(__NR_thr_kill,         sys_thr_kill),          // 433
   BSDXY(__NR__umtx_lock,       sys__umtx_lock),        // 434
   BSDXY(__NR__umtx_unlock,     sys__umtx_unlock),      // 435

   // jail_attach                                          436
   // extattr_list_fd                                      437
   // extattr_list_file                                    438
   // extattr_list_link                                    439

   // kse_switchin                                         440
   // ksem_timedwait                                       441
   // thr_suspend                                          442
   BSDX_(__NR_thr_wake,         sys_thr_wake),          // 443
   // kldunloadf                                           444
   // audit                                                445
   // auditon                                              446
   // getauid                                              447

   // setauid                                              448
   // getaudit                                             449
   // setaudit                                             450
   // getaudit_addr                                        451

   // setaudit_addr                                        452
   // auditctl                                             453
   BSDXY(__NR__umtx_op,         sys__umtx_op),          // 454
   BSDX_(__NR_thr_new,          sys_thr_new),           // 455

   // sigqueue                                             456
   BSDXY(__NR_kmq_open,         sys_kmq_open),          // 457
   BSDX_(__NR_kmq_setattr,      sys_kmq_setattr),       // 458
   BSDXY(__NR_kmq_timedreceive, sys_kmq_timedreceive),  // 459

   BSDX_(__NR_kmq_timedsend,    sys_kmq_timedsend),     // 460
   BSDX_(__NR_kmq_notify,       sys_kmq_notify),        // 461
   BSDX_(__NR_kmq_unlink,       sys_mq_unlink),         // 462
   // abort2                                               463

   BSDX_(__NR_thr_set_name,     sys_thr_set_name),      // 464
   // aio_fsync                                            465
   BSDXY(__NR_rtprio_thread,    sys_rtprio_thread),     // 466
   // nosys                                                467

   // nosys                                                468
   // __getpath_fromfd                                     469
   // __getpath_fromaddr                                   470
   // sctp_peeloff                                         471

   // sctp_generic_sendmsg                                 472
   // sctp_generic_sendmsg_iov                             473
   // sctp_generic_recvmsg                                 474
   BSDXY(__NR_pread,            sys_pread),             // 475

   BSDX_(__NR_pwrite,           sys_pwrite),            // 476
   BSDX_(__NR_mmap,             sys_mmap),              // 477
   BSDX_(__NR_lseek,            sys_lseek),             // 478
   BSDX_(__NR_truncate,         sys_truncate),          // 479
   BSDX_(__NR_ftruncate,        sys_ftruncate),         // 480
   BSDXY(__NR_thr_kill2,        sys_thr_kill2),         // 481
   BSDXY(__NR_shm_open,         sys_shm_open),          // 482
   BSDX_(__NR_shm_unlink,       sys_shm_unlink),        // 483

   // cpuset                                               484
   // cpuset_setid                                         485
   // cpuset_getid                                         486

   BSDXY(__NR_cpuset_getaffinity, sys_cpuset_getaffinity), // 487
   BSDX_(__NR_cpuset_setaffinity, sys_cpuset_setaffinity), // 488
   BSDX_(__NR_faccessat,        sys_faccessat),         // 489
   BSDX_(__NR_fchmodat,         sys_fchmodat),          // 490
   BSDX_(__NR_fchownat,         sys_fchownat),          // 491

   // fexecve                                              492
   BSDXY(__NR_fstatat,          sys_fstatat),           // 493
   BSDX_(__NR_futimesat,        sys_futimesat),         // 494
   BSDX_(__NR_linkat,           sys_linkat),            // 495

   BSDX_(__NR_mkdirat,          sys_mkdirat),           // 496
   
   */
   
   /* SYS_mkfifoat                497 */
   /* not getting an error with fd */
   /* need to investigate */
   GO(SYS_mkfifoat, "3s 1m");
   SY(SYS_mkfifoat, x0, x0, x0); FAIL;

   /*
   
   BSDX_(__NR_mknodat,          sys_mknodat),           // 498
   BSDXY(__NR_openat,           sys_openat),            // 499

   BSDX_(__NR_readlinkat,       sys_readlinkat),        // 500
   BSDX_(__NR_renameat,         sys_renameat),          // 501
   BSDX_(__NR_symlinkat,        sys_symlinkat),         // 502
   BSDX_(__NR_unlinkat,         sys_unlinkat),          // 503

   BSDX_(__NR_posix_openpt,     sys_posix_openpt),      // 504
   // gssd_syscall                                         505
   BSDXY(__NR_jail_get,         sys_jail_get),          // 506
   BSDX_(__NR_jail_set,         sys_jail_set),          // 507
   BSDX_(__NR_jail_remove,      sys_jail_remove),       // 508
   // closefrom                                            509
   BSDXY(__NR___semctl,         sys___semctl),          // 510
   // msgctl                                               511
   BSDXY(__NR_shmctl,           sys_shmctl),            // 512
    // lpathconf                                           513
    // 514 is obsolete cap_new
    // __cap_rights_get                                    515
    BSDX_(__NR_cap_enter,       sys_cap_enter),         // 516
    // cap_getmode                                         517
    BSDXY(__NR_pdfork,          sys_pdfork),            // 518
    BSDX_(__NR_pdkill,          sys_pdkill),            // 519
    BSDXY(__NR_pdgetpid,        sys_pdgetpid),          // 520
    BSDXY(__NR_pselect,         sys_pselect),           // 522
    // getloginclass                                       523
    // setloginclass                                       524
    // rctl_get_racct                                      525
    // rctl_get_rules                                      526
    // rctl_get_limits                                     527
    // rctl_add_rule                                       528
    // rctl_remove_rule                                    529
    BSDX_(__NR_posix_fallocate, sys_posix_fallocate),   // 530
    BSDX_(__NR_posix_fadvise,   sys_posix_fadvise),     // 531
    // wait6                                               532
    BSDXY(__NR_cap_rights_limit, sys_cap_rights_limit), // 533
    BSDXY(__NR_cap_ioctls_limit, sys_cap_ioctls_limit), // 534
    // cap_ioctls_get                                      535
    BSDX_(__NR_cap_fcntls_limit, sys_cap_fcntls_limit), // 536
    // cap_fcntls_get                                      537
    // bindat                                              538
    // connectat                                           539
    // chflagsat                                           540
   BSDXY(__NR_accept4,          sys_accept4),           // 541
   BSDXY(__NR_pipe2,            sys_pipe2),             // 542
    // aio_mlock                                           543
    // procctl                                             544

    // 544 is the highest syscall on FreeBSD 9

#if (FREEBSD_VERS >= FREEBSD_10)

   BSDXY(__NR_ppoll,            sys_ppoll),             // 545
    // futimens                                            546
    // utimensat                                           547

#endif // FREEBSD_VERS >= FREEBSD_11

#if (FREEBSD_VERS >= FREEBSD_11)


    // 548 is obsolete numa_getaffinity
    // 549 is obsolete numa_setaffinity
    // fdatasync                                           550

#endif // FREEBSD_VERS >= FREEBSD_11

*/

#if (FREEBSD_VERS >= FREEBSD_12)

/*
   BSDXY(__NR_fstat,            sys_fstat),             // 551
   
    // fstatat                                             552
    
    // fhstat                                              553
    
    // getdirentries                                       554
    
    BSDXY(__NR_statfs,          sys_statfs),            // 555
    
    BSDXY(__NR_fstatfs,         sys_fstatfs),           // 556
    
    BSDXY(__NR_getfsstat,       sys_getfsstat),         // 557
    
    BSDXY(__NR_fhstatfs,        sys_fhstatfs),          // 558
    
    // mknodat                                             559
    
    // kevent                                              560
    
    // cpuset_getdomain                                    561
    
    // cpuset_setdomain                                    562
    
   BSDXY(__NR_getrandom,        sys_getrandom),         // 563
   
   */
   
   /* SYS_getfhat                 564 */
   GO(SYS_getfhat, "4s 2m");
   SY(SYS_getfhat, x0, x0, x0, x0); FAIL;
   
   /*

    
    // fhlink                                              565
    
    // fhlinkat                                            566
    
    // fhreadlink                                          567
*/

#endif

}
