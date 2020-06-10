
/*--------------------------------------------------------------------*/
/*--- FreeBSD-specific syscalls stuff.          priv_syswrap-freebsd.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2008 Nicholas Nethercote
      njn@valgrind.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef PRIV_SYSWRAP_FREEBSD_H
#define PRIV_SYSWRAP_FREEBSD_H

/* requires #include "priv_types_n_macros.h" */
#include "priv_types_n_macros.h"
#include "config.h"

// Clone-related functions
extern Word ML_(start_thread_NORETURN) ( void* arg );
extern Addr ML_(allocstack)            ( ThreadId tid );
extern void ML_(call_on_new_stack_0_1) ( Addr stack, Addr retaddr,
			                 void (*f)(Word), Word arg1 );
extern SysRes ML_(do_fork) ( ThreadId tid );
extern SysRes ML_(do_vfork) ( ThreadId tid );
extern SysRes ML_(do_rfork) ( ThreadId tid, Int flags );


DECL_TEMPLATE(freebsd, sys_syscall)
DECL_TEMPLATE(freebsd, sys_exit)
DECL_TEMPLATE(freebsd, sys_fork)
// lots are not here ????
// it would be nice if thse were in the same order as sys/syscall.h
// instead of just being some random jumble

DECL_TEMPLATE(freebsd, sys_mount)
DECL_TEMPLATE(freebsd, sys_unmount)
DECL_TEMPLATE(freebsd, sys_ptrace)
DECL_TEMPLATE(freebsd, sys_recvmsg)
DECL_TEMPLATE(freebsd, sys_sendmsg)
DECL_TEMPLATE(freebsd, sys_recvfrom)
DECL_TEMPLATE(freebsd, sys_accept)
DECL_TEMPLATE(freebsd, sys_getpeername)
DECL_TEMPLATE(freebsd, sys_getsockname)
DECL_TEMPLATE(freebsd, sys_chflags)
DECL_TEMPLATE(freebsd, sys_fchflags)
DECL_TEMPLATE(freebsd, sys_pipe)
DECL_TEMPLATE(freebsd, sys_ktrace)
DECL_TEMPLATE(freebsd, sys_getlogin) // 49
DECL_TEMPLATE(freebsd, sys_setlogin) // 50
DECL_TEMPLATE(freebsd, sys_ioctl) // 54
DECL_TEMPLATE(freebsd, sys_reboot)
DECL_TEMPLATE(freebsd, sys_revoke)
DECL_TEMPLATE(freebsd, sys_sbrk)
DECL_TEMPLATE(freebsd, sys_sstk)
DECL_TEMPLATE(freebsd, sys_swapon)
DECL_TEMPLATE(freebsd, sys_getdtablesize) // 90
DECL_TEMPLATE(freebsd, sys_fcntl) // 92
DECL_TEMPLATE(freebsd, sys_socket) // 97
DECL_TEMPLATE(freebsd, sys_connect)
DECL_TEMPLATE(freebsd, sys_bind)
DECL_TEMPLATE(freebsd, sys_setsockopt)
DECL_TEMPLATE(freebsd, sys_listen)
DECL_TEMPLATE(freebsd, sys_getsockopt)
DECL_TEMPLATE(freebsd, sys_mkfifo)
DECL_TEMPLATE(freebsd, sys_sendto)
DECL_TEMPLATE(freebsd, sys_shutdown)
DECL_TEMPLATE(freebsd, sys_socketpair)
DECL_TEMPLATE(freebsd, sys_adjtime)
DECL_TEMPLATE(freebsd, sys_quotactl)
DECL_TEMPLATE(freebsd, sys_nfssvc)
DECL_TEMPLATE(freebsd, sys_lgetfh)
DECL_TEMPLATE(freebsd, sys_getfh)
#if (FREEBSD_VERS <= FREEBSD_10)
DECL_TEMPLATE(freebsd, sys_freebsd4_getdomainname)
DECL_TEMPLATE(freebsd, sys_freebsd4_setdomainname)
DECL_TEMPLATE(freebsd, sys_freebsd4_uname)
#endif
DECL_TEMPLATE(freebsd, sys_sysarch)
DECL_TEMPLATE(freebsd, sys_rtprio)
DECL_TEMPLATE(freebsd, sys_semsys)
DECL_TEMPLATE(freebsd, sys_msgsys)
DECL_TEMPLATE(freebsd, sys_shmsys)
#if (FREEBSD_VERS <= FREEBSD_10)
DECL_TEMPLATE(freebsd, sys_freebsd6_pread)
DECL_TEMPLATE(freebsd, sys_freebsd6_pwrite)
#endif
DECL_TEMPLATE(freebsd, sys_ntp_adjtime)
DECL_TEMPLATE(freebsd, sys_setegid)
DECL_TEMPLATE(freebsd, sys_seteuid)
#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_stat)
DECL_TEMPLATE(freebsd, sys_freebsd11_fstat)
DECL_TEMPLATE(freebsd, sys_freebsd11_lstat)
#else
DECL_TEMPLATE(freebsd, sys_stat)
DECL_TEMPLATE(freebsd, sys_fstat)
DECL_TEMPLATE(freebsd, sys_lstat)
#endif
DECL_TEMPLATE(freebsd, sys_pathconf)
DECL_TEMPLATE(freebsd, sys_fpathconf)
#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_getdirentries)
#else
DECL_TEMPLATE(freebsd, sys_getdirentries)
#endif

#if (FREEBSD_VERS <= FREEBSD_10)
DECL_TEMPLATE(freebsd, sys_freebsd6_mmap)
#endif
//DECL_TEMPLATE(freebsd, sys___syscall)
#if (FREEBSD_VERS <= FREEBSD_10)
DECL_TEMPLATE(freebsd, sys_freebsd6_lseek) // 199
DECL_TEMPLATE(freebsd, sys_freebsd6_truncate) // 200
DECL_TEMPLATE(freebsd, sys_freebsd6_ftruncate) // 201
#endif
DECL_TEMPLATE(freebsd, sys___sysctl)
DECL_TEMPLATE(freebsd, sys_undelete)
DECL_TEMPLATE(freebsd, sys_futimes)
DECL_TEMPLATE(freebsd, sys_nfs_fhopen)
DECL_TEMPLATE(freebsd, sys_freebsd7___semctl)
DECL_TEMPLATE(freebsd, sys_semget)
DECL_TEMPLATE(freebsd, sys_semop)
DECL_TEMPLATE(freebsd, sys_freebsd7_msgctl)
DECL_TEMPLATE(freebsd, sys_msgget)
DECL_TEMPLATE(freebsd, sys_msgsnd)
DECL_TEMPLATE(freebsd, sys_msgrcv)
DECL_TEMPLATE(freebsd, sys_shmat)
DECL_TEMPLATE(freebsd, sys_freebsd7_shmctl)
DECL_TEMPLATE(freebsd, sys_shmdt)
DECL_TEMPLATE(freebsd, sys_shmget)
DECL_TEMPLATE(freebsd, sys_clock_gettime)
DECL_TEMPLATE(freebsd, sys_clock_settime)
DECL_TEMPLATE(freebsd, sys_clock_getres)
DECL_TEMPLATE(freebsd, sys_minherit)
DECL_TEMPLATE(freebsd, sys_rfork)
DECL_TEMPLATE(freebsd, sys_issetugid)
DECL_TEMPLATE(freebsd, sys_lchmod)
DECL_TEMPLATE(freebsd, sys_lutimes)
DECL_TEMPLATE(freebsd, sys_netbsd_msync)
DECL_TEMPLATE(freebsd, sys_nstat)
DECL_TEMPLATE(freebsd, sys_nfstat)
DECL_TEMPLATE(freebsd, sys_nlstat)
DECL_TEMPLATE(freebsd, sys_fhstatfs)
DECL_TEMPLATE(freebsd, sys_fhopen)

#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_fhstat)
#else
DECL_TEMPLATE(freebsd, sys_fhstat)
#endif

DECL_TEMPLATE(freebsd, sys_modnext)
DECL_TEMPLATE(freebsd, sys_modstat)
DECL_TEMPLATE(freebsd, sys_modfnext)
DECL_TEMPLATE(freebsd, sys_modfind)
DECL_TEMPLATE(freebsd, sys_kldload)
DECL_TEMPLATE(freebsd, sys_kldunload)
DECL_TEMPLATE(freebsd, sys_kldfind)
DECL_TEMPLATE(freebsd, sys_kldnext)
DECL_TEMPLATE(freebsd, sys_kldstat)
DECL_TEMPLATE(freebsd, sys_kldfirstmod)
DECL_TEMPLATE(freebsd, sys_setresuid)
DECL_TEMPLATE(freebsd, sys_setresgid)
DECL_TEMPLATE(freebsd, sys_aio_return)
DECL_TEMPLATE(freebsd, sys_aio_suspend)
DECL_TEMPLATE(freebsd, sys_aio_cancel)
DECL_TEMPLATE(freebsd, sys_aio_error)
DECL_TEMPLATE(freebsd, sys_aio_read)
DECL_TEMPLATE(freebsd, sys_aio_write)
DECL_TEMPLATE(freebsd, sys_lio_listio)
DECL_TEMPLATE(freebsd, sys_yield)
DECL_TEMPLATE(freebsd, sys_thr_sleep)
DECL_TEMPLATE(freebsd, sys_thr_wakeup)
DECL_TEMPLATE(freebsd, sys_munlockall)
DECL_TEMPLATE(freebsd, sys___getcwd)
DECL_TEMPLATE(freebsd, sys_sched_setparam)
DECL_TEMPLATE(freebsd, sys_sched_getparam)
DECL_TEMPLATE(freebsd, sys_sched_setscheduler)
DECL_TEMPLATE(freebsd, sys_sched_getscheduler)
DECL_TEMPLATE(freebsd, sys_sched_yield)
DECL_TEMPLATE(freebsd, sys_sched_get_priority_max)
DECL_TEMPLATE(freebsd, sys_sched_get_priority_min)
DECL_TEMPLATE(freebsd, sys_sched_rr_get_interval)
DECL_TEMPLATE(freebsd, sys_utrace)
DECL_TEMPLATE(freebsd, sys_kldsym)
DECL_TEMPLATE(freebsd, sys_jail)
DECL_TEMPLATE(freebsd, sys_sigprocmask)
DECL_TEMPLATE(freebsd, sys_sigsuspend)
// DECL_TEMPLATE(freebsd, sys_sigaction4)
DECL_TEMPLATE(freebsd, sys_sigaction)
DECL_TEMPLATE(freebsd, sys_sigpending)
DECL_TEMPLATE(freebsd, sys_sigreturn)
DECL_TEMPLATE(freebsd, sys_fake_sigreturn)
DECL_TEMPLATE(freebsd, sys_sigtimedwait)
DECL_TEMPLATE(freebsd, sys_sigwaitinfo)
DECL_TEMPLATE(freebsd, sys_getcontext)
DECL_TEMPLATE(freebsd, sys_setcontext)
DECL_TEMPLATE(freebsd, sys_swapcontext)
DECL_TEMPLATE(freebsd, sys___acl_get_file)
DECL_TEMPLATE(freebsd, sys___acl_set_file)
DECL_TEMPLATE(freebsd, sys___acl_get_fd)
DECL_TEMPLATE(freebsd, sys___acl_set_fd)
DECL_TEMPLATE(freebsd, sys___acl_delete_file)
DECL_TEMPLATE(freebsd, sys___acl_delete_fd)
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_file)
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_fd)
DECL_TEMPLATE(freebsd, sys___acl_get_link)
DECL_TEMPLATE(freebsd, sys___acl_set_link)
DECL_TEMPLATE(freebsd, sys___acl_delete_link)
DECL_TEMPLATE(freebsd, sys___acl_aclcheck_link)
DECL_TEMPLATE(freebsd, sys_sigwait)
DECL_TEMPLATE(freebsd, sys_extattrctl)
DECL_TEMPLATE(freebsd, sys_extattr_set_file)
DECL_TEMPLATE(freebsd, sys_extattr_get_file)
DECL_TEMPLATE(freebsd, sys_extattr_delete_file)
DECL_TEMPLATE(freebsd, sys_aio_waitcomplete)
DECL_TEMPLATE(freebsd, sys_getresuid)
DECL_TEMPLATE(freebsd, sys_getresgid)
DECL_TEMPLATE(freebsd, sys_kqueue)

#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_kevent)
#else
DECL_TEMPLATE(freebsd, sys_kevent)
#endif

DECL_TEMPLATE(freebsd, sys_sendfile)

#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_getfsstat)
DECL_TEMPLATE(freebsd, sys_freebsd11_statfs)
DECL_TEMPLATE(freebsd, sys_freebsd11_fstatfs)
DECL_TEMPLATE(freebsd, sys_freebsd11_fhstatfs)
#else
DECL_TEMPLATE(freebsd, sys_getfsstat)
DECL_TEMPLATE(freebsd, sys_statfs)
DECL_TEMPLATE(freebsd, sys_fstatfs)
DECL_TEMPLATE(freebsd, sys_fhstatfs)
#endif

DECL_TEMPLATE(freebsd, sys_thr_exit)
DECL_TEMPLATE(freebsd, sys_thr_self)
DECL_TEMPLATE(freebsd, sys_vfork)
DECL_TEMPLATE(freebsd, sys_modfind)

DECL_TEMPLATE(freebsd, sys_lkmnosys0) // 210
DECL_TEMPLATE(freebsd, sys_lkmnosys1)
DECL_TEMPLATE(freebsd, sys_lkmnosys2)
DECL_TEMPLATE(freebsd, sys_lkmnosys3)
DECL_TEMPLATE(freebsd, sys_lkmnosys4)
DECL_TEMPLATE(freebsd, sys_lkmnosys5)
DECL_TEMPLATE(freebsd, sys_lkmnosys6)
DECL_TEMPLATE(freebsd, sys_lkmnosys7)
DECL_TEMPLATE(freebsd, sys_lkmnosys8) // 218
DECL_TEMPLATE(freebsd, sys_modstat) // 301
DECL_TEMPLATE(freebsd, sys_eaccess) // 376
DECL_TEMPLATE(freebsd, sys_kenv) // 390
DECL_TEMPLATE(freebsd, sys_lchflags) // 391
DECL_TEMPLATE(freebsd, sys_uuidgen) // 392
DECL_TEMPLATE(freebsd, sys_thr_kill) // 433
DECL_TEMPLATE(freebsd, sys__umtx_lock) // 434
DECL_TEMPLATE(freebsd, sys__umtx_unlock) // 435
DECL_TEMPLATE(freebsd, sys_jail_attach) // 436
DECL_TEMPLATE(freebsd, sys_thr_wake) // 443

DECL_TEMPLATE(freebsd, sys__umtx_op) // 454
DECL_TEMPLATE(freebsd, sys_thr_new) // 455
DECL_TEMPLATE(freebsd, sys_kmq_open) // 457
DECL_TEMPLATE(freebsd, sys_kmq_setattr) // 458
DECL_TEMPLATE(freebsd, sys_kmq_timedreceive) // 459
DECL_TEMPLATE(freebsd, sys_kmq_timedsend) // 460
DECL_TEMPLATE(freebsd, sys_kmq_notify) // 461
DECL_TEMPLATE(freebsd, sys_kmq_unlink) // 462
DECL_TEMPLATE(freebsd, sys_thr_set_name) // 464
// aio_fsync 465
DECL_TEMPLATE(freebsd, sys_rtprio_thread) // 466
DECL_TEMPLATE(freebsd, sys_pread) // 475
DECL_TEMPLATE(freebsd, sys_pwrite) // 476
DECL_TEMPLATE(freebsd, sys_mmap) // 477
DECL_TEMPLATE(freebsd, sys_lseek) // 478
DECL_TEMPLATE(freebsd, sys_truncate) // 479
DECL_TEMPLATE(freebsd, sys_ftruncate) // 480
DECL_TEMPLATE(freebsd, sys_thr_kill2) // 481
DECL_TEMPLATE(freebsd, sys_shm_open) // 482
DECL_TEMPLATE(freebsd, sys_shm_unlink) // 483
DECL_TEMPLATE(freebsd, sys_cpuset) // 484
DECL_TEMPLATE(freebsd, sys_cpuset_setid) // 485
DECL_TEMPLATE(freebsd, sys_cpuset_getid) // 486
DECL_TEMPLATE(freebsd, sys_cpuset_getaffinity) // 487
DECL_TEMPLATE(freebsd, sys_cpuset_setaffinity) // 488
DECL_TEMPLATE(freebsd, sys_faccessat) // 489
DECL_TEMPLATE(freebsd, sys_fchmodat) //490
DECL_TEMPLATE(freebsd, sys_fchownat) // 491
DECL_TEMPLATE(freebsd, sys_fexecve)

#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_fstatat) // 493
#else
DECL_TEMPLATE(freebsd, sys_fstatat) // 493
#endif
DECL_TEMPLATE(freebsd, sys_futimesat) // 494
DECL_TEMPLATE(freebsd, sys_linkat) // 495
DECL_TEMPLATE(freebsd, sys_mkdirat) // 496
DECL_TEMPLATE(freebsd, sys_mkfifoat) // 497

#if (FREEBSD_VERS >= FREEBSD_12)
DECL_TEMPLATE(freebsd, sys_freebsd11_mknodat) // 498
#else
DECL_TEMPLATE(freebsd, sys_mknodat) // 498
#endif

DECL_TEMPLATE(freebsd, sys_openat) // 499
DECL_TEMPLATE(freebsd, sys_readlinkat) // 500
DECL_TEMPLATE(freebsd, sys_renameat) // 501
DECL_TEMPLATE(freebsd, sys_symlinkat) // 502
DECL_TEMPLATE(freebsd, sys_unlinkat) // 503
DECL_TEMPLATE(freebsd, sys_posix_openpt) // 504
DECL_TEMPLATE(freebsd, sys_jail_get)
DECL_TEMPLATE(freebsd, sys_jail_set)
DECL_TEMPLATE(freebsd, sys_jail_remove)
DECL_TEMPLATE(freebsd, sys___semctl)
DECL_TEMPLATE(freebsd, sys_msgctl)
DECL_TEMPLATE(freebsd, sys_shmctl)
// lpathconf
DECL_TEMPLATE(freebsd, sys_cap_rights_get)
DECL_TEMPLATE(freebsd, sys_cap_enter)
DECL_TEMPLATE(freebsd, sys_cap_getmode)
DECL_TEMPLATE(freebsd, sys_pdfork)
DECL_TEMPLATE(freebsd, sys_pdkill)
DECL_TEMPLATE(freebsd, sys_pdgetpid)
DECL_TEMPLATE(freebsd, sys_pselect)
// getloginclass
// setloginclass
// rctl_get_racct
// rctl_get_rules
// rctl_get_limits
// rctl_add_rule
// rctl_remove_rule
DECL_TEMPLATE(freebsd, sys_posix_fallocate)
DECL_TEMPLATE(freebsd, sys_posix_fadvise)
// wait6
DECL_TEMPLATE(freebsd, sys_cap_rights_limit)
DECL_TEMPLATE(freebsd, sys_cap_ioctls_limit)
// get_ioctls_get
DECL_TEMPLATE(freebsd, sys_cap_fcntls_limit)
// cap_fcntls_get
// bindat
// connectat
// chflagsat
DECL_TEMPLATE(freebsd, sys_accept4)
DECL_TEMPLATE(freebsd, sys_pipe2)
// aio_mlock
// procctl
DECL_TEMPLATE(freebsd, sys_ppoll)
// futimens
// utimensat
// fdatasync

#if (FREEBSD_VERS >= FREEBSD_12)

DECL_TEMPLATE(freebsd, sys_fstat)
DECL_TEMPLATE(freebsd, sys_fstatat)
DECL_TEMPLATE(freebsd, sys_fhstat)
DECL_TEMPLATE(freebsd, sys_getdirentries)
DECL_TEMPLATE(freebsd, sys_statfs)
DECL_TEMPLATE(freebsd, sys_fstatfs)
DECL_TEMPLATE(freebsd, sys_getfsstat)
DECL_TEMPLATE(freebsd, sys_fhstatfs)
DECL_TEMPLATE(freebsd, sys_mknodat)
DECL_TEMPLATE(freebsd, sys_kevent)
// cpuset_getdomain
// cpuset_setdomain
DECL_TEMPLATE(freebsd, sys_getrandom)
DECL_TEMPLATE(freebsd, sys_getfhat)
// fhlink
// fhlinkat
// fhreadlink

#endif

#endif   // PRIV_SYSWRAP_FREEBSD_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
