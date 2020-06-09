/*--------------------------------------------------------------------*/
/*--- FreeBSD-specific syscalls, etc.            syswrap-freebsd.c ---*/
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

#if defined(VGO_freebsd)

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_debuginfo.h"    // VG_(di_notify_*)
#include "pub_core_transtab.h"     // VG_(discard_translations)
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_machine.h"
#include "pub_core_mallocfree.h"
#include "pub_core_tooliface.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_signals.h"
#include "pub_core_stacks.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_inner.h"
#if defined(ENABLE_INNER_CLIENT_REQUEST)
#include "pub_core_clreq.h"
#endif

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"
#include "priv_syswrap-main.h"
#include "priv_syswrap-freebsd.h"

static Bool capabiltyMode = False;

Bool VG_(getCapabilityMode)(void)
{
    return capabiltyMode;
}


// Run a thread from beginning to end and return the thread's
// scheduler-return-code.
static VgSchedReturnCode thread_wrapper(Word /*ThreadId*/ tidW)
{
   VgSchedReturnCode ret;
   ThreadId     tid = (ThreadId)tidW;
   ThreadState* tst = VG_(get_ThreadState)(tid);

   VG_(debugLog)(1, "syswrap-freebsd", 
                    "thread_wrapper(tid=%u): entry\n",
                    tid);

   vg_assert(tst->status == VgTs_Init);

   /* make sure we get the CPU lock before doing anything significant */
   VG_(acquire_BigLock)(tid, "thread_wrapper(starting new thread)");

   if (0)
      VG_(printf)("thread tid %u started: stack = %p\n",
                   tid, (void*)&tid);

   /* Make sure error reporting is enabled in the new thread. */
   tst->err_disablement_level = 0;

   VG_TRACK(pre_thread_first_insn, tid);

   tst->os_state.lwpid = VG_(gettid)();
   /* Set the threadgroup for real.  This overwrites the provisional value set
      in do_clone().  See comments in do_clone for background, also #226116. */
   tst->os_state.threadgroup = VG_(getpid)();

   /* Thread created with all signals blocked; scheduler will set the
      appropriate mask */

   ret = VG_(scheduler)(tid);

   vg_assert(VG_(is_exiting)(tid));
   
   vg_assert(tst->status == VgTs_Runnable);
   vg_assert(VG_(is_running_thread)(tid));

   VG_(debugLog)(1, "syswrap-freebsd", 
                    "thread_wrapper(tid=%u): exit, schedreturncode %s\n", 
                    tid, VG_(name_of_VgSchedReturnCode)(ret));

   /* Return to caller, still holding the lock. */
   return ret;
}


/* ---------------------------------------------------------------------
   clone-related stuff
   ------------------------------------------------------------------ */

/* Run a thread all the way to the end, then do appropriate exit actions
   (this is the last-one-out-turn-off-the-lights bit).  */
__attribute__((noreturn))
static void run_a_thread_NORETURN ( Word tidW )
{
   ThreadId          tid = (ThreadId)tidW;
   VgSchedReturnCode src;
   Int               c;
   ThreadState*      tst;
#ifdef ENABLE_INNER_CLIENT_REQUEST
   Int               registered_vgstack_id;
#endif

   VG_(debugLog)(1, "syswrap-freebsd", 
                    "run_a_thread_NORETURN(tid=%u): pre-thread_wrapper\n",
                    tid);

   tst = VG_(get_ThreadState)(tid);
   vg_assert(tst);

   /* An thread has two stacks:
      * the simulated stack (used by the synthetic cpu. Guest process
        is using this stack).
      * the valgrind stack (used by the real cpu. Valgrind code is running
        on this stack).
      When Valgrind runs as an inner, it must signals that its (real) stack
      is the stack to use by the outer to e.g. do stacktraces.
   */
   INNER_REQUEST
      (registered_vgstack_id 
       = VALGRIND_STACK_REGISTER (tst->os_state.valgrind_stack_base,
                                  tst->os_state.valgrind_stack_init_SP));
   
   /* Run the thread all the way through. */
   src = thread_wrapper(tid);  

   VG_(debugLog)(1, "syswrap-freebsd", 
                    "run_a_thread_NORETURN(tid=%u): post-thread_wrapper\n",
                    tid);

   c = VG_(count_living_threads)();
   vg_assert(c >= 1); /* stay sane */

   /* Deregister thread's stack. */
   if (tst->os_state.stk_id != NULL_STK_ID)
      VG_(deregister_stack)(tst->os_state.stk_id);

   // Tell the tool this thread is exiting
   VG_TRACK( pre_thread_ll_exit, tid );

   /* If the thread is exiting with errors disabled, complain loudly;
      doing so is bad (does the user know this has happened?)  Also,
      in all cases, be paranoid and clear the flag anyway so that the
      thread slot is safe in this respect if later reallocated.  This
      should be unnecessary since the flag should be cleared when the
      slot is reallocated, in thread_wrapper(). */
   if (tst->err_disablement_level > 0) {
      VG_(umsg)(
         "WARNING: exiting thread has error reporting disabled.\n"
         "WARNING: possibly as a result of some mistake in the use\n"
         "WARNING: of the VALGRIND_DISABLE_ERROR_REPORTING macros.\n"
      );
      VG_(debugLog)(
         1, "syswrap-freebsd", 
            "run_a_thread_NORETURN(tid=%u): "
            "WARNING: exiting thread has err_disablement_level = %u\n",
            tid, tst->err_disablement_level
      );
   }
   tst->err_disablement_level = 0;

   if (c == 1) {

      VG_(debugLog)(1, "syswrap-freebsd", 
                       "run_a_thread_NORETURN(tid=%u): "
                          "last one standing\n",
                          tid);

      /* We are the last one standing.  Keep hold of the lock and
         carry on to show final tool results, then exit the entire system. 
         Use the continuation pointer set at startup in m_main. */
      ( * VG_(address_of_m_main_shutdown_actions_NORETURN) ) (tid, src);
   } else {

      VG_(debugLog)(1, "syswrap-freebsd", 
                       "run_a_thread_NORETURN(tid=%u): "
                          "not last one standing\n",
                          tid);

      /* OK, thread is dead, but others still exist.  Just exit. */

      /* This releases the run lock */
      VG_(exit_thread)(tid);
      vg_assert(tst->status == VgTs_Zombie);
      vg_assert(sizeof(tst->status) == 4);
      vg_assert(sizeof(tst->os_state.exitcode) == sizeof(Word));

      INNER_REQUEST (VALGRIND_STACK_DEREGISTER (registered_vgstack_id));

      /* We have to use this sequence to terminate the thread to
         prevent a subtle race.  If VG_(exit_thread)() had left the
         ThreadState as Empty, then it could have been reallocated,
         reusing the stack while we're doing these last cleanups.
         Instead, VG_(exit_thread) leaves it as Zombie to prevent
         reallocation.  We need to make sure we don't touch the stack
         between marking it Empty and exiting.  Hence the
         assembler. */
#if defined(VGP_x86_freebsd)    /* FreeBSD has args on the stack */
      asm volatile (
         "movl    %1, %0\n"    /* set tst->status = VgTs_Empty */
         "movl    %2, %%eax\n"    /* set %eax = __NR_thr_exit */
         "movl    %3, %%ebx\n"    /* set %ebx = tst->os_state.exitcode */
         "pushl   %%ebx\n"    /* arg on stack */
         "pushl   %%ebx\n"    /* fake return address */
         "int     $0x80\n"    /* thr_exit(tst->os_state.exitcode) */
         "popl    %%ebx\n"    /* fake return address */
         "popl    %%ebx\n"    /* arg off stack */
         : "=m" (tst->status)
         : "n" (VgTs_Empty), "n" (__NR_thr_exit), "m" (tst->os_state.exitcode)
         : "eax", "ebx"
      );
#elif defined(VGP_amd64_freebsd)
      asm volatile (
         "movl   %1, %0\n"    /* set tst->status = VgTs_Empty */
         "movq   %2, %%rax\n"    /* set %rax = __NR_thr_exit */
         "movq   %3, %%rdi\n"    /* set %rdi = tst->os_state.exitcode */
         "pushq  %%rdi\n"    /* fake return address */
         "syscall\n"        /* thr_exit(tst->os_state.exitcode) */
         "popq   %%rdi\n"    /* fake return address */
         : "=m" (tst->status)
         : "n" (VgTs_Empty), "n" (__NR_thr_exit), "m" (tst->os_state.exitcode)
         : "rax", "rdi"
      );
#else
# error Unknown platform
#endif

      VG_(core_panic)("Thread exit failed?\n");
   }

   /*NOTREACHED*/
   vg_assert(0);
}

Word ML_(start_thread_NORETURN) ( void* arg )
{
   ThreadState* tst = (ThreadState*)arg;
   ThreadId     tid = tst->tid;

   run_a_thread_NORETURN ( (Word)tid );
   /*NOTREACHED*/
   vg_assert(0);
}

/* Allocate a stack for this thread, if it doesn't already have one.
   They're allocated lazily, and never freed.  Returns the initial stack
   pointer value to use, or 0 if allocation failed. */
Addr ML_(allocstack)(ThreadId tid)
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   VgStack*     stack;
   Addr         initial_SP;

   /* Either the stack_base and stack_init_SP are both zero (in which
      case a stack hasn't been allocated) or they are both non-zero,
      in which case it has. */

   if (tst->os_state.valgrind_stack_base == 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP == 0);

   if (tst->os_state.valgrind_stack_base != 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP != 0);

   /* If no stack is present, allocate one. */

   if (tst->os_state.valgrind_stack_base == 0) {
      stack = VG_(am_alloc_VgStack)( &initial_SP );
      if (stack) {
         tst->os_state.valgrind_stack_base    = (Addr)stack;
         tst->os_state.valgrind_stack_init_SP = initial_SP;
      }
   }

   if (0)
      VG_(printf)( "stack for tid %u at %p; init_SP=%p\n",
                   tid, 
                   (void*)tst->os_state.valgrind_stack_base, 
                   (void*)tst->os_state.valgrind_stack_init_SP );
                  
   return tst->os_state.valgrind_stack_init_SP;
}

/* Allocate a stack for the main thread, and run it all the way to the
   end.  Although we already have a working VgStack
   (VG_(interim_stack)) it's better to allocate a new one, so that
   overflow detection works uniformly for all threads.
*/
__attribute__((noreturn))
void VG_(main_thread_wrapper_NORETURN)(ThreadId tid)
{
   Addr sp;
   VG_(debugLog)(1, "syswrap-freebsd", 
                    "entering VG_(main_thread_wrapper_NORETURN)\n");

   sp = ML_(allocstack)(tid);
#if defined(ENABLE_INNER_CLIENT_REQUEST)
   {
      // we must register the main thread stack before the call
      // to ML_(call_on_new_stack_0_1), otherwise the outer valgrind
      // reports 'write error' on the non registered stack.
      ThreadState* tst = VG_(get_ThreadState)(tid);
      INNER_REQUEST
         ((void) 
          VALGRIND_STACK_REGISTER (tst->os_state.valgrind_stack_base,
                                   tst->os_state.valgrind_stack_init_SP));
   }
#endif

   /* If we can't even allocate the first thread's stack, we're hosed.
      Give up. */
   vg_assert2(sp != 0, "%s", "Cannot allocate main thread's stack.");

   /* shouldn't be any other threads around yet */
   vg_assert( VG_(count_living_threads)() == 1 );

   ML_(call_on_new_stack_0_1)( 
      (Addr)sp,               /* stack */
      0,                      /* bogus return address */
      run_a_thread_NORETURN,  /* fn to call */
      (Word)tid               /* arg to give it */
   );

   /*NOTREACHED*/
   vg_assert(0);
}


/* Do a fork() */
SysRes ML_(do_fork) ( ThreadId tid )
{
   vki_sigset_t fork_saved_mask;
   vki_sigset_t mask;
   SysRes       res;

   /* Block all signals during fork, so that we can fix things up in
      the child without being interrupted. */
   VG_(sigfillset)(&mask);
   VG_(sigprocmask)(VKI_SIG_SETMASK, &mask, &fork_saved_mask);

   VG_(do_atfork_pre)(tid);

   res = VG_(do_syscall0)( __NR_fork );
   
   if (!sr_isError(res)) {
      if (sr_Res(res) == 0) {
         /* child */
         VG_(do_atfork_child)(tid);

         /* restore signal mask */
         VG_(sigprocmask)(VKI_SIG_SETMASK, &fork_saved_mask, NULL);

      } 
      else { 
         /* parent */
         VG_(do_atfork_parent)(tid);

         if (VG_(clo_trace_syscalls))
         VG_(printf)("   clone(fork): process %d created child %lu\n",
                         VG_(getpid)(), sr_Res(res));

         /* restore signal mask */
         VG_(sigprocmask)(VKI_SIG_SETMASK, &fork_saved_mask, NULL);
      }
   }

   return res;
}


/* ---------------------------------------------------------------------
   PRE/POST wrappers for arch-generic, FreeBSD-specific syscalls
   ------------------------------------------------------------------ */

// Nb: See the comment above the generic PRE/POST wrappers in
// m_syswrap/syswrap-generic.c for notes about how they work.

#define PRE(name)       DEFN_PRE_TEMPLATE(freebsd, name)
#define POST(name)      DEFN_POST_TEMPLATE(freebsd, name)

PRE(sys_fork)
{
   PRINT("%s", "sys_fork ()");
   PRE_REG_READ0(int, "fork");

   SET_STATUS_from_SysRes( ML_(do_fork)(tid) );
   if (SUCCESS) {
      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }
}

PRE(sys_vfork)
{
   PRINT("%s", "sys_vfork ()");
   PRE_REG_READ0(int, "vfork");

   /* Pretend vfork == fork. Not true, but will have to do. */
   SET_STATUS_from_SysRes( ML_(do_fork)(tid) );
   if (SUCCESS) {
      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }
}

PRE(sys_sbrk)
{
   PRINT("sys_sbrk ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(void*, "sbrk", vki_intptr_t, incr);
}

// int socket(int domain, int type, int protocol);
PRE(sys_socket)
{
   PRINT("sys_socket ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %" FMT_REGWORD "d )",SARG1,SARG2,SARG3);
   PRE_REG_READ3(long, "socket", int, domain, int, type, int, protocol);
}

POST(sys_socket)
{
   SysRes r;
   vg_assert(SUCCESS);
   r = ML_(generic_POST_sys_socket)(tid, VG_(mk_SysRes_Success)(RES));
   SET_STATUS_from_SysRes(r);
}

// int setsockopt(int s, int level, int optname, const void *optval,
//                socklen_t optlen);
PRE(sys_setsockopt)
{
   PRINT("sys_setsockopt ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",SARG1,SARG2,SARG3,ARG4,ARG5);
   PRE_REG_READ5(int, "setsockopt",
                 int, s, int, level, int, optname,
                 const void *, optval, vki_socklen_t, optlen);
   ML_(generic_PRE_sys_setsockopt)(tid, ARG1,ARG2,ARG3,ARG4,ARG5);
}

PRE(sys_getsockopt)
{
   Addr optval_p = ARG4;
   Addr optlen_p = ARG5;
   PRINT("sys_getsockopt ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "getsockopt",
                 int, s, int, level, int, optname,
                 void *, optval, int, *optlen);
   if (optval_p != (Addr)NULL) {
      ML_(buf_and_len_pre_check) ( tid, optval_p, optlen_p,
                                   "getsockopt(optval)",
                                   "getsockopt(optlen)" );
   }
}

POST(sys_getsockopt)
{
   Addr optval_p = ARG4;
   Addr optlen_p = ARG5;
   vg_assert(SUCCESS);
   if (optval_p != (Addr)NULL) {
      ML_(buf_and_len_post_check) ( tid, VG_(mk_SysRes_Success)(RES),
                                    optval_p, optlen_p,
                                    "getsockopt(optlen_out)" );
   }
}

PRE(sys_connect)
{
   *flags |= SfMayBlock;
   PRINT("sys_connect ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "connect",
                 int, sockfd, struct sockaddr *, serv_addr, int, addrlen);
   ML_(generic_PRE_sys_connect)(tid, ARG1,ARG2,ARG3);
}

PRE(sys_accept)
{
   *flags |= SfMayBlock;
   PRINT("sys_accept ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "accept",
                 int, s, struct sockaddr *, addr, int, *addrlen);
   ML_(generic_PRE_sys_accept)(tid, ARG1,ARG2,ARG3);
}

POST(sys_accept)
{
   SysRes r;
   vg_assert(SUCCESS);
   r = ML_(generic_POST_sys_accept)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3);
   SET_STATUS_from_SysRes(r);
}

PRE(sys_sendto)
{
   *flags |= SfMayBlock;
   PRINT("sys_sendto ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   PRE_REG_READ6(long, "sendto",
                 int, s, const void *, msg, int, len, 
                 unsigned int, flags, 
                 const struct sockaddr *, to, int, tolen);
   ML_(generic_PRE_sys_sendto)(tid, ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// ssize_t recvfrom(int s, void *buf, size_t len, int flags,
//                  struct sockaddr * restrict from, socklen_t * restrict fromlen);
PRE(sys_recvfrom)
{
   *flags |= SfMayBlock;
   PRINT("sys_recvfrom ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",SARG1,ARG2,ARG3,SARG4,ARG5,ARG6);
   PRE_REG_READ6(long, "recvfrom",
                 int, s, void *, buf, int, len, unsigned int, flags,
                 struct sockaddr *, from, int *, fromlen);
   ML_(generic_PRE_sys_recvfrom)(tid, ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

POST(sys_recvfrom)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_recvfrom)(tid, VG_(mk_SysRes_Success)(RES),
                                       ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

PRE(sys_sendmsg)
{
   *flags |= SfMayBlock;
   PRINT("sys_sendmsg ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sendmsg",
                 int, s, const struct msghdr *, msg, int, flags);
   ML_(generic_PRE_sys_sendmsg)(tid, "sendmsg", (struct vki_msghdr *)ARG2);
}

PRE(sys_recvmsg)
{
   *flags |= SfMayBlock;
   PRINT("sys_recvmsg ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "d )",SARG1,ARG2,SARG3);
   PRE_REG_READ3(vki_ssize_t, "recvmsg", int, s, struct msghdr *, msg, int, flags);
   ML_(generic_PRE_sys_recvmsg)(tid, "recvmsg", (struct vki_msghdr *)ARG2);
}

POST(sys_recvmsg)
{

   ML_(generic_POST_sys_recvmsg)(tid, "recvmsg", (struct vki_msghdr *)ARG2, RES);
}

PRE(sys_shutdown)
{
   *flags |= SfMayBlock;
   PRINT("sys_shutdown ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2);
   PRE_REG_READ2(int, "shutdown", int, s, int, how);
}

PRE(sys_bind)
{
   PRINT("sys_bind ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "bind",
                 int, sockfd, struct sockaddr *, my_addr, int, addrlen);
   ML_(generic_PRE_sys_bind)(tid, ARG1,ARG2,ARG3);
}

// int listen(int s, int backlog);
PRE(sys_listen)
{
   PRINT("sys_listen ( %" FMT_REGWORD "d, %" FMT_REGWORD "d )",SARG1,SARG2);
   PRE_REG_READ2(long, "listen", int, s, int, backlog);
}

// int getsockname(int s, struct sockaddr * restrict name,
//                 socklen_t * restrict namelen);
PRE(sys_getsockname)
{
   PRINT("sys_getsockname ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",SARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getsockname",
                 int, s, struct sockaddr *, name, int *, namelen);
   ML_(generic_PRE_sys_getsockname)(tid, ARG1,ARG2,ARG3);
}

POST(sys_getsockname)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_getsockname)(tid, VG_(mk_SysRes_Success)(RES),
                                          ARG1,ARG2,ARG3);
}

PRE(sys_getpeername)
{
   PRINT("sys_getpeername ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getpeername",
                 int, s, struct sockaddr *, name, int *, namelen);
   ML_(generic_PRE_sys_getpeername)(tid, ARG1,ARG2,ARG3);
}

POST(sys_getpeername)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_getpeername)(tid, VG_(mk_SysRes_Success)(RES),
                                          ARG1,ARG2,ARG3);
}

PRE(sys_socketpair)
{
   PRINT("sys_socketpair ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "socketpair",
                 int, d, int, type, int, protocol, int *, sv);
   ML_(generic_PRE_sys_socketpair)(tid, ARG1,ARG2,ARG3,ARG4);
}

POST(sys_socketpair)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_socketpair)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3,ARG4);
}

// int adjtime(const struct timeval *delta, struct timeval *olddelta);
PRE(sys_adjtime)
{
   PRINT("sys_adjtime ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(int, "adjtime",
                 const struct vki_timeval *, delta, struct vki_timeval *, olddelta);
   PRE_MEM_READ("adjtime(delta)", ARG1, sizeof(struct vki_timeval));
   if (ARG2) {
      PRE_MEM_WRITE("adjtime(olddelta)", ARG1, sizeof(struct vki_timeval));
   }
}

POST(sys_adjtime)
{
   if (ARG2) {
      POST_MEM_WRITE(ARG1, sizeof(struct vki_timeval));
   }
}

/* ---------------------------------------------------------------------
   *mount wrappers
   ------------------------------------------------------------------ */

PRE(sys_mount)
{
   // Nb: depending on 'flags', the 'type' and 'data' args may be ignored.
   // We are conservative and check everything, except the memory pointed to
   // by 'data'.
   *flags |= SfMayBlock;
   PRINT( "sys_mount( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )" ,ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "mount",
                 char *, type, char *, path, int, flags,
                 void *, data);
   PRE_MEM_RASCIIZ( "mount(type)", ARG1);
   PRE_MEM_RASCIIZ( "mount(path)", ARG2);
}

PRE(sys_unmount)
{
   PRINT("sys_umount( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1, ARG2);
   PRE_REG_READ2(long, "unmount", char *, path, int, flags);
   PRE_MEM_RASCIIZ( "unmount(path)", ARG1);
}

/* ---------------------------------------------------------------------
   16- and 32-bit uid/gid wrappers
   ------------------------------------------------------------------ */

#if 0
PRE(sys_setfsuid)
{
   PRINT("sys_setfsuid ( %" FMT_REGWORD "d )", ARG1);
   PRE_REG_READ1(long, "setfsuid", vki_uid_t, uid);
}

PRE(sys_setfsgid)
{
   PRINT("sys_setfsgid ( %" FMT_REGWORD "d )", ARG1);
   PRE_REG_READ1(long, "setfsgid", vki_gid_t, gid);
}
#endif

PRE(sys_setresuid)
{
   PRINT("sys_setresuid ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresuid",
                 vki_uid_t, ruid, vki_uid_t, euid, vki_uid_t, suid);
}

PRE(sys_getresuid)
{
   PRINT("sys_getresuid ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresuid", 
                 vki_uid_t *, ruid, vki_uid_t *, euid, vki_uid_t *, suid);
   PRE_MEM_WRITE( "getresuid(ruid)", ARG1, sizeof(vki_uid_t) );
   PRE_MEM_WRITE( "getresuid(euid)", ARG2, sizeof(vki_uid_t) );
   PRE_MEM_WRITE( "getresuid(suid)", ARG3, sizeof(vki_uid_t) );
}

POST(sys_getresuid)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_uid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_uid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_uid_t) );
   }
}

PRE(sys_setresgid)
{
   PRINT("sys_setresgid ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresgid",
                 vki_gid_t, rgid, vki_gid_t, egid, vki_gid_t, sgid);
}

PRE(sys_getresgid)
{
   PRINT("sys_getresgid ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresgid", 
                 vki_gid_t *, rgid, vki_gid_t *, egid, vki_gid_t *, sgid);
   PRE_MEM_WRITE( "getresgid(rgid)", ARG1, sizeof(vki_gid_t) );
   PRE_MEM_WRITE( "getresgid(egid)", ARG2, sizeof(vki_gid_t) );
   PRE_MEM_WRITE( "getresgid(sgid)", ARG3, sizeof(vki_gid_t) );
}

POST(sys_getresgid)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_gid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_gid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_gid_t) );
   }
}

/* ---------------------------------------------------------------------
   miscellaneous wrappers
   ------------------------------------------------------------------ */

#if 0
PRE(sys_exit_group)
{
   ThreadId     t;
   ThreadState* tst;

   PRINT("exit_group( %" FMT_REGWORD "d )", ARG1);
   PRE_REG_READ1(void, "exit_group", int, exit_code);

   tst = VG_(get_ThreadState)(tid);

   /* A little complex; find all the threads with the same threadgroup
      as this one (including this one), and mark them to exit */
   for (t = 1; t < VG_N_THREADS; t++) {
      if ( /* not alive */
           VG_(threads)[t].status == VgTs_Empty 
           ||
       /* not our group */
           VG_(threads)[t].os_state.threadgroup != tst->os_state.threadgroup
         )
         continue;

      VG_(threads)[t].exitreason = VgSrc_ExitSyscall;
      VG_(threads)[t].os_state.exitcode = ARG1;

      if (t != tid)
         VG_(get_thread_out_of_syscall)(t);    /* unblock it, if blocked */
   }

   /* We have to claim the syscall already succeeded. */
   SET_STATUS_Success(0);
}
#endif

/* On FreeBSD, if any thread calls exit(2), then they are all shut down, pretty
 * much like linux's exit_group().
 */
PRE(sys_exit)
{
   ThreadId     t;

   PRINT("exit( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(void, "exit", int, status);

   /* Mark all threads (including this one) to exit. */
   for (t = 1; t < VG_N_THREADS; t++) {
      if ( /* not alive */ VG_(threads)[t].status == VgTs_Empty )
         continue;

      //VG_(threads)[t].exitreason = VgSrc_ExitThread;
      VG_(threads)[t].os_state.exitcode = ARG1;

     // if (t != tid)
    // VG_(get_thread_out_of_syscall)(t);    /* unblock it, if blocked */
   }

   VG_(nuke_all_threads_except)( tid, VgSrc_ExitProcess );
   VG_(reap_threads)(tid);
   VG_(threads)[tid].exitreason = VgSrc_ExitThread;

   /* We have to claim the syscall already succeeded. */
   SET_STATUS_Success(0);
}

PRE(sys_getlogin)
{
   PRINT("sys_getlogin ( )");
   PRE_REG_READ0(char *, "getlogin");
}

POST(sys_getlogin)
{
   if (ARG1 != 0) {
      POST_MEM_WRITE( ARG1, ARG2 );
   }
}

PRE(sys_setlogin)
{
   PRINT("sys_setlogin ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(long, "setlogin", char *, buf);
   PRE_MEM_RASCIIZ( "setlogin(buf)", ARG1 );
}

PRE(sys_mkfifo)
{
   PRINT("sys_mkfifo ( %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x, 0x%" FMT_REGWORD "x )", ARG1, (char *)ARG1, ARG2, ARG3 );
   PRE_REG_READ2(long, "mkfifo", const char *, pathname, int, mode);
   PRE_MEM_RASCIIZ( "mkfifo(pathname)", ARG1 );
}

/* int quotactl(const char *path, int cmd, int id, void *addr); */
PRE(sys_quotactl)
{
   PRINT("sys_quotactl ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3, ARG4);
   switch (ARG2) {
   case VKI_Q_QUOTAON:
   case VKI_Q_SETQUOTA:
   case VKI_Q_SETUSE:

   case VKI_Q_GETQUOTASIZE:
      PRE_REG_READ4(int, "quotactl",
                    const char *, path, int, cmd, int, id,
                    void *, addr);
      PRE_MEM_RASCIIZ( "quotactl(path)", ARG1 );
      break;
   case VKI_Q_GETQUOTA:
      // @todo PJF strictly this one does not read id but I don't know how to
      // check just args 1, 2 and 4, probably needs a
      if (VG_(tdict).track_pre_reg_read) { \
         PRRSN;
         PRA1("quotactl",const char*,path);
         PRA2("quotactl",int,cmd);
         PRA4("quotactl",void*,addr);
      }
      break;
   case VKI_Q_QUOTAOFF:
   case VKI_Q_SYNC:
      PRE_REG_READ2(int, "quotactl",
                    const char *, path, int, cmd);
      break;
   default:
      break;
   }
}

// int lgetfh(const char *path, fhandle_t *fhp);
PRE(sys_lgetfh)
{
   PRINT("sys_lgetfh ( %#" FMT_REGWORD "x, %" FMT_REGWORD "x ", ARG1, ARG2);
   PRE_REG_READ2(int, "lgetfh", const char*, path, vki_fhandle_t*, fhp);
   PRE_MEM_RASCIIZ( "lgetfh(path)", ARG1 );
   PRE_MEM_WRITE("lgetfh(fhp)", ARG2, sizeof(vki_fhandle_t));
}

POST(sys_lgetfh)
{
   POST_MEM_WRITE(ARG2, sizeof(vki_fhandle_t));
}

// int getfh(const char *path, fhandle_t *fhp);
PRE(sys_getfh)
{
   PRINT("sys_getfh ( %#" FMT_REGWORD "x, %" FMT_REGWORD "x ", ARG1, ARG2);
   PRE_REG_READ2(int, "getfh", const char*, path, vki_fhandle_t*, fhp);
   PRE_MEM_RASCIIZ( "getfh(path)", ARG1 );
   PRE_MEM_WRITE("getfh(fhp)", ARG2, sizeof(vki_fhandle_t));
}

POST(sys_getfh)
{
   POST_MEM_WRITE(ARG2, sizeof(vki_fhandle_t));
}

#if (FREEBSD_VERS <= FREEBSD_10)
/* int getdomainname(char *domainname, int len); */
PRE(sys_freebsd4_getdomainname)
{
   PRINT("sys_freebsd4_getdomainname ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2);
   PRE_REG_READ2(long, "getdomainname",
                 char *, buf, int, len);
   PRE_MEM_WRITE( "getdomainname(buf, len)", ARG1, ARG2 );
}

POST(sys_freebsd4_getdomainname)
{
   if (ARG1 != 0) {
      POST_MEM_WRITE( ARG1, ARG2 );
   }
}

/* int setdomainname(char *domainname, int len); */
PRE(sys_freebsd4_setdomainname)
{
   PRINT("sys_freebsd4_setdomainname ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(long, "setdomainname", char *, buf);
   PRE_MEM_RASCIIZ( "setdomainname(buf)", ARG1 );
}

PRE(sys_freebsd4_uname)
{
   PRINT("sys_freebsd4_uname ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "uname", struct utsname *, buf);
   PRE_MEM_WRITE( "uname(buf)", ARG1, sizeof(struct vki_utsname) );
}

POST(sys_freebsd4_uname)
{
   if (ARG1 != 0) {
      POST_MEM_WRITE( ARG1, sizeof(struct vki_utsname) );
   }
}
#endif

PRE(sys_lstat)
{
   PRINT("sys_lstat ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "lstat", char *, file_name, struct stat *, buf);
   PRE_MEM_RASCIIZ( "lstat(file_name)", ARG1 );
   PRE_MEM_WRITE( "lstat(buf)", ARG2, sizeof(struct vki_stat) );
}

POST(sys_lstat)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG2, sizeof(struct vki_stat) );
   }
}

PRE(sys_stat)
{
   PRINT("sys_stat ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "stat", char *, file_name, struct stat *, buf);
   PRE_MEM_RASCIIZ( "stat(file_name)", ARG1 );
   PRE_MEM_WRITE( "stat(buf)", ARG2, sizeof(struct vki_stat) );
}

POST(sys_stat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat) );
}

#if (FREEBSD_VERS >= FREEBSD_12)

PRE(sys_freebsd11_fstat)
{
   PRINT("sys_freebsd11_fstat ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x )",SARG1,ARG2);
   PRE_REG_READ2(long, "fstat", unsigned long, fd, struct stat *, buf);
   PRE_MEM_WRITE( "fstat(buf)", ARG2, sizeof(struct vki_freebsd11_stat) );
}

POST(sys_freebsd11_fstat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_stat) );
}

#else

PRE(sys_fstat)
{
   PRINT("sys_fstat ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x )",SARG1,ARG2);
   PRE_REG_READ2(long, "fstat", unsigned long, fd, struct stat *, buf);
   PRE_MEM_WRITE( "fstat(buf)", ARG2, sizeof(struct vki_freebsd11_stat) );
}

POST(sys_fstat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_stat) );
}

#endif

PRE(sys_pathconf)
{
   PRINT("sys_pathconf ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "pathconf", char *, file_name, int, name);
   PRE_MEM_RASCIIZ( "pathconf(file_name)", ARG1 );
}

PRE(sys_fpathconf)
{
   PRINT("sys_fpathconf ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2);
   PRE_REG_READ2(long, "fpathconf", int, fd, int, name);
}

PRE(sys_lchmod)
{
   PRINT("sys_lchmod ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "lchmod", const char *, path, vki_mode_t, mode);
   PRE_MEM_RASCIIZ( "lchmod(path)", ARG1 );
}

PRE(sys_issetugid)
{
   PRINT("%s", "sys_issetugid ()");
   PRE_REG_READ0(long, "issetugid");
}

// int revoke(const char *path);
PRE(sys_revoke)
{
   PRINT("sys_revoke ( %#" FMT_REGWORD "x(%s) )", ARG1, (char*)ARG1);
   PRE_REG_READ1(long, "revoke", const char *, path);
   PRE_MEM_RASCIIZ( "revoke(path)", ARG1);
}

PRE(sys_undelete)
{
   *flags |= SfMayBlock;
   PRINT("sys_undelete ( %#" FMT_REGWORD "x(%s) )", ARG1,(char *)ARG1);
   PRE_REG_READ1(long, "undelete", const char *, pathname);
   PRE_MEM_RASCIIZ( "undelete(pathname)", ARG1 );
}

PRE(sys_yield)
{
   *flags |= SfMayBlock;
   PRINT("%s", "yield()");
   PRE_REG_READ0(long, "yield");
}

PRE(sys_sched_yield)
{
   *flags |= SfMayBlock;
   PRINT("sched_yield()");
}

#if 0
PRE(sys_sysinfo)
{
   PRINT("sys_sysinfo ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(long, "sysinfo", struct sysinfo *, info);
   PRE_MEM_WRITE( "sysinfo(info)", ARG1, sizeof(struct vki_sysinfo) );
}

POST(sys_sysinfo)
{
   POST_MEM_WRITE( ARG1, sizeof(struct vki_sysinfo) );
}
#endif

/* int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen); */
/*               ARG1        ARG2          ARG3         ARG4           ARG5        ARG6 */
PRE(sys___sysctl)
{
   PRINT("sys_sysctl ( %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,SARG2,ARG3,ARG4,ARG5,ARG6 );
   int* name = (int*)ARG1;
   PRINT("\nmib[0]: ");
   if (SARG2 >= 1)
   {
       switch (name[0])
       {
       case 0: // CTL_UNSPEC
           PRINT("unspec");
           break;
       case 1: // CTL_KERN
           PRINT("kern");
           break;
       case 2: // CTL_VM
           PRINT("vm");
           break;
       case 3: // CTL_VFS
           PRINT("vfs");
           break;
       case 4: // CTL_NET
           PRINT("net");
           break;
       case 5: // CTL_DEBUG
           PRINT("debug");
           break;
       case 6: // CTL_HW
           PRINT("hw");
           break;
       case 7: // CTL_MACHDEP
           PRINT("machdep");
           break;
       case 8: // CTL _USER
           PRINT("user");
           break;
       case 9: //CTL_P1003_1B
           PRINT("p1003_b1b");
           break;
       default:
           PRINT("unrecognized (%d)", ((int*)ARG1)[0]);
           break;
       }
   }
   if (SARG2 >= 2)
   {
       PRINT(" mib[1]: %d\n", name[1]);
   }

   PRE_REG_READ6(long, "__sysctl", int *, name, vki_u_int32_t, namelen, void *, oldp,
         vki_size_t *, oldlenp, void *, newp, vki_size_t, newlen);

#define ORIGINAL_CODE 0

#if defined(ORIGINAL_CODE) && ORIGINAL_CODE == 1
   PRE_MEM_READ("sysctl(name)", ARG1, ARG2 * sizeof(int));
   if (ARG5 != (UWord)NULL)
      PRE_MEM_READ("sysctl(new)", (Addr)ARG5, ARG6);
   if (ARG4 != (UWord)NULL) {
      if (ARG3 != (UWord)NULL) {
         PRE_MEM_READ("sysctl(oldlenp)", (Addr)ARG4, sizeof(vki_size_t));
         PRE_MEM_WRITE("sysctl(oldval)", (Addr)ARG3, *(vki_size_t *)ARG4);
      }
      PRE_MEM_WRITE("sysctl(oldlenp)", (Addr)ARG4, sizeof(vki_size_t));
   }
#else

   // read number of ints specified in ARG2 from mem pointed to by ARG1
   PRE_MEM_READ("sysctl(name)", (Addr)ARG1, ARG2 * sizeof(int));

   // if 'newp' is not NULL can read namelen bytes from that addess
   if (ARG5 != (UWord)NULL)
      PRE_MEM_READ("sysctl(newp)", (Addr)ARG5, ARG6);

   // there are two scenarios for oldlenp/oldp
   // 1. oldval is NULL and oldlenp is non-NULL
   //    this is a query of oldlenp so oldlenp will be written
   // 2. Both are non-NULL
   //    this is a query of oldp, oldlenp will be read and oldp will
   //    be written

   // is oldlenp is not NULL, can write
   if (ARG4 != (UWord)NULL) {
      if (ARG3 != (UWord)NULL) {
         // case 2 above
         PRE_MEM_READ("sysctl(oldlenp)", (Addr)ARG4, sizeof(vki_size_t));
         PRE_MEM_WRITE("sysctl(oldp)", (Addr)ARG3, *(vki_size_t *)ARG4);
      } else {
         // case 1 above
          PRE_MEM_WRITE("sysctl(oldlenp)", (Addr)ARG4, sizeof(vki_size_t));
      }

   }
#endif

#undef ORIGINAL_CODE
}

POST(sys___sysctl)
{
   if (ARG4 != (UWord)NULL) {
      if (ARG3 != (UWord)NULL) {
         //POST_MEM_WRITE((Addr)ARG4, sizeof(vki_size_t));
         POST_MEM_WRITE((Addr)ARG3, *(vki_size_t *)ARG4);
      }
      else
         POST_MEM_WRITE((Addr)ARG4, sizeof(vki_size_t));
   }
}


// int getdirentries(int fd, char *buf, int nbytes, long *basep);
#if (FREEBSD_VERS >= FREEBSD_12)
PRE(sys_freebsd11_getdirentries)
{
   *flags |= SfMayBlock;
   PRINT("sys_freebsd11_getdirentries ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG2,ARG3);
   PRE_REG_READ4(int, "getdirentries",
                 int, fd, char *, buf,
                 int, nbytes,
                 long *, basep);
   PRE_MEM_WRITE( "getdirentries(buf)", ARG2, ARG3 );
   if (ARG4)
      PRE_MEM_WRITE( "getdirentries(basep)", ARG4, sizeof(long) );
}

POST(sys_freebsd11_getdirentries)
{
   vg_assert(SUCCESS);
   if (RES > 0) {
      POST_MEM_WRITE( ARG2, RES );
      if ( ARG4 != 0 )
         POST_MEM_WRITE( ARG4, sizeof (long));
   }
}
#else
PRE(sys_getdirentries)
{
   *flags |= SfMayBlock;
   PRINT("sys_getdirentries ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG2,ARG3);
   PRE_REG_READ4(int, "getdirentries",
                 int, fd, char *, buf,
                 int, nbytes,
                 long *, basep);
   PRE_MEM_WRITE( "getdirentries(buf)", ARG2, ARG3 );
   if (ARG4)
      PRE_MEM_WRITE( "getdirentries(basep)", ARG4, sizeof(long) );
}

POST(sys_getdirentries)
{
   vg_assert(SUCCESS);
   if (RES > 0) {
      POST_MEM_WRITE( ARG2, RES );
      if ( ARG4 != 0 )
         POST_MEM_WRITE( ARG4, sizeof (long));
   }
}
#endif


PRE(sys_seteuid)
{
   PRINT("sys_seteuid ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(long, "seteuid", vki_uid_t, uid);
}

PRE(sys_setegid)
{
   PRINT("sys_setegid ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(long, "setegid", vki_gid_t, gid);
}

PRE(sys_lutimes)
{
   PRINT("sys_lutimes ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "lutimes", char *, filename, struct timeval *, tvp);
   PRE_MEM_RASCIIZ( "lutimes(filename)", ARG1 );
   if (ARG2 != 0)
      PRE_MEM_READ( "lutimes(tvp)", ARG2, sizeof(struct vki_timeval) );
}

PRE(sys_futimes)
{
   PRINT("sys_lutimes ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2);
   PRE_REG_READ2(long, "futimes", int, fd, struct timeval *, tvp);
   if (ARG2 != 0)
      PRE_MEM_READ( "futimes(tvp)", ARG2, sizeof(struct vki_timeval) );
}

PRE(sys_utrace)
{
   PRINT("sys_utrace ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1, ARG2);
   PRE_REG_READ2(long, "utrace", const void *, buf, vki_size_t, len);
   PRE_MEM_READ( "utrace(buf,len)", ARG2, ARG3 );
}

// int swapon(const char *special);
PRE(sys_swapon)
{
   PRINT("sys_swapon ( %#" FMT_REGWORD "x(%s) )", ARG1,(char*)ARG1);
   PRE_REG_READ1(int, "swapon", const char*, special );
   PRE_MEM_RASCIIZ( "swapon(special)", ARG1 );
}

PRE(sys_getdtablesize)
{
   PRINT("%s", "sys_getdtablesize ( )");
   PRE_REG_READ0(long, "getdtablesize");
}

PRE(sys_kqueue)
{
   PRINT("%s", "sys_kqueue ()");
}

POST(sys_kqueue)
{
   if (!ML_(fd_allowed)(RES, "kqueue", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds)) {
         ML_(record_fd_open_nameless)(tid, RES);
      }
   }
}

PRE(sys_kevent)
{
   /* struct kevent {
        uintptr_t ident;  -- identifier for this event
        short     filter; -- filter for event
        u_short   flags;  -- action flags for kqueue
        u_int     fflags; -- filter flag value
        intptr_t  data;   -- filter data value
        void      *udata; -- opaque user data identifier
      };
      int kevent(int kq, const struct kevent *changelist, int nchanges,
                 struct kevent *eventlist, int nevents,
                 const struct timespec *timeout);
   */
   *flags |= SfMayBlock;
   PRINT("sys_kevent ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )\n", ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   PRE_REG_READ6(long, "kevent",
                 int, fd, struct vki_kevent *, newev, int, num_newev,
                 struct vki_kevent *, ret_ev, int, num_retev,
                 struct timespec *, timeout);
   if (ARG2 != 0 && ARG3 != 0)
      PRE_MEM_READ( "kevent(changeevent)", ARG2, sizeof(struct vki_kevent)*ARG3 );
   if (ARG4 != 0 && ARG5 != 0)
      PRE_MEM_WRITE( "kevent(events)", ARG4, sizeof(struct vki_kevent)*ARG5);
   if (ARG6 != 0)
      PRE_MEM_READ( "kevent(timeout)",
                    ARG6, sizeof(struct vki_timespec));
}

POST(sys_kevent)
{
   vg_assert(SUCCESS);
   if ((Word)RES != -1) {
      if (ARG4 != 0)
         POST_MEM_WRITE( ARG4, sizeof(struct vki_kevent)*RES) ;
   }
}

PRE(sys___getcwd)
{
   PRINT("sys___getcwd ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG2);
   PRE_REG_READ2(long, "__getcwd", char *, buf, unsigned int, size);
   PRE_MEM_WRITE( "__getcwd(buf)", ARG1, ARG2 );
}

POST(sys___getcwd)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      // QQQ it is unclear if this is legal or not, but the
      // QQQ kernel just wrote it there...
      // QQQ Why oh why didn't phk return the length from __getcwd()?
      UInt len = VG_(strlen) ( (char *)ARG1 ) + 1;
      POST_MEM_WRITE( ARG1, len );
   }
}

#if (FREEBSD_VERS >= FREEBSD_12)

PRE(sys_freebsd11_getfsstat)
{
   PRINT("sys_freebsd11_getfsstat ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getfsstat", struct vki_freebsd11_statfs *, buf, long, len, int, flags);
   PRE_MEM_WRITE( "getfsstat(buf)", ARG1, ARG2 );
}

POST(sys_freebsd11_getfsstat)
{
   vg_assert(SUCCESS);
   if ((Word)RES != -1) {
      POST_MEM_WRITE( ARG1, RES * sizeof(struct vki_freebsd11_statfs) );
   }
}

PRE(sys_freebsd11_statfs)
{
   PRINT("sys_statfs ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "statfs", const char *, path, struct statfs *, buf);
   PRE_MEM_RASCIIZ( "statfs(path)", ARG1 );
   PRE_MEM_WRITE( "statfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_freebsd11_statfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}

PRE(sys_freebsd11_fstatfs)
{
   PRINT("sys_fstatfs ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fstatfs",
                 unsigned int, fd, struct statfs *, buf);
   PRE_MEM_WRITE( "fstatfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_freebsd11_fstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}

PRE(sys_freebsd11_fhstatfs)
{
   PRINT("sys_fhstatfs ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fhstatfs",
                 struct fhandle *, fhp, struct statfs *, buf);
   PRE_MEM_READ( "fhstatfs(fhp)", ARG1, sizeof(struct vki_fhandle) );
   PRE_MEM_WRITE( "fhstatfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_freebsd11_fhstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}


#else

PRE(sys_getfsstat)
{
   PRINT("sys_getfsstat ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getfsstat", struct vki_freebsd11_statfs *, buf, long, len, int, flags);
   PRE_MEM_WRITE( "getfsstat(buf)", ARG1, ARG2 );
}

POST(sys_getfsstat)
{
   vg_assert(SUCCESS);
   if ((Word)RES != -1) {
      POST_MEM_WRITE( ARG1, RES * sizeof(struct vki_freebsd11_statfs) );
   }
}

PRE(sys_statfs)
{
   PRINT("sys_statfs ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "statfs", const char *, path, struct statfs *, buf);
   PRE_MEM_RASCIIZ( "statfs(path)", ARG1 );
   PRE_MEM_WRITE( "statfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_statfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}

PRE(sys_fstatfs)
{
   PRINT("sys_fstatfs ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fstatfs",
                 unsigned int, fd, struct statfs *, buf);
   PRE_MEM_WRITE( "fstatfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_fstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}

PRE(sys_fhstatfs)
{
   PRINT("sys_fhstatfs ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fhstatfs",
                 struct fhandle *, fhp, struct statfs *, buf);
   PRE_MEM_READ( "fhstatfs(fhp)", ARG1, sizeof(struct vki_fhandle) );
   PRE_MEM_WRITE( "fhstatfs(buf)", ARG2, sizeof(struct vki_freebsd11_statfs) );
}

POST(sys_fhstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_freebsd11_statfs) );
}


#endif



PRE(sys_fhopen)
{
   PRINT("sys_open ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2);
   PRE_REG_READ2(long, "open",
                 struct fhandle *, fhp, int, flags);
   PRE_MEM_READ( "fhopen(fhp)", ARG1, sizeof(struct vki_fhandle) );

   /* Otherwise handle normally */
   *flags |= SfMayBlock;
}

POST(sys_fhopen)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "fhopen", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_nameless)(tid, RES);
   }
}

PRE(sys_fhstat)
{
   PRINT("sys_fhstat ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fhstat", struct fhandle *, fhp, struct stat *, buf);
   PRE_MEM_READ( "fhstat(fhp)", ARG1, sizeof(struct vki_fhandle) );
   PRE_MEM_WRITE( "fhstat(buf)", ARG2, sizeof(struct vki_stat) );
}

POST(sys_fhstat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat) );
}


/* ---------------------------------------------------------------------
   kld* wrappers
   ------------------------------------------------------------------ */

PRE(sys_kldload)
{
   PRINT("sys_kldload ( %#" FMT_REGWORD "x(%s) )", ARG1, (char *)ARG1);
   PRE_REG_READ1(int, "kldload", const char *, "file");

   PRE_MEM_RASCIIZ( "kldload(file)", ARG1 );
}

PRE(sys_kldunload)
{
   PRINT("sys_kldunload ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(int, "kldunload", int, "fileid");
}

PRE(sys_kldfind)
{
   PRINT("sys_kldfind ( %#" FMT_REGWORD "x(%s) )", ARG1, (char *)ARG1);
   PRE_REG_READ1(int, "kldfind", const char *, "file");

   PRE_MEM_RASCIIZ( "kldfind(file)", ARG1 );
}

PRE(sys_kldnext)
{
   PRINT("sys_kldnext ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(int, "kldnext", int, "fileid");
}

PRE(sys_kldsym)
{
   PRINT("sys_kldsym ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3 );
   PRE_REG_READ3(int, "kldsym", int, "fileid", int, "command", void*, "data");
   PRE_MEM_READ( "kldsym(data)", ARG3, sizeof(struct vki_kld_sym_lookup) );
   struct vki_kld_sym_lookup *kslp = (struct vki_kld_sym_lookup *)ARG3;
   PRE_MEM_RASCIIZ( "kldsym(data.symname)", (Addr)kslp->symname );
}

POST(sys_kldsym)
{
   struct vki_kld_sym_lookup *kslp = (struct vki_kld_sym_lookup *)ARG3;
   POST_MEM_WRITE( (Addr)&kslp->symvalue, sizeof(kslp->symvalue) );
   POST_MEM_WRITE( (Addr)&kslp->symsize, sizeof(kslp->symsize) );
}

#if 0
/* ---------------------------------------------------------------------
   aio_* wrappers
   ------------------------------------------------------------------ */

// Nb: this wrapper has to pad/unpad memory around the syscall itself,
// and this allows us to control exactly the code that gets run while
// the padding is in place.

PRE(sys_io_setup)
{
   PRINT("sys_io_setup ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2);
   PRE_REG_READ2(long, "io_setup",
                 unsigned, nr_events, vki_aio_context_t *, ctxp);
   PRE_MEM_WRITE( "io_setup(ctxp)", ARG2, sizeof(vki_aio_context_t) );
}

POST(sys_io_setup)
{
   SizeT size;
   struct vki_aio_ring *r;
           
   size = VG_PGROUNDUP(sizeof(struct vki_aio_ring) +
                       ARG1*sizeof(struct vki_io_event));
   r = *(struct vki_aio_ring **)ARG2;
   vg_assert(ML_(valid_client_addr)((Addr)r, size, tid, "io_setup"));

   ML_(notify_aspacem_and_tool_of_mmap)( (Addr)r, size,
                                         VKI_PROT_READ | VKI_PROT_WRITE,
                                         VKI_MAP_ANONYMOUS, -1, 0 );

   POST_MEM_WRITE( ARG2, sizeof(vki_aio_context_t) );
}

// Nb: This wrapper is "Special" because we need 'size' to do the unmap
// after the syscall.  We must get 'size' from the aio_ring structure,
// before the syscall, while the aio_ring structure still exists.  (And we
// know that we must look at the aio_ring structure because Tom inspected the
// kernel and glibc sources to see what they do, yuk.)
//
// XXX This segment can be implicitly unmapped when aio
// file-descriptors are closed...
PRE(sys_io_destroy)
{
   struct vki_aio_ring *r;
   SizeT size;
      
   PRINT("sys_io_destroy ( %llu )", (ULong)ARG1);
   PRE_REG_READ1(long, "io_destroy", vki_aio_context_t, ctx);

   // If we are going to seg fault (due to a bogus ARG1) do it as late as
   // possible...
   r = (struct vki_aio_ring *)ARG1;
   size = VG_PGROUNDUP(sizeof(struct vki_aio_ring) + 
                       r->nr*sizeof(struct vki_io_event));

   SET_STATUS_from_SysRes( VG_(do_syscall1)(SYSNO, ARG1) );

   if (SUCCESS && RES == 0) { 
      Bool d = VG_(am_notify_munmap)( ARG1, size );
      VG_TRACK( die_mem_munmap, ARG1, size );
      if (d)
         VG_(discard_translations)( (Addr64)ARG1, (ULong)size, 
                                    "PRE(sys_io_destroy)" );
   }  
}  

PRE(sys_io_getevents)
{
   *flags |= SfMayBlock;
   PRINT("sys_io_getevents ( %llu, %lld, %lld, %#lx, %#lx )",
         (ULong)ARG1,(Long)ARG2,(Long)ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "io_getevents",
                 vki_aio_context_t, ctx_id, long, min_nr, long, nr,
                 struct io_event *, events,
                 struct timespec *, timeout);
   if (ARG3 > 0)
      PRE_MEM_WRITE( "io_getevents(events)",
                     ARG4, sizeof(struct vki_io_event)*ARG3 );
   if (ARG5 != 0)
      PRE_MEM_READ( "io_getevents(timeout)",
                    ARG5, sizeof(struct vki_timespec));
}
POST(sys_io_getevents)
{
   Int i;
   vg_assert(SUCCESS);
   if (RES > 0) {
      POST_MEM_WRITE( ARG4, sizeof(struct vki_io_event)*RES );
      for (i = 0; i < RES; i++) {
         const struct vki_io_event *vev = ((struct vki_io_event *)ARG4) + i;
         const struct vki_iocb *cb = (struct vki_iocb *)(Addr)vev->obj;

         switch (cb->aio_lio_opcode) {
         case VKI_IOCB_CMD_PREAD:
            if (vev->result > 0)
               POST_MEM_WRITE( cb->aio_buf, vev->result );
            break;
            
         case VKI_IOCB_CMD_PWRITE:
            break;
           
         default:
            VG_(message)(Vg_DebugMsg,
                        "Warning: unhandled io_getevents opcode: %u\n",
                        cb->aio_lio_opcode);
            break;
         }
      }
   }
}

PRE(sys_io_submit)
{
   Int i;

   PRINT("sys_io_submit ( %llu, %ld, %#lx )", (ULong)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "io_submit",
                 vki_aio_context_t, ctx_id, long, nr,
                 struct iocb **, iocbpp);
   PRE_MEM_READ( "io_submit(iocbpp)", ARG3, ARG2*sizeof(struct vki_iocb *) );
   if (ARG3 != 0) {
      for (i = 0; i < ARG2; i++) {
         struct vki_iocb *cb = ((struct vki_iocb **)ARG3)[i];
         PRE_MEM_READ( "io_submit(iocb)", (Addr)cb, sizeof(struct vki_iocb) );
         switch (cb->aio_lio_opcode) {
         case VKI_IOCB_CMD_PREAD:
            PRE_MEM_WRITE( "io_submit(PREAD)", cb->aio_buf, cb->aio_nbytes );
            break;

         case VKI_IOCB_CMD_PWRITE:
            PRE_MEM_READ( "io_submit(PWRITE)", cb->aio_buf, cb->aio_nbytes );
            break;
           
         default:
            VG_(message)(Vg_DebugMsg,"Warning: unhandled io_submit opcode: %u\n",
                         cb->aio_lio_opcode);
            break;
         }
      }
   }
}

PRE(sys_io_cancel)
{
   PRINT("sys_io_cancel ( %llu, %#lx, %#lx )", (ULong)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "io_cancel",
                 vki_aio_context_t, ctx_id, struct iocb *, iocb,
                 struct io_event *, result);
   PRE_MEM_READ( "io_cancel(iocb)", ARG2, sizeof(struct vki_iocb) );
   PRE_MEM_WRITE( "io_cancel(result)", ARG3, sizeof(struct vki_io_event) );
}
POST(sys_io_cancel)
{
   POST_MEM_WRITE( ARG3, sizeof(struct vki_io_event) );
}

/* ---------------------------------------------------------------------
   inotify_* wrappers
   ------------------------------------------------------------------ */

PRE(sys_inotify_init)
{
   PRINT("sys_inotify_init ( )");
   PRE_REG_READ0(long, "inotify_init");
}
POST(sys_inotify_init)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "inotify_init", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_nameless) (tid, RES);
   }
}

PRE(sys_inotify_add_watch)
{
   PRINT( "sys_inotify_add_watch ( %ld, %#lx, %lx )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "inotify_add_watch", int, fd, char *, path, int, mask);
   PRE_MEM_RASCIIZ( "inotify_add_watch(path)", ARG2 );
}

PRE(sys_inotify_rm_watch)
{
   PRINT( "sys_inotify_rm_watch ( %ld, %lx )", ARG1,ARG2);
   PRE_REG_READ2(long, "inotify_rm_watch", int, fd, int, wd);
}

#endif

/* ---------------------------------------------------------------------
   mq_* wrappers
   ------------------------------------------------------------------ */

PRE(sys_kmq_open)
{
   PRINT("sys_kmq_open( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %llu, %#" FMT_REGWORD "x )",
         ARG1,(char *)ARG1,ARG2,(ULong)ARG3,ARG4);
   PRE_REG_READ4(long, "mq_open",
                 const char *, name, int, oflag, vki_mode_t, mode,
                 struct mq_attr *, attr);
   PRE_MEM_RASCIIZ( "mq_open(name)", ARG1 );
   if ((ARG2 & VKI_O_CREAT) != 0 && ARG4 != 0) {
      const struct vki_mq_attr *attr = (struct vki_mq_attr *)ARG4;
      PRE_MEM_READ( "mq_open(attr->mq_maxmsg)",
                     (Addr)&attr->mq_maxmsg, sizeof(attr->mq_maxmsg) );
      PRE_MEM_READ( "mq_open(attr->mq_msgsize)",
                     (Addr)&attr->mq_msgsize, sizeof(attr->mq_msgsize) );
   }
}

POST(sys_kmq_open)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "mq_open", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_with_given_name)(tid, RES, (const HChar*)ARG1);
   }
}

PRE(sys_kmq_setattr)
{
   PRINT("sys_kmq_getattr( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3 );
   PRE_REG_READ3(long, "mq_getsetattr",
                 vki_mqd_t, mqdes, const struct mq_attr *, mqstat,
                 struct mq_attr *, omqstat);
   if (!ML_(fd_allowed)(ARG1, "mq_getattr", tid, False)) {
      SET_STATUS_Failure( VKI_EBADF );
   } else {
      if (ARG2 != 0) {
         const struct vki_mq_attr *attr = (struct vki_mq_attr *)ARG2;
         PRE_MEM_READ( "mq_getattr(mqstat->mq_flags)",
                        (Addr)&attr->mq_flags, sizeof(attr->mq_flags) );
      }
      if (ARG3 != 0)
         PRE_MEM_WRITE( "mq_getattr(omqstat)", ARG3,
                        sizeof(struct vki_mq_attr) );
   }
}

PRE(sys_kmq_timedreceive)
{
   *flags |= SfMayBlock;
   PRINT("sys_kmq_timedreceive( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %llu, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         ARG1,ARG2,(ULong)ARG3,ARG4,ARG5);
   PRE_REG_READ5(ssize_t, "mq_timedreceive",
                 vki_mqd_t, mqdes, char *, msg_ptr, vki_size_t, msg_len,
                 unsigned int *, msg_prio,
                 const struct timespec *, abs_timeout);
   if (!ML_(fd_allowed)(ARG1, "mq_timedreceive", tid, False)) {
      SET_STATUS_Failure( VKI_EBADF );
   } else {
      PRE_MEM_WRITE( "mq_timedreceive(msg_ptr)", ARG2, ARG3 );
      if (ARG4 != 0)
         PRE_MEM_WRITE( "mq_timedreceive(msg_prio)",
                        ARG4, sizeof(unsigned int) );
      if (ARG5 != 0)
         PRE_MEM_READ( "mq_timedreceive(abs_timeout)",
                        ARG5, sizeof(struct vki_timespec) );
   }
}

POST(sys_kmq_timedreceive)
{
   POST_MEM_WRITE( ARG2, ARG3 );
   if (ARG4 != 0)
      POST_MEM_WRITE( ARG4, sizeof(unsigned int) );
}

PRE(sys_kmq_timedsend)
{
   *flags |= SfMayBlock;
   PRINT("sys_kmq_timedsend ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %llu, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",
         ARG1,ARG2,(ULong)ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "mq_timedsend",
                 vki_mqd_t, mqdes, const char *, msg_ptr, vki_size_t, msg_len,
                 unsigned int, msg_prio, const struct timespec *, abs_timeout);
   if (!ML_(fd_allowed)(ARG1, "mq_timedsend", tid, False)) {
      SET_STATUS_Failure( VKI_EBADF );
   } else {
      PRE_MEM_READ( "mq_timedsend(msg_ptr)", ARG2, ARG3 );
      if (ARG5 != 0)
         PRE_MEM_READ( "mq_timedsend(abs_timeout)", ARG5,
                        sizeof(struct vki_timespec) );
   }
}

PRE(sys_kmq_notify)
{
   PRINT("sys_kmq_notify( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2 );
   PRE_REG_READ2(long, "mq_notify",
                 vki_mqd_t, mqdes, const struct sigevent *, notification);
   if (!ML_(fd_allowed)(ARG1, "mq_notify", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else if (ARG2 != 0)
      PRE_MEM_READ( "mq_notify(notification)",
                    ARG2, sizeof(struct vki_sigevent) );
}

PRE(sys_mq_unlink)
{
   PRINT("sys_mq_unlink ( %#" FMT_REGWORD "x(%s) )", ARG1,(char *)ARG1);
   PRE_REG_READ1(long, "mq_unlink", const char *, name);
   PRE_MEM_RASCIIZ( "mq_unlink(name)", ARG1 );
}


/* ---------------------------------------------------------------------
   clock_* wrappers
   ------------------------------------------------------------------ */

PRE(sys_clock_settime)
{
   PRINT("sys_clock_settime( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2);
   PRE_REG_READ2(long, "clock_settime", 
                 vki_clockid_t, clk_id, const struct timespec *, tp);
   PRE_MEM_READ( "clock_settime(tp)", ARG2, sizeof(struct vki_timespec) );
}

PRE(sys_clock_gettime)
{
   PRINT("sys_clock_gettime( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )" , ARG1,ARG2);
   PRE_REG_READ2(long, "clock_gettime", 
                 vki_clockid_t, clk_id, struct timespec *, tp);
   PRE_MEM_WRITE( "clock_gettime(tp)", ARG2, sizeof(struct vki_timespec) );
}

POST(sys_clock_gettime)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_timespec) );
}

PRE(sys_clock_getres)
{
   PRINT("sys_clock_getres( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )" , ARG1,ARG2);
   // Nb: we can't use "RES" as the param name because that's a macro
   // defined above!
   PRE_REG_READ2(long, "clock_getres", 
                 vki_clockid_t, clk_id, struct timespec *, res);
   if (ARG2 != 0)
      PRE_MEM_WRITE( "clock_getres(res)", ARG2, sizeof(struct vki_timespec) );
}

POST(sys_clock_getres)
{
   if (ARG2 != 0)
      POST_MEM_WRITE( ARG2, sizeof(struct vki_timespec) );
}

PRE(sys_minherit)
{
   PRINT("sys_minherit( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )" , ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "minherit",
                 void *, addr, vki_size_t, len, int, inherit);
   if (ARG2 != 0)
      PRE_MEM_WRITE( "minherit(addr)", ARG1,ARG2 );
}

POST(sys_minherit)
{
    if (ARG2 != 0)
       POST_MEM_WRITE( ARG1, ARG2 );
}

#if 0
PRE(sys_clock_nanosleep)
{
   *flags |= SfMayBlock|SfPostOnFail;
   PRINT("sys_clock_nanosleep( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(int32_t, "clock_nanosleep",
                 vki_clockid_t, clkid, int, flags,
                 const struct timespec *, rqtp, struct timespec *, rmtp);
   PRE_MEM_READ( "clock_nanosleep(rqtp)", ARG3, sizeof(struct vki_timespec) );
   if (ARG4 != 0)
      PRE_MEM_WRITE( "clock_nanosleep(rmtp)", ARG4, sizeof(struct vki_timespec) );
}

POST(sys_clock_nanosleep)
{
   if (ARG4 != 0 && FAILURE && RES_unchecked == VKI_EINTR)
      POST_MEM_WRITE( ARG4, sizeof(struct vki_timespec) );
}

/* ---------------------------------------------------------------------
   timer_* wrappers
   ------------------------------------------------------------------ */

PRE(sys_timer_create)
{
   PRINT("sys_timer_create( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "timer_create",
                 vki_clockid_t, clockid, struct sigevent *, evp,
                 vki_timer_t *, timerid);
   if (ARG2 != 0)
      PRE_MEM_READ( "timer_create(evp)", ARG2, sizeof(struct vki_sigevent) );
   PRE_MEM_WRITE( "timer_create(timerid)", ARG3, sizeof(vki_timer_t) );
}
POST(sys_timer_create)
{
   POST_MEM_WRITE( ARG3, sizeof(vki_timer_t) );
}

PRE(sys_timer_settime)
{
   PRINT("sys_timer_settime( %lld, %l" FMT_REGWORD ", %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", (ULong)ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "timer_settime", 
                 vki_timer_t, timerid, int, flags,
                 const struct itimerspec *, value,
                 struct itimerspec *, ovalue);
   PRE_MEM_READ( "timer_settime(value)", ARG3,
                  sizeof(struct vki_itimerspec) );
   if (ARG4 != 0)
       PRE_MEM_WRITE( "timer_settime(ovalue)", ARG4,
                      sizeof(struct vki_itimerspec) );
}

POST(sys_timer_settime)
{
   if (ARG4 != 0)
      POST_MEM_WRITE( ARG4, sizeof(struct vki_itimerspec) );
}

PRE(sys_timer_gettime)
{
   PRINT("sys_timer_gettime( %lld, %#" FMT_REGWORD "x )", (ULong)ARG1,ARG2);
   PRE_REG_READ2(long, "timer_gettime", 
                 vki_timer_t, timerid, struct itimerspec *, value);
   PRE_MEM_WRITE( "timer_gettime(value)", ARG2,
                  sizeof(struct vki_itimerspec));
}

POST(sys_timer_gettime)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_itimerspec) );
}

PRE(sys_timer_getoverrun)
{
   PRINT("sys_timer_getoverrun( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "timer_getoverrun", vki_timer_t, timerid);
}

PRE(sys_timer_delete)
{
   PRINT("sys_timer_delete( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "timer_delete", vki_timer_t, timerid);
}

/* ---------------------------------------------------------------------
   sched_* wrappers
   ------------------------------------------------------------------ */

PRE(sys_sched_setparam)
{
   PRINT("sched_setparam ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1, ARG2 );
   PRE_REG_READ2(long, "sched_setparam", 
                 vki_pid_t, pid, struct sched_param *, p);
   PRE_MEM_READ( "sched_setparam(p)", ARG2, sizeof(struct vki_sched_param) );
}

POST(sys_sched_setparam)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_sched_param) );
}

PRE(sys_sched_getparam)
{
   PRINT("sched_getparam ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1, ARG2 );
   PRE_REG_READ2(long, "sched_getparam", 
                 vki_pid_t, pid, struct sched_param *, p);
   PRE_MEM_WRITE( "sched_getparam(p)", ARG2, sizeof(struct vki_sched_param) );
}

POST(sys_sched_getparam)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_sched_param) );
}

PRE(sys_sched_getscheduler)
{
   PRINT("sys_sched_getscheduler ( %" FMT_REGWORD "d )", ARG1);
   PRE_REG_READ1(long, "sched_getscheduler", vki_pid_t, pid);
}

PRE(sys_sched_setscheduler)
{
   PRINT("sys_sched_setscheduler ( %ld, %ld, %#lx )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sched_setscheduler", 
                 vki_pid_t, pid, int, policy, struct sched_param *, p);
   if (ARG3 != 0)
      PRE_MEM_READ("sched_setscheduler(p)",
                   ARG3, sizeof(struct vki_sched_param));
}

PRE(sys_sched_yield)
{
   *flags |= SfMayBlock;
   PRINT("sched_yield()");
   PRE_REG_READ0(long, "sched_yield");
}
#endif

PRE(sys_sched_get_priority_max)
{
   PRINT("sched_get_priority_max ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(long, "sched_get_priority_max", int, policy);
}

PRE(sys_sched_get_priority_min)
{
   PRINT("sched_get_priority_min ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(long, "sched_get_priority_min", int, policy);
}

#if 0
PRE(sys_sched_setaffinity)
{
   PRINT("sched_setaffinity ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "sched_setaffinity", 
                 vki_pid_t, pid, unsigned int, len, unsigned long *, mask);
   PRE_MEM_READ( "sched_setaffinity(mask)", ARG3, ARG2);
}

PRE(sys_sched_getaffinity)
{
   PRINT("sched_getaffinity ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "sched_getaffinity", 
                 vki_pid_t, pid, unsigned int, len, unsigned long *, mask);
   PRE_MEM_WRITE( "sched_getaffinity(mask)", ARG3, ARG2);
}

POST(sys_sched_getaffinity)
{
   POST_MEM_WRITE(ARG3, ARG2);
}

#endif

/* ---------------------------------------------------------------------
   miscellaneous wrappers
   ------------------------------------------------------------------ */

PRE(sys_munlockall)
{
   *flags |= SfMayBlock;
   PRINT("%s", "sys_munlockall ( )");
   PRE_REG_READ0(long, "munlockall");
}

// Pipe on freebsd doesn't have args, and uses dual returns!
PRE(sys_pipe)
{
   PRINT("%s", "sys_pipe ()");
}

POST(sys_pipe)
{
   if (!ML_(fd_allowed)(RES, "pipe", tid, True) ||
       !ML_(fd_allowed)(RESHI, "pipe", tid, True)) {
      VG_(close)(RES);
      VG_(close)(RESHI);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds)) {
         ML_(record_fd_open_nameless)(tid, RES);
         ML_(record_fd_open_nameless)(tid, RESHI);
      }
   }
}

PRE(sys_pipe2)
{
   PRINT("sys_pipe2 ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1, ARG2);
   PRE_REG_READ2(long, "pipe2",
                 int *, fildes, int, flags);
   PRE_MEM_WRITE("pipe2(fildes)", ARG1, 2 * sizeof(int));

}

POST(sys_pipe2)
{
   int *fildes;

   if (RES != 0)
      return;

   POST_MEM_WRITE(ARG1, 2 * sizeof(int));
   fildes = (int *)ARG1;

   if (!ML_(fd_allowed)(fildes[0], "pipe2", tid, True) ||
       !ML_(fd_allowed)(fildes[1], "pipe2", tid, True)) {
      VG_(close)(fildes[0]);
      VG_(close)(fildes[1]);
      SET_STATUS_Failure( VKI_EMFILE );
   } else if (VG_(clo_track_fds)) {
      ML_(record_fd_open_nameless)(tid, fildes[0]);
      ML_(record_fd_open_nameless)(tid, fildes[1]);
   }
}

// int ppoll(struct pollfd fds[], nfds_t nfds,
//           const struct timespec * restrict timeout,
//           const sigset_t * restrict newsigmask);
PRE(sys_ppoll)
{
   PRINT("sys_ppoll ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD
         "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )\n",
         ARG1, ARG2, ARG3, ARG4, ARG5);
   UInt i;
   struct vki_pollfd* fds = (struct vki_pollfd *)(Addr)ARG1;
   *flags |= SfMayBlock | SfPostOnFail;
   PRINT("sys_ppoll ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD
         "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )\n",
         ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(long, "ppoll",
                 struct vki_pollfd *, fds, unsigned int, nfds,
                 struct vki_timespec *, timeout, vki_sigset_t *, newsigmask,
                 vki_size_t, sigsetsize);

   for (i = 0; i < ARG2; i++) {
      PRE_MEM_READ( "ppoll(fds.fd)",
                    (Addr)(&fds[i].fd), sizeof(fds[i].fd) );
      PRE_MEM_READ( "ppoll(fds.events)",
                    (Addr)(&fds[i].events), sizeof(fds[i].events) );
      PRE_MEM_WRITE( "ppoll(fds.revents)",
                     (Addr)(&fds[i].revents), sizeof(fds[i].revents) );
   }

   if (ARG3) {
         PRE_MEM_READ( "ppoll(tsp)", ARG3,
                       sizeof(struct vki_timespec) );
   }
   if (ARG4 != 0 && sizeof(vki_sigset_t) == ARG5) {
      const vki_sigset_t *guest_sigmask = (vki_sigset_t *)(Addr)ARG4;
      PRE_MEM_READ( "ppoll(sigmask)", ARG4, ARG5);
      if (!ML_(safe_to_deref)(guest_sigmask, sizeof(*guest_sigmask))) {
         ARG4 = 1; /* Something recognisable to POST() hook. */
      } else {
         vki_sigset_t *vg_sigmask =
             VG_(malloc)("syswrap.ppoll.1", sizeof(*vg_sigmask));
         ARG4 = (Addr)vg_sigmask;
         *vg_sigmask = *guest_sigmask;
         VG_(sanitize_client_sigmask)(vg_sigmask);
      }
   }
}

POST(sys_ppoll)
{
    if (SUCCESS && ((Word)RES != -1)) {
       UInt i;
       struct vki_pollfd* ufds = (struct vki_pollfd *)(Addr)ARG1;
       for (i = 0; i < ARG2; i++)
      POST_MEM_WRITE( (Addr)(&ufds[i].revents), sizeof(ufds[i].revents) );
    }
    if (ARG4 != 0 && ARG5 == sizeof(vki_sigset_t) && ARG4 != 1) {
       VG_(free)((vki_sigset_t *) (Addr)ARG4);
    }
}


PRE(sys_accept4)
{
   *flags |= SfMayBlock;
   PRINT("sys_accept4 ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u)",ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "accept4",
                 int, s, struct sockaddr *, addr, int, *addrlen, int, flags);
   ML_(generic_PRE_sys_accept)(tid, ARG1,ARG2,ARG3);
}

POST(sys_accept4)
{
    SysRes r;
   vg_assert(SUCCESS);
   r = ML_(generic_POST_sys_accept)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3);
   SET_STATUS_from_SysRes(r);
}

#if 0
PRE(sys_quotactl)
{
   PRINT("sys_quotactl (0x%" FMT_REGWORD "x, %#" FMT_REGWORD "x, 0x%" FMT_REGWORD "x, 0x%" FMT_REGWORD "x )", ARG1,ARG2,ARG3, ARG4);
   PRE_REG_READ4(long, "quotactl",
                 unsigned int, cmd, const char *, special, vki_qid_t, id,
                 void *, addr);
   PRE_MEM_RASCIIZ( "quotactl(special)", ARG2 );
}

PRE(sys_waitid)
{
   *flags |= SfMayBlock;
   PRINT("sys_waitid( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(int32_t, "sys_waitid",
                 int, which, vki_pid_t, pid, struct vki_siginfo *, infop,
                 int, options, struct vki_rusage *, ru);
   PRE_MEM_WRITE( "waitid(infop)", ARG3, sizeof(struct vki_siginfo) );
   if (ARG5 != 0)
      PRE_MEM_WRITE( "waitid(ru)", ARG5, sizeof(struct vki_rusage) );
}

POST(sys_waitid)
{
   POST_MEM_WRITE( ARG3, sizeof(struct vki_siginfo) );
   if (ARG5 != 0)
      POST_MEM_WRITE( ARG5, sizeof(struct vki_rusage) );
}

/* ---------------------------------------------------------------------
   utime wrapper
   ------------------------------------------------------------------ */

PRE(sys_utime)
{
   *flags |= SfMayBlock;
   PRINT("sys_utime ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1,ARG2);
   PRE_REG_READ2(long, "utime", char *, filename, struct utimbuf *, buf);
   PRE_MEM_RASCIIZ( "utime(filename)", ARG1 );
   if (ARG2 != 0)
      PRE_MEM_READ( "utime(buf)", ARG2, sizeof(struct vki_utimbuf) );
}

#endif

/* ---------------------------------------------------------------------
   thr* wrappers
   ------------------------------------------------------------------ */

PRE(sys_thr_self)
{
   PRINT( "sys_thr_self ( %#" FMT_REGWORD "x )", ARG1 );
   PRE_REG_READ1(long, "thr_self", long *, "id");
   PRE_MEM_WRITE( "thr_self()", ARG1, sizeof(long));
}
POST(sys_thr_self)
{
   POST_MEM_WRITE( ARG1, sizeof(long));
}

PRE(sys_thr_exit)
{
   ThreadState *tst;

   PRINT( "sys_thr_exit ( %#" FMT_REGWORD "x )", ARG1 );
   PRE_REG_READ1(long, "thr_exit", long *, "status");

   if (ARG1)
      PRE_MEM_WRITE( "thr_exit(status)", ARG1, sizeof(long) );
   tst = VG_(get_ThreadState)(tid);
   tst->exitreason = VgSrc_ExitThread;
   tst->os_state.exitcode = ARG1;
   SET_STATUS_Success(0);
}

PRE(sys_thr_set_name)
{
   PRINT( "sys_thr_set_name ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1, ARG2 );
   PRE_REG_READ2(long, "thr_set_name", long, "id", const char *, "name");
   PRE_MEM_RASCIIZ( "sys_thr_set_name(threadname)", ARG2);
}

PRE(sys_thr_kill)
{
   PRINT("sys_thr_kill ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2);
   PRE_REG_READ2(long, "thr_kill", long, id, int, sig);
   if (!ML_(client_signal_OK)(ARG2)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   /* Check to see if this kill gave us a pending signal */
   *flags |= SfPollAfter;

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "thr_kill: sending signal %lu to tid %lu\n",
                   ARG2, ARG1);

   /* If we're sending SIGKILL, check to see if the target is one of
      our threads and handle it specially. */
   if (ARG2 == VKI_SIGKILL && ML_(do_sigkill)(ARG1, -1)) {
      SET_STATUS_Success(0);
      return;
   }

   /* Ask to handle this syscall via the slow route, since that's the
      only one that sets tst->status to VgTs_WaitSys.  If the result
      of doing the syscall is an immediate run of
      async_signalhandler() in m_signals, then we need the thread to
      be properly tidied away.  I have the impression the previous
      version of this wrapper worked on x86/amd64 only because the
      kernel did not immediately deliver the async signal to this
      thread (on ppc it did, which broke the assertion re tst->status
      at the top of async_signalhandler()). */
   *flags |= SfMayBlock;
}

POST(sys_thr_kill)
{
   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "thr_kill: sent signal %lu to tid %lu\n",
                   ARG2, ARG1);
}

PRE(sys_thr_kill2)
{
   PRINT("sys_thr_kill2 ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "thr_kill2", int, pid, long, tid, int, sig);
   if (!ML_(client_signal_OK)(ARG3)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   /* Check to see if this kill gave us a pending signal */
   *flags |= SfPollAfter;

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "thr_kill2: sending signal %lu to pid %lu/%lu\n",
                   ARG3, ARG1, ARG2);

   /* If we're sending SIGKILL, check to see if the target is one of
      our threads and handle it specially. */
   if (ARG3 == VKI_SIGKILL && ML_(do_sigkill)(ARG2, ARG1)) {
      SET_STATUS_Success(0);
      return;
   }

   /* Ask to handle this syscall via the slow route, since that's the
      only one that sets tst->status to VgTs_WaitSys.  If the result
      of doing the syscall is an immediate run of
      async_signalhandler() in m_signals, then we need the thread to
      be properly tidied away.  I have the impression the previous
      version of this wrapper worked on x86/amd64 only because the
      kernel did not immediately deliver the async signal to this
      thread (on ppc it did, which broke the assertion re tst->status
      at the top of async_signalhandler()). */
   *flags |= SfMayBlock;
}

POST(sys_thr_kill2)
{
   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "thr_kill2: sent signal %lu to pid %lu/%lu\n",
                   ARG3, ARG1, ARG2);
}

PRE(sys_thr_wake)
{
   PRINT("sys_thr_wake ( %" FMT_REGWORD "u )", ARG1);
   PRE_REG_READ1(long, "thr_wake", long, id);
}

/* ---------------------------------------------------------------------
   umtx* wrappers
   ------------------------------------------------------------------ */

PRE(sys__umtx_op)
{
// ThreadState *tst;
   /* 5 args are always passed through.  The last two can vary, but
      they're always pointers.  They may not be used though. */
   switch(ARG2) {
   case VKI_UMTX_OP_LOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, LOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_lock",
                    struct umtx *, obj, int, op, unsigned long, id,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_lock(mtx)", ARG1, sizeof(struct vki_umtx) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_lock(timespec)", ARG5, sizeof(struct vki_timespec) );
      PRE_MEM_WRITE( "_umtx_op_lock(mtx)", ARG1, sizeof(struct vki_umtx) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_UNLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, UNLOCK, %" FMT_REGWORD "u)", ARG1, ARG3);
      PRE_REG_READ3(long, "_umtx_op_unlock",
                    struct umtx *, obj, int, op, unsigned long, id);
      PRE_MEM_READ( "_umtx_op_unlock(mtx)", ARG1, sizeof(struct vki_umtx) );
      PRE_MEM_WRITE( "_umtx_op_unlock(mtx)", ARG1, sizeof(struct vki_umtx) );
      break;
   case VKI_UMTX_OP_WAIT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, WAIT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_wait",
                    struct umtx *, obj, int, op, unsigned long, id,
                    void *, zero, struct vki_timespec *, timeout);
      /*
      PRE_MEM_READ( "_umtx_op_wait(mtx)", ARG1, sizeof(struct vki_umtx) );
      if (ARG5)
     PRE_MEM_READ( "_umtx_op_wait(timespec)", ARG5, sizeof(struct vki_timespec) );
      */
      if (ARG1)
          PRE_MEM_READ( "_umtx_op_wait(val)", ARG1, sizeof(long) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_WAKE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, WAKE, %" FMT_REGWORD "u)", ARG1, ARG3);
      PRE_REG_READ3(long, "_umtx_op_wake",
                    struct umtx *, obj, int, op, unsigned long, id);
      PRE_MEM_READ( "_umtx_op_wake(mtx)", ARG1, sizeof(struct vki_umtx) );
      break;
   case VKI_UMTX_OP_MUTEX_TRYLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_TRYLOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_mutex_trylock",
                    struct umutex *, obj, int, op, unsigned long, noid,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_mutex_trylock(mutex)", ARG1, sizeof(struct vki_umutex) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_mutex_trylock(timespec)", ARG5, sizeof(struct vki_timespec) );
      PRE_MEM_WRITE( "_umtx_op_mutex_trylock(mutex)", ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_MUTEX_LOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_LOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_mutex_lock",
                    struct umutex *, obj, int, op, unsigned long, noid,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_mutex_lock(mutex)", ARG1, sizeof(struct vki_umutex) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_mutex_lock(timespec)", ARG5, sizeof(struct vki_timespec) );
      PRE_MEM_WRITE( "_umtx_op_mutex_lock(mutex)", ARG1, sizeof(struct vki_umutex) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_MUTEX_UNLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_UNLOCK)", ARG1);
      PRE_REG_READ2(long, "_umtx_op_mutex_unlock",
                    struct umutex *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_mutex_unlock(mutex)", ARG1, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_mutex_unlock(mutex)", ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_SET_CEILING:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SET_CEILING, %" FMT_REGWORD "u, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4);
      PRE_REG_READ4(long, "_umtx_op_set_ceiling",
                    struct umutex *, obj, int, op, unsigned int, ceiling,
                    unsigned int *, old_ceiling);
      PRE_MEM_READ( "_umtx_op_set_ceiling(mutex)", ARG1, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_set_ceiling(mutex)", ARG1, sizeof(struct vki_umutex) );
      if (ARG4)
         PRE_MEM_WRITE( "_umtx_op_set_ceiling(old_ceiling)", ARG4, sizeof(vki_uint32_t) );
      break;
   case VKI_UMTX_OP_CV_WAIT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_WAIT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_cv_wait",
                    struct ucond *, obj, int, op, unsigned long, wflags,
                    struct umutex *, umtx, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_cv_wait(cond)", ARG1, sizeof(struct vki_ucond) );
      PRE_MEM_WRITE( "_umtx_op_cv_wait(cond)", ARG1, sizeof(struct vki_ucond) );
      PRE_MEM_READ( "_umtx_op_cv_wait(mutex)", ARG4, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_cv_wait(mutex)", ARG4, sizeof(struct vki_umutex) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_cv_wait(timespec)", ARG5, sizeof(struct vki_timespec) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_CV_SIGNAL:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_SIGNAL)", ARG1);
      PRE_REG_READ2(long, "_umtx_op_cv_signal",
                    struct ucond *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_cv_signal(cond)", ARG1, sizeof(struct vki_ucond) );
      PRE_MEM_WRITE( "_umtx_op_cv_signal(cond)", ARG1, sizeof(struct vki_ucond) );
      break;
   case VKI_UMTX_OP_CV_BROADCAST:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_BROADCAST, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ2(long, "_umtx_op_cv_broadcast",
                    struct ucond *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_cv_broadcast(cond)", ARG1, sizeof(struct vki_ucond) );
      PRE_MEM_WRITE( "_umtx_op_cv_broadcast(cond)", ARG1, sizeof(struct vki_ucond) );
      break;
   case VKI_UMTX_OP_WAIT_UINT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_WAIT_UINT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_wait_uint",
                    int *, obj, int, op, unsigned long, id,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_wait(uint)", ARG1, sizeof(int) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_wait(timespec)", ARG5, sizeof(struct vki_timespec) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_RW_RDLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, RW_RDLOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_rw_rdlock",
                    struct urwlock *, obj, int, op, unsigned long, noid,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_rw_rdlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      PRE_MEM_WRITE( "_umtx_op_rw_rdlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_RW_WRLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, RW_WRLOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_rw_wrlock",
                    struct urwlock *, obj, int, op, unsigned long, noid,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_rw_wrlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      PRE_MEM_WRITE( "_umtx_op_rw_wrlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_RW_UNLOCK:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, RW_UNLOCK, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ2(long, "_umtx_op_rw_unlock",
                    struct urwlock *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_rw_unlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      PRE_MEM_WRITE( "_umtx_op_rw_unlock(rw)", ARG1, sizeof(struct vki_urwlock) );
      break;
   case VKI_UMTX_OP_WAIT_UINT_PRIVATE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_WAIT_UINT_PRIVATE, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_wait_uint_private",
                    int *, obj, int, op, unsigned long, id,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_wait_private(uint)", ARG1, sizeof(int) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_wait_private(umtx_time)", ARG5, sizeof(struct vki_umtx_time) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_WAKE_PRIVATE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, CV_WAKE_PRIVATE, %" FMT_REGWORD "u)", ARG1, ARG3);
      PRE_REG_READ3(long, "_umtx_op_wake_private",
                    struct umtx *, obj, int, op, unsigned long, id);
      PRE_MEM_READ( "_umtx_op_wake_private(mtx)", ARG1, sizeof(struct vki_umtx) );
      break;
   case VKI_UMTX_OP_MUTEX_WAIT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_WAIT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ2(long, "_umtx_op_mutex_wait",
                    struct umutex *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_mutex_wait(mutex)", ARG1, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_mutex_wait(mutex)", ARG1, sizeof(struct vki_umutex) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_MUTEX_WAKE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_WAKE, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ2(long, "_umtx_op_mutex_wake",
                    struct umutex *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_mutex_wake(mutex)", ARG1, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_mutex_wake(mutex)", ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_SEM_WAIT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SEM_WAIT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ5(long, "_umtx_op_sem_wait",
                    struct usem *, obj, int, op, unsigned long, id,
                    void *, zero, struct vki_timespec *, timeout);
      PRE_MEM_READ( "_umtx_op_sem_wait(usem)", ARG1, sizeof(struct vki_usem) );
      PRE_MEM_WRITE( "_umtx_op_sem_wait(usem)", ARG1, sizeof(struct vki_usem) );
      if (ARG5)
         PRE_MEM_READ( "_umtx_op_sem_wait(umtx_time)", ARG5, sizeof(struct vki_umtx_time) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_SEM_WAKE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SEM_WAKE, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ2(long, "_umtx_op_sem_wake",
                    struct umutex *, obj, int, op);
      PRE_MEM_READ( "_umtx_op_sem_wake(mutex)", ARG1, sizeof(struct vki_usem) );
      PRE_MEM_WRITE( "_umtx_op_sem_wake(mutex)", ARG1, sizeof(struct vki_usem) );
      break;
   case VKI_UMTX_OP_NWAKE_PRIVATE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, NWAKE_PRIVATE, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ3(long, "_umtx_op_nwake_private",
                    struct umutex *, obj, int, op, int, count);
      PRE_MEM_READ( "_umtx_op_nwake_private(mtxs)", ARG1, ARG3 * sizeof(void *) );
      PRE_MEM_WRITE( "_umtx_op_mutex_wake(mtxs)", ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_MUTEX_WAKE2:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, MUTEX_WAKE2, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ3(long, "_umtx_op_mutex_wake2",
                    struct umutex *, obj, int, op, unsigned long, flags);
      PRE_MEM_READ( "_umtx_op_mutex_wake(mutex)", ARG1, sizeof(struct vki_umutex) );
      PRE_MEM_WRITE( "_umtx_op_mutex_wake(mutex)", ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_SEM2_WAIT:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SEM2_WAIT, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ3(long, "_umtx_op_sem2_wake",
                    struct _usem2 *, obj, int, op, unsigned long, flags);
      PRE_MEM_READ( "_umtx_op_sem2_wait(mutex)", ARG1, sizeof(struct vki_usem2) );
      PRE_MEM_WRITE( "_umtx_op_sem2_wait(mutex)", ARG1, sizeof(struct vki_usem2) );
      *flags |= SfMayBlock;
      break;
   case VKI_UMTX_OP_SEM2_WAKE:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SEM2_WAKE, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ3(long, "_umtx_op_sem2_wake",
                    struct _usem2 *, obj, int, op, unsigned long, flags);
      PRE_MEM_READ( "_umtx_op_sem2_wait(mutex)", ARG1, sizeof(struct vki_usem2) );
      PRE_MEM_WRITE( "_umtx_op_sem2_wait(mutex)", ARG1, sizeof(struct vki_usem2) );
      break;
   case VKI_UMTX_OP_SHM:
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, SHM, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ4(long, "_umtx_op_shm",
                    void *, obj, int, op, unsigned long, val, void*, uaddr);
      break;
   case VKI_UMTX_OP_ROBUST_LISTS:
       // val (ARG2) ought to be the same as sizeof(struct vki_umtx_robust_lists_params)
       // then the structure contains a pointer to mutex structures
      if (ARG1 != sizeof(struct vki_umtx_robust_lists_params))
          SET_STATUS_Failure( VKI_ENOSYS );
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, ROBUST_LISTS, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x)", ARG1, ARG3, ARG4, ARG5);
      PRE_REG_READ3(long, "_umtx_op_robust_lists",
                    struct umtx_robust_lists_params *, obj, int, op, unsigned long, flags);
      PRE_MEM_READ( "_umtx_op_robust_lists(mutex)", ARG3, sizeof(struct vki_umtx_robust_lists_params) );
      break;
   default:
      VG_(umsg)("WARNING: _umtx_op unsupported value.\n");
      PRINT( "sys__umtx_op ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u(UNKNOWN), %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1, ARG2, ARG3, ARG4, ARG5);
      break;
   }
//   tst = VG_(get_ThreadState)(tid);
//PRINT(" [[ UMTX_OP %d: me=%d arg1 %#lx = %#lx (%ld) ]]", ARG2, tst->os_state.lwpid, ARG1, *(UWord *)ARG1, *(UWord *)ARG1 & 0x7fffffff);
}

POST(sys__umtx_op)
{
//PRINT("[[ POST_UMTX_OP %d: arg1 %#lx = %#lx (%ld) ]]\n", ARG2, ARG1, *(UWord *)ARG1, *(UWord *)ARG1 & 0x7fffffff);
   switch(ARG2) {
   case VKI_UMTX_OP_LOCK:
      if (SUCCESS)
         POST_MEM_WRITE( ARG1, sizeof(struct vki_umtx) );
      break;
   case VKI_UMTX_OP_UNLOCK:
      if (SUCCESS)
         POST_MEM_WRITE( ARG1, sizeof(struct vki_umtx) );
      break;
   case VKI_UMTX_OP_WAIT:
   case VKI_UMTX_OP_WAKE:
   case VKI_UMTX_OP_WAIT_UINT:
   case VKI_UMTX_OP_WAIT_UINT_PRIVATE:
   case VKI_UMTX_OP_WAKE_PRIVATE:
      break;
   case VKI_UMTX_OP_MUTEX_TRYLOCK:
   case VKI_UMTX_OP_MUTEX_LOCK:
   case VKI_UMTX_OP_MUTEX_UNLOCK:
   case VKI_UMTX_OP_MUTEX_WAIT:        /* Sets/clears contested bits */
   case VKI_UMTX_OP_MUTEX_WAKE:        /* Sets/clears contested bits */
      if (SUCCESS)
         POST_MEM_WRITE( ARG1, sizeof(struct vki_umutex) );
      break;
   case VKI_UMTX_OP_SET_CEILING:
      if (SUCCESS) {
         POST_MEM_WRITE( ARG1, sizeof(struct vki_umutex) );
         if (ARG4)
            POST_MEM_WRITE( ARG4, sizeof(vki_uint32_t) );
      }
      break;
   case VKI_UMTX_OP_CV_WAIT:
      if (SUCCESS) {
         POST_MEM_WRITE( ARG1, sizeof(struct vki_ucond) );
         POST_MEM_WRITE( ARG4, sizeof(struct vki_umutex) );
      }
      break;
   case VKI_UMTX_OP_CV_SIGNAL:
      if (SUCCESS) {
         POST_MEM_WRITE( ARG1, sizeof(struct vki_ucond) );
      }
      break;
   case VKI_UMTX_OP_CV_BROADCAST:
      if (SUCCESS) {
         POST_MEM_WRITE( ARG1, sizeof(struct vki_ucond) );
      }
      break;
   case VKI_UMTX_OP_RW_RDLOCK:
   case VKI_UMTX_OP_RW_WRLOCK:
   case VKI_UMTX_OP_RW_UNLOCK:
      if (SUCCESS) {
         POST_MEM_WRITE( ARG1, sizeof(struct vki_urwlock) );
      }
      break;
   case VKI_UMTX_OP_SEM2_WAIT:
   case VKI_UMTX_OP_SEM2_WAKE:
       if (SUCCESS) {
          POST_MEM_WRITE( ARG1, sizeof(struct vki_usem2) );
       }
       break;
   case VKI_UMTX_OP_SHM:
   case VKI_UMTX_OP_ROBUST_LISTS:
   default:
      break;
   }
}

PRE(sys__umtx_lock)
{
   PRINT( "sys__umtx_lock ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "_umtx_lock", struct vki_umtx *, umtx);
   PRE_MEM_READ( "_umtx_lock(mtx)", ARG1, sizeof(struct vki_umtx) );
   PRE_MEM_WRITE( "_umtx_lock(mtx)", ARG1, sizeof(struct vki_umtx) );
}

POST(sys__umtx_lock)
{
   if (SUCCESS)
       POST_MEM_WRITE(ARG1, sizeof(struct vki_umtx));
}

PRE(sys__umtx_unlock)
{
   PRINT( "sys__umtx_unlock ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "_umtx_unlock", struct vki_umtx *, umtx);
   PRE_MEM_READ( "_umtx_unlock(mtx)", ARG1, sizeof(struct vki_umtx) );
   PRE_MEM_WRITE( "_umtx_unlock(mtx)", ARG1, sizeof(struct vki_umtx) );
}

POST(sys__umtx_unlock)
{
   if (SUCCESS)
      POST_MEM_WRITE(ARG1, sizeof(struct vki_umtx));
}

PRE(sys_rtprio_thread)
{
   PRINT( "sys_rtprio_thread ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1, ARG2, ARG3 );
   PRE_REG_READ3(long, "rtprio_thread",
      int, "function", __vki_lwpid_t, "lwpid", struct vki_rtprio *, "rtp");
   if (ARG1 == VKI_RTP_SET) {
      PRE_MEM_READ( "rtprio_thread(set)", ARG3, sizeof(struct vki_rtprio));
   } else if (ARG1 == VKI_RTP_LOOKUP) {
      PRE_MEM_WRITE( "rtprio_thread(lookup)", ARG3, sizeof(struct vki_rtprio));
   } else {
    /* PHK ?? */
   }
}

POST(sys_rtprio_thread)
{
   if (ARG1 == VKI_RTP_LOOKUP && RES == 0)
      POST_MEM_WRITE( ARG3, sizeof(struct vki_rtprio));
}

/* ---------------------------------------------------------------------
   sig* wrappers
   ------------------------------------------------------------------ */

PRE(sys_sigpending)
{
   PRINT( "sys_sigpending ( %#" FMT_REGWORD "x )", ARG1 );
   PRE_REG_READ1(long, "sigpending", vki_sigset_t *, set);
   PRE_MEM_WRITE( "sigpending(set)", ARG1, sizeof(vki_sigset_t));
}

POST(sys_sigpending)
{
   POST_MEM_WRITE( ARG1, sizeof(vki_sigset_t) ) ;
}

/* ---------------------------------------------------------------------
   rt_sig* wrappers
   ------------------------------------------------------------------ */

//int sigaction(int sig, const struct sigaction * restrict act,
//              struct sigaction * restrict oact);
PRE(sys_sigaction)
{
    vki_sigaction_toK_t   new, *newp;
    vki_sigaction_fromK_t old, *oldp;

   PRINT("sys_sigaction ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         SARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sigaction",
                 int, sign, const struct sigaction *, act,
                 struct sigaction *, oact);

   newp = oldp = NULL;

   if (ARG2 != 0) {
      struct vki_sigaction *sa = (struct vki_sigaction *)ARG2;
      PRE_MEM_READ( "sigaction(act->sa_handler)", (Addr)&sa->ksa_handler, sizeof(sa->ksa_handler));
      PRE_MEM_READ( "sigaction(act->sa_mask)", (Addr)&sa->sa_mask, sizeof(sa->sa_mask));
      PRE_MEM_READ( "sigaction(act->sa_flags)", (Addr)&sa->sa_flags, sizeof(sa->sa_flags));
   }

   if (ARG3 != 0) {
      PRE_MEM_WRITE( "sigaction(oact)", ARG3, sizeof(struct vki_sigaction));
      oldp = &old;
   }

   if (ARG2 != 0
       && ! ML_(safe_to_deref)((void *)(Addr)ARG2,
                               sizeof(struct vki_sigaction))) {
      VG_(umsg)("Warning: bad act handler address %p in sigaction()\n",
                (void *)(Addr)ARG2);
      SET_STATUS_Failure ( VKI_EFAULT );
   } else if ((ARG3 != 0
               && ! ML_(safe_to_deref)((void *)(Addr)ARG3,
                                       sizeof(struct vki_sigaction)))) {
      VG_(umsg)("Warning: bad oact handler address %p in sigaction()\n",
                (void *)(Addr)ARG3);
      SET_STATUS_Failure ( VKI_EFAULT );
   } else {
      if (ARG2 != 0) {
         struct vki_sigaction *oldnew =
            (struct vki_sigaction *)(Addr)ARG2;

         new.ksa_handler = oldnew->ksa_handler;
         new.sa_flags = oldnew->sa_flags;
         new.sa_mask = oldnew->sa_mask;
         newp = &new;
      }

      SET_STATUS_from_SysRes( VG_(do_sys_sigaction)(ARG1, newp, oldp) );

      if (ARG3 != 0 && SUCCESS && RES == 0) {
         struct vki_sigaction *oldold =
            (struct vki_sigaction *)(Addr)ARG3;

         oldold->ksa_handler = oldp->ksa_handler;
         oldold->sa_flags = oldp->sa_flags;
         oldold->sa_mask = oldp->sa_mask;
      }
  }
}

POST(sys_sigaction)
{
   vg_assert(SUCCESS);
   if (RES == 0 && ARG3 != 0)
      POST_MEM_WRITE( ARG3, sizeof(struct vki_sigaction));
}


PRE(sys_sigprocmask)
{
   PRINT("sys_sigprocmask ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sigprocmask", 
                 int, how, vki_sigset_t *, set, vki_sigset_t *, oldset);
   if (ARG2 != 0)
      PRE_MEM_READ( "sigprocmask(set)", ARG2, sizeof(vki_sigset_t));
   if (ARG3 != 0)
      PRE_MEM_WRITE( "sigprocmask(oldset)", ARG3, sizeof(vki_sigset_t));

   SET_STATUS_from_SysRes( 
           VG_(do_sys_sigprocmask) ( tid, ARG1 /*how*/,
                                    (vki_sigset_t*) ARG2,
                                    (vki_sigset_t*) ARG3 )
   );

   if (SUCCESS)
      *flags |= SfPollAfter;
}

POST(sys_sigprocmask)
{
   vg_assert(SUCCESS);
   if (RES == 0 && ARG3 != 0)
      POST_MEM_WRITE( ARG3, sizeof(vki_sigset_t));
}

/* Not in 4.x */
PRE(sys_sigtimedwait)
{
   *flags |= SfMayBlock;
   PRINT("sys_sigtimedwait ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sigtimedwait", 
                 const vki_sigset_t *, set, vki_siginfo_t *, info,
                 const struct timespec *, timeout);
   if (ARG1 != 0) 
      PRE_MEM_READ(  "sigtimedwait(set)",  ARG1, sizeof(vki_sigset_t));
   if (ARG2 != 0)
      PRE_MEM_WRITE( "sigtimedwait(info)", ARG2, sizeof(vki_siginfo_t) );
   if (ARG3 != 0)
      PRE_MEM_READ( "sigtimedwait(timeout)",
                    ARG3, sizeof(struct vki_timespec) );
}

POST(sys_sigtimedwait)
{
   if (ARG2 != 0)
      POST_MEM_WRITE( ARG2, sizeof(vki_siginfo_t) );
}

/* Not in 4.x */
PRE(sys_sigwaitinfo)
{
   *flags |= SfMayBlock;
   PRINT("sys_sigwaitinfo ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         ARG1,ARG2);
   PRE_REG_READ2(long, "sigwaitinfo", 
                 const vki_sigset_t *, set, vki_siginfo_t *, info);
   if (ARG1 != 0) 
      PRE_MEM_READ(  "sigwaitinfo(set)",  ARG1, sizeof(vki_sigset_t));
   if (ARG2 != 0)
      PRE_MEM_WRITE( "sigwaitinfo(info)", ARG2, sizeof(vki_siginfo_t) );
}

POST(sys_sigwaitinfo)
{
   if (ARG2 != 0)
      POST_MEM_WRITE( ARG2, sizeof(vki_siginfo_t) );
}

#if 0    /* not on freebsd 4.x */
PRE(sys_rt_sigqueueinfo)
{
   PRINT("sys_rt_sigqueueinfo(%" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x)", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "rt_sigqueueinfo", 
                 int, pid, int, sig, vki_siginfo_t *, uinfo);
   if (ARG2 != 0)
      PRE_MEM_READ( "rt_sigqueueinfo(uinfo)", ARG3, sizeof(vki_siginfo_t) );
}

POST(sys_rt_sigqueueinfo)
{
   if (!ML_(client_signal_OK)(ARG2))
      SET_STATUS_Failure( VKI_EINVAL );
}
#endif

PRE(sys_sigsuspend)
{
   *flags |= SfMayBlock;
   PRINT("sys_sigsuspend ( %#" FMT_REGWORD "x )", ARG1 );
   PRE_REG_READ1(int, "sigsuspend", vki_sigset_t *, mask)
   if (ARG1 != (Addr)NULL) {
      PRE_MEM_READ( "_sigsuspend(mask)", ARG1, sizeof(vki_sigset_t) );
      if (ML_(safe_to_deref)((vki_sigset_t *) (Addr)ARG1, sizeof(vki_sigset_t))) {
         VG_(sigdelset)((vki_sigset_t *) (Addr)ARG1, VG_SIGVGKILL);
         /* We cannot mask VG_SIGVGKILL, as otherwise this thread would not
            be killable by VG_(nuke_all_threads_except).
            We thus silently ignore the user request to mask this signal.
            Note that this is similar to what is done for e.g.
            sigprocmask (see m_signals.c calculate_SKSS_from_SCSS). */
      } else {
         SET_STATUS_Failure(VKI_EFAULT);
      }
   }
}

PRE(sys_chflags)
{
   PRINT("sys_chflags ( %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "chflags",
                 const char *, path, unsigned long, flags);
   PRE_MEM_RASCIIZ( "chflags(path)", ARG1 );
}

PRE(sys_fchflags)
{
   PRINT("sys_fchflags ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2);
   PRE_REG_READ2(long, "fchflags", unsigned int, fd, unsigned long, flags);
}


PRE(sys_modfind)
{
   PRINT("sys_modfind ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(long, "modfind", char *, modname);
   PRE_MEM_RASCIIZ( "modfind(modname)", ARG1 );
}

PRE(sys_modstat)
{
   PRINT("sys_modstat ( %lu, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "modstat", int, modid, struct module_stat *, buf);
   PRE_MEM_WRITE( "modstat(buf)", ARG2, sizeof(struct vki_module_stat) );
}

POST(sys_modstat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_module_stat) );
}

PRE(sys_lkmnosys0)
{
   PRINT("%s", "sys_lkmnosys0 ()");
   PRE_REG_READ0(long, "lkmnosys0");
}

PRE(sys_lkmnosys1)
{
   PRINT("%s", "sys_lkmnosys1 ()");
   PRE_REG_READ0(long, "lkmnosys1");
}

PRE(sys_lkmnosys2)
{
   PRINT("%s", "sys_lkmnosys2 ()");
   PRE_REG_READ0(long, "lkmnosys2");
}

PRE(sys_lkmnosys3)
{
   PRINT("%s", "sys_lkmnosys3 ()");
   PRE_REG_READ0(long, "lkmnosys3");
}

PRE(sys_lkmnosys4)
{
   PRINT("%s", "sys_lkmnosys4 ()");
   PRE_REG_READ0(long, "lkmnosys4");
}

PRE(sys_lkmnosys5)
{
   PRINT("%s", "sys_lkmnosys5 ()");
   PRE_REG_READ0(long, "lkmnosys5");
}

PRE(sys_lkmnosys6)
{
   PRINT("%s", "sys_lkmnosys6 ()");
   PRE_REG_READ0(long, "lkmnosys6");
}

PRE(sys_lkmnosys7)
{
   PRINT("%s", "sys_lkmnosys7 ()");
   PRE_REG_READ0(long, "lkmnosys7");
}

PRE(sys_lkmnosys8)
{
   PRINT("%s", "sys_lkmnosys8 ()");
   PRE_REG_READ0(long, "lkmnosys8");
}

PRE(sys_kenv)
{
   PRINT("sys_kenv ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "kenv",
                 int, action, const char *, name, char *, value, int, len);
   switch (ARG1) {
   case VKI_KENV_GET:
   case VKI_KENV_SET:
   case VKI_KENV_UNSET:
      PRE_MEM_RASCIIZ("kenv(name)", ARG2);
      /* FALLTHROUGH */
   case VKI_KENV_DUMP:
      break;
   default:
      I_die_here;
   }
}

POST(sys_kenv)
{
   if (SUCCESS) {
      switch (ARG1) {
      case VKI_KENV_GET:
         POST_MEM_WRITE(ARG3, ARG4);
         break;
      case VKI_KENV_DUMP:
         if (ARG3 != (Addr)NULL)
            POST_MEM_WRITE(ARG3, ARG4);
         break;
      }
   }
}

PRE(sys_lchflags)
{
   PRINT("sys_lchflags ( %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "lchglags",
                 const char *, path, unsigned long, flags);
   PRE_MEM_RASCIIZ( "chflags(path)", ARG1 );
}

PRE(sys_uuidgen)
{
   PRINT("sys_uuidgen ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG2);
   PRE_REG_READ2(long, "uuidgen",
         struct vki_uuid *, store, int, count);
   PRE_MEM_WRITE( "uuidgen(store)", ARG1, ARG2 * sizeof(struct vki_uuid));
}

POST(sys_uuidgen)
{
   if (SUCCESS)
      POST_MEM_WRITE( ARG1, ARG2 * sizeof(struct vki_uuid) );
}

PRE(sys_shmget)
{
   PRINT("sys_shmget ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "shmget", vki_key_t, key, vki_size_t, size, int, shmflg);
}

PRE(sys_shmat)
{
   UWord arg2tmp;
   PRINT("sys_shmat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "shmat",
                 int, shmid, const void *, shmaddr, int, shmflg);
   arg2tmp = ML_(generic_PRE_sys_shmat)(tid, ARG1,ARG2,ARG3);
   if (arg2tmp == 0)
      SET_STATUS_Failure( VKI_EINVAL );
   else
      ARG2 = arg2tmp;
}

POST(sys_shmat)
{
   ML_(generic_POST_sys_shmat)(tid, RES,ARG1,ARG2,ARG3);
}

PRE(sys_shmdt)
{
   PRINT("sys_shmdt ( %#" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(long, "shmdt", const void *, shmaddr);
   if (!ML_(generic_PRE_sys_shmdt)(tid, ARG1))
      SET_STATUS_Failure( VKI_EINVAL );
}

POST(sys_shmdt)
{
   ML_(generic_POST_sys_shmdt)(tid, RES,ARG1);
}

// int msgctl(int msqid, int cmd, struct msqid_ds_old *buf);
PRE(sys_freebsd7_msgctl)
{
   PRINT("sys_msgctl ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3 );

   PRE_REG_READ3(int, "msgctl", int, msqid, int, cmd, struct msqid_ds_old *, buf);

   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      PRE_MEM_WRITE( "msgctl(IPC_STAT, buf)",
                     ARG3, sizeof(struct vki_msqid_ds_old) );
      break;
   case VKI_IPC_SET:
      PRE_MEM_READ( "msgctl(IPC_SET, buf)",
                    ARG3, sizeof(struct vki_msqid_ds_old) );
      break;
   }
}

POST(sys_freebsd7_msgctl)
{
   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      POST_MEM_WRITE( ARG3, sizeof(struct vki_msqid_ds_old) );
      break;
   }
}

PRE(sys_shmctl)
{
   PRINT("sys_shmctl ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )",SARG1,SARG2,ARG3);
   PRE_REG_READ3(long, "shmctl",
                 int, shmid, int, cmd, struct vki_shmid_ds *, buf);
   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      PRE_MEM_WRITE( "shmctl(IPC_STAT, buf)",
                     ARG3, sizeof(struct vki_shmid_ds) );
      break;
   case VKI_IPC_SET:
      PRE_MEM_READ( "shmctl(IPC_SET, buf)",
                    ARG3, sizeof(struct vki_shmid_ds) );
      break;
   }
}


PRE(sys_freebsd7_shmctl)
{
   PRINT("sys_freebsd7_shmctl ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )",SARG1,SARG2,ARG3);
   PRE_REG_READ3(long, "shmctl",
                 int, shmid, int, cmd, struct vki_shmid_ds_old *, buf);
   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      PRE_MEM_WRITE( "shmctl7(IPC_STAT, buf)",
                     ARG3, sizeof(struct vki_shmid_ds_old) );
      break;
   case VKI_IPC_SET:
      PRE_MEM_READ( "shmctl7(IPC_SET, buf)",
                    ARG3, sizeof(struct vki_shmid_ds_old) );
      break;
   }
}

POST(sys_shmctl)
{
   if (ARG2 == VKI_IPC_STAT) {
      POST_MEM_WRITE( ARG3, sizeof(struct vki_shmid_ds) );
   }
}

POST(sys_freebsd7_shmctl)
{
   if (ARG2 == VKI_IPC_STAT) {
      POST_MEM_WRITE( ARG3, sizeof(struct vki_shmid_ds_old) );
   }
}

PRE(sys_semget)
{
   PRINT("sys_semget ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "semget", vki_key_t, key, int, nsems, int, semflg);
}

PRE(sys_shm_open)
{
   PRE_REG_READ3(long, "shm_open",
                const char *, "name", int, "flags", vki_mode_t, "mode");
   if (ARG1 == VKI_SHM_ANON) {
      PRINT("sys_shm_open(%#" FMT_REGWORD "x(SHM_ANON), %" FMT_REGWORD "u, %" FMT_REGWORD "u)", ARG1, ARG2, ARG3);
   } else {
      PRINT("sys_shm_open(%#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %" FMT_REGWORD "u)", ARG1, (char *)ARG1, ARG2, ARG3);
      PRE_MEM_RASCIIZ( "shm_open(filename)", ARG1 );
   }
   *flags |= SfMayBlock;
}

POST(sys_shm_open)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "shm_open", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_with_given_name)(tid, RES, (HChar*)ARG1);
   }
}

PRE(sys_shm_unlink)
{
   PRINT("sys_shm_unlink(%#" FMT_REGWORD "x(%s))", ARG1, (char *)ARG1);
   PRE_REG_READ1(long, "shm_unlink",
                 const char *, "name");

   PRE_MEM_RASCIIZ( "shm_unlink(filename)", ARG1 );

   *flags |= SfMayBlock;
}

PRE(sys_semop)
{
   *flags |= SfMayBlock;
   PRINT("sys_semop ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "semop",
                 int, semid, struct sembuf *, sops, unsigned, nsoops);
   ML_(generic_PRE_sys_semop)(tid, ARG1,ARG2,ARG3);
}

struct ipc_perm7 {
    unsigned short    cuid;    /* creator user id */
    unsigned short    cgid;    /* creator group id */
    unsigned short    uid;    /* user id */
    unsigned short    gid;    /* group id */
    unsigned short    mode;    /* r/w permission */
    unsigned short    seq;    /* sequence # (to generate unique ipcid) */
    vki_key_t    key;    /* user specified msg/sem/shm key */
};

/* ---------------------------------------------------------------------
   msg* wrappers
   ------------------------------------------------------------------ */

PRE(sys_msgget)
{
   PRINT("sys_msgget ( %" FMT_REGWORD"d, %" FMT_REGWORD"d )",ARG1,ARG2);
   PRE_REG_READ2(int, "msgget", key_t, key, int, msgflg);
}

// int msgsnd(int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg);
PRE(sys_msgsnd)
{
   PRINT("sys_msgsnd ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %" FMT_REGWORD "d )", ARG1,ARG2,ARG3,ARG4 );
   PRE_REG_READ4(int, "msgsnd", int, msqid, struct msgbuf *, msgp, size_t, msgsz, int, msgflg);
   struct vki_msgbuf *msgp = (struct vki_msgbuf *)ARG2;
   PRE_MEM_READ( "msgsnd(msgp->mtype)", (Addr)&msgp->mtype, sizeof(msgp->mtype) );
   PRE_MEM_READ( "msgsnd(msgp->mtext)", (Addr)&msgp->mtext, ARG3 );
}

// ssize_t msgrcv(int msqid, struct msgbuf *msgp, size_t msgsz, long msgtyp, int msgflg);
PRE(sys_msgrcv)
{
   *flags |= SfMayBlock;

   PRINT("sys_msgrcv ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %" FMT_REGWORD "d, %" FMT_REGWORD "d )", ARG1,ARG2,ARG3,ARG4,ARG5 );
   PRE_REG_READ5(ssize_t, "msgrcv", int, msqid, struct msgbuf *, msgp, size_t, msgsz,
      long, msgtyp, int, msgflg);
   struct vki_msgbuf *msgp = (struct vki_msgbuf *)ARG2;
   PRE_MEM_WRITE( "msgrcv(msgp->mtype)", (Addr)&msgp->mtype, sizeof(msgp->mtype) );
   PRE_MEM_WRITE( "msgrcv(msgp->mtext)", (Addr)&msgp->mtext, ARG3 );
}

POST(sys_msgrcv)
{
   struct vki_msgbuf *msgp = (struct vki_msgbuf *)ARG2;
   POST_MEM_WRITE( (Addr)&msgp->mtype, sizeof(msgp->mtype) );
   POST_MEM_WRITE( (Addr)&msgp->mtext, RES );
}

// int msgctl(int msqid, int cmd, struct msqid_ds *buf);
PRE(sys_msgctl)
{
   PRINT("sys_msgctl ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3 );

   PRE_REG_READ3(int, "msgctl", int, msqid, int, cmd, struct msqid_ds *, buf);

   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      PRE_MEM_WRITE( "msgctl(IPC_STAT, buf)",
                     ARG3, sizeof(struct vki_msqid_ds) );
      break;
   case VKI_IPC_SET:
      PRE_MEM_READ( "msgctl(IPC_SET, buf)",
                    ARG3, sizeof(struct vki_msqid_ds) );
      break;
   }
}

POST(sys_msgctl)
{
   switch (ARG2 /* cmd */) {
   case VKI_IPC_STAT:
      POST_MEM_WRITE( ARG3, sizeof(struct vki_msqid_ds) );
      break;
   }
}

struct semid_ds7 {
    struct ipc_perm7 sem_perm;    /* operation permission struct */
    struct sem    *sem_base;    /* pointer to first semaphore in set */
    unsigned short    sem_nsems;    /* number of sems in set */
    vki_time_t    sem_otime;    /* last operation time */
    long        sem_pad1;    /* SVABI/386 says I need this here */
    vki_time_t    sem_ctime;    /* last change time */
                        /* Times measured in secs since */
                        /* 00:00:00 GMT, Jan. 1, 1970 */
    long        sem_pad2;    /* SVABI/386 says I need this here */
    long        sem_pad3[4];    /* SVABI/386 says I need this here */
};

PRE(sys_freebsd7___semctl)
{
   switch (ARG3) {
   case VKI_IPC_INFO:
   case VKI_SEM_INFO:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, struct seminfo *, arg);
      break;
   case VKI_IPC_STAT:
   case VKI_SEM_STAT:
   case VKI_IPC_SET:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, struct semid_ds7 *, arg);
      break;
   case VKI_GETALL:
   case VKI_SETALL:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, unsigned short *, arg);
      break;
   default:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "semctl",
                    int, semid, int, semnum, int, cmd);
      break;
   }
   ML_(generic_PRE_sys_semctl)(tid, ARG1,ARG2,ARG3,ARG4);
}

POST(sys_freebsd7___semctl)
{
   ML_(generic_POST_sys_semctl)(tid, RES,ARG1,ARG2,ARG3,ARG4);
}

PRE(sys___semctl)
{
   switch (ARG3) {
   case VKI_IPC_INFO:
   case VKI_SEM_INFO:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, struct seminfo *, arg);
      break;
   case VKI_IPC_STAT:
   case VKI_SEM_STAT:
   case VKI_IPC_SET:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, struct semid_ds *, arg);
      break;
   case VKI_GETALL:
   case VKI_SETALL:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, unsigned short *, arg);
      break;
   default:
      PRINT("sys_semctl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "semctl",
                    int, semid, int, semnum, int, cmd);
      break;
   }
   ML_(generic_PRE_sys_semctl)(tid, ARG1,ARG2,ARG3,ARG4);
}

POST(sys___semctl)
{
   ML_(generic_POST_sys_semctl)(tid, RES,ARG1,ARG2,ARG3,ARG4);
}

PRE(sys_eaccess)
{
   PRINT("sys_eaccess ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,(char*)ARG1,ARG2);
   PRE_REG_READ2(long, "eaccess", const char *, pathname, int, mode);
   PRE_MEM_RASCIIZ( "eaccess(pathname)", ARG1 );
}


/* ---------------------------------------------------------------------
   *at wrappers
   ------------------------------------------------------------------ */

PRE(sys_openat)
{

   if (ARG3 & VKI_O_CREAT) {
      // 4-arg version
      PRINT("sys_openat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,(char*)ARG2,ARG3,ARG4);
      PRE_REG_READ4(int, "openat",
                    int, dfd, const char *, filename, int, flags, vki_mode_t, mode);
   } else {
      // 3-arg version
      PRINT("sys_openat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )",ARG1,ARG2,(char*)ARG2,ARG3);
      PRE_REG_READ3(int, "openat",
                    int, dfd, const char *, filename, int, flags);
   }

   if (ARG1 != (unsigned)VKI_AT_FDCWD && !ML_(fd_allowed)(ARG1, "openat", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_RASCIIZ( "openat(filename)", ARG2 );

   /* Otherwise handle normally */
   *flags |= SfMayBlock;
}

POST(sys_openat)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "openat", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_with_given_name)(tid, RES, (HChar*)ARG2);
   }
}

PRE(sys_mkdirat)
{
   *flags |= SfMayBlock;
   PRINT("sys_mkdirat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,ARG2,(char*)ARG2,ARG3);
   PRE_REG_READ3(long, "mkdirat",
                 int, dfd, const char *, pathname, int, mode);
   PRE_MEM_RASCIIZ( "mkdirat(pathname)", ARG2 );
}

PRE(sys_mkfifoat)
{
   PRINT("sys_mkfifoat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x )", ARG1,ARG2,(ARG2?(char*)ARG2:"NULL"),ARG3 );
   PRE_REG_READ3(int, "mkfifoat",
                 int, fd, const char *, path, vki_mode_t, mode);
   PRE_MEM_RASCIIZ( "mkfifoat(path)", ARG2 );
}

PRE(sys_mknodat)
{
  PRINT("sys_mknodat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x, 0x%" FMT_REGWORD "x )", ARG1,ARG2,(char*)ARG2,ARG3,ARG4 );
   PRE_REG_READ4(long, "mknodat",
                 int, dfd, const char *, pathname, int, mode, unsigned, dev);
   PRE_MEM_RASCIIZ( "mknodat(pathname)", ARG2 );
}

PRE(sys_fchownat)
{
   PRINT("sys_fchownat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), 0x%" FMT_REGWORD "x, 0x%" FMT_REGWORD "x )", ARG1,ARG2,(char*)ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "fchownat",
                 int, dfd, const char *, path,
                 vki_uid_t, owner, vki_gid_t, group);
   PRE_MEM_RASCIIZ( "fchownat(path)", ARG2 );
}

PRE(sys_futimesat)
{
   PRINT("sys_futimesat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )", ARG1,ARG2,(char*)ARG2,ARG3);
   PRE_REG_READ3(long, "futimesat",
                 int, dfd, char *, filename, struct timeval *, tvp);
   if (ARG2 != 0)
      PRE_MEM_RASCIIZ( "futimesat(filename)", ARG2 );
   if (ARG3 != 0)
      PRE_MEM_READ( "futimesat(tvp)", ARG3, 2 * sizeof(struct vki_timeval) );
}

PRE(sys_fstatat)
{
   PRINT("sys_fstatat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )", ARG1,ARG2,(char*)ARG2,ARG3);
   PRE_REG_READ3(long, "fstatat",
                 int, dfd, char *, file_name, struct stat *, buf);
   PRE_MEM_RASCIIZ( "fstatat(file_name)", ARG2 );
   PRE_MEM_WRITE( "fstatat(buf)", ARG3, sizeof(struct vki_stat) );
}

POST(sys_fstatat)
{
   POST_MEM_WRITE( ARG3, sizeof(struct vki_stat) );
}

PRE(sys_unlinkat)
{
   *flags |= SfMayBlock;
   PRINT("sys_unlinkat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s) )", ARG1,ARG2,(char*)ARG2);
   PRE_REG_READ2(long, "unlinkat", int, dfd, const char *, pathname);
   PRE_MEM_RASCIIZ( "unlinkat(pathname)", ARG2 );
}

//int posix_openpt(int oflag);
PRE(sys_posix_openpt)
{
   PRINT("sys_posix_openpt ( %" FMT_REGWORD "d )", SARG2);
   PRE_REG_READ1(long, "posix_openpt", int, oflag);

}

PRE(sys_jail_get)
{
    PRINT("sys_jail_get ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3);
    PRE_REG_READ3(int, "jail_get", struct vki_iovec *, iov, unsigned int,
        niov, int, flags);
    PRE_MEM_WRITE("jail_get", ARG1, ARG2 * sizeof(struct vki_iovec));
}

POST(sys_jail_get)
{
    vg_assert(SUCCESS);
    POST_MEM_WRITE(ARG1, ARG2);
}

PRE(sys_jail_set)
{
    PRINT("sys_jail_set ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3);
    PRE_REG_READ3(int, "jail_set", struct vki_iovec *, iov, unsigned int,
        niov, int, flags);
    PRE_MEM_WRITE("jail_set", ARG1, ARG2 * sizeof(struct vki_iovec));
}

PRE(sys_jail_attach)
{
    PRINT("sys_jail_attach ( %" FMT_REGWORD "d )", SARG1);
    PRE_REG_READ1(int, "jail_attach", int, jid);
}

PRE(sys_jail_remove)
{
    PRINT("sys_jail_remove ( %" FMT_REGWORD "d )", SARG1);
    PRE_REG_READ1(int, "jail_remove", int, jid);
}

PRE(sys_renameat)
{
   PRINT("sys_renameat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s) )", ARG1,ARG2,(char*)ARG2,ARG3,ARG4,(char*)ARG4);
   PRE_REG_READ4(long, "renameat",
                 int, olddfd, const char *, oldpath,
                 int, newdfd, const char *, newpath);
   PRE_MEM_RASCIIZ( "renameat(oldpath)", ARG2 );
   PRE_MEM_RASCIIZ( "renameat(newpath)", ARG4 );
}

PRE(sys_linkat)
{
   *flags |= SfMayBlock;
   PRINT("sys_linkat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )",ARG1,ARG2,(char*)ARG2,ARG3,ARG4,(char*)ARG4,ARG5);
   PRE_REG_READ5(long, "linkat",
                 int, olddfd, const char *, oldpath,
                 int, newdfd, const char *, newpath,
                 int, flags);
   PRE_MEM_RASCIIZ( "linkat(oldpath)", ARG2);
   PRE_MEM_RASCIIZ( "linkat(newpath)", ARG4);
}

PRE(sys_symlinkat)
{
   *flags |= SfMayBlock;
   PRINT("sys_symlinkat ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s) )",ARG1,(char*)ARG1,ARG2,ARG3,(char*)ARG3);
   PRE_REG_READ3(long, "symlinkat",
                 const char *, oldpath, int, newdfd, const char *, newpath);
   PRE_MEM_RASCIIZ( "symlinkat(oldpath)", ARG1 );
   PRE_MEM_RASCIIZ( "symlinkat(newpath)", ARG3 );
}

PRE(sys_readlinkat)
{
   HChar name[25];
   Word  saved = SYSNO;

   PRINT("sys_readlinkat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x, %llu )", ARG1,ARG2,(char*)ARG2,ARG3,(ULong)ARG4);
   PRE_REG_READ4(long, "readlinkat",
                 int, dfd, const char *, path, char *, buf, int, bufsiz);
   PRE_MEM_RASCIIZ( "readlinkat(path)", ARG2 );
   PRE_MEM_WRITE( "readlinkat(buf)", ARG3,ARG4 );

   /*
    * Handle the case where readlinkat is looking at /proc/curproc/file or
    * /proc/<pid>/file.
    */
   VG_(sprintf)(name, "/proc/%d/file", VG_(getpid)());
   if (ML_(safe_to_deref)((void*)ARG2, 1)
       && (VG_(strcmp)((HChar *)ARG2, name) == 0 
           || VG_(strcmp)((HChar *)ARG2, "/proc/curproc/file") == 0)) {
      VG_(sprintf)(name, "/proc/self/fd/%d", VG_(cl_exec_fd));
      SET_STATUS_from_SysRes( VG_(do_syscall4)(saved, ARG1, (UWord)name, 
                                                      ARG3, ARG4));
   } else {
      /* Normal case */
      SET_STATUS_from_SysRes( VG_(do_syscall4)(saved, ARG1, ARG2, ARG3, ARG4));
   }

   if (SUCCESS && (Word)RES != -1)
      POST_MEM_WRITE( ARG3, RES );
}

PRE(sys_fchmodat)
{
   PRINT("sys_fchmodat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,ARG2,(char*)ARG2,ARG3);
   PRE_REG_READ3(long, "fchmodat",
                 int, dfd, const char *, path, vki_mode_t, mode);
   PRE_MEM_RASCIIZ( "fchmodat(path)", ARG2 );
}

PRE(sys_faccessat)
{
   PRINT("sys_faccessat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,ARG2,(char*)ARG2,ARG3);
   PRE_REG_READ3(long, "faccessat",
                 int, dfd, const char *, pathname, int, mode);
   PRE_MEM_RASCIIZ( "faccessat(pathname)", ARG2 );
}

/* ---------------------------------------------------------------------
   __acl* wrappers
   ------------------------------------------------------------------ */

PRE(sys___acl_get_file)
{
   PRINT("sys___acl_get_file ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_get_file",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_WRITE( "__acl_get_file(aclp)", ARG3, sizeof(struct vki_acl) );
}

POST(sys___acl_get_file)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG3, sizeof(struct vki_acl) );
   }
}

PRE(sys___acl_set_file)
{
   PRINT("sys___acl_set_file ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_set_file",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_set_file(aclp)", ARG3, sizeof(struct vki_acl) );
}

PRE(sys___acl_get_fd)
{
   PRINT("sys___acl_get_fd ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_get_fd",
                 int, fd, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_WRITE( "__acl_get_file(aclp)", ARG3, sizeof(struct vki_acl) );
}

POST(sys___acl_get_fd)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG3, sizeof(struct vki_acl) );
   }
}

PRE(sys___acl_set_fd)
{
   PRINT("sys___acl_set_fd ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_set_fd",
                 int, fd, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_get_file(aclp)", ARG3, sizeof(struct vki_acl) );
}

PRE(sys___acl_delete_file)
{
   PRINT("sys___acl_delete_file ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "__acl_delete_file",
                 const char *, path, int, acltype);
}

PRE(sys___acl_delete_fd)
{
   PRINT("sys___acl_delete_fd ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2);
   PRE_REG_READ2(long, "__acl_delete_fd",
                 int, fd, int, acltype);
}

PRE(sys___acl_aclcheck_file)
{
   PRINT("sys___acl_aclcheck_file ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_aclcheck_file",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_aclcheck_file(aclp)", ARG3, sizeof(struct vki_acl) );
}

PRE(sys___acl_aclcheck_fd)
{
   PRINT("sys___acl_aclcheck_fd ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_aclcheck_fd",
                 int, fd, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_aclcheck_fd(aclp)", ARG3, sizeof(struct vki_acl) );
}


// ssize_t extattr_get_file(const char *path, int attrnamespace,
//                          const char *attrname, void *data, size_t nbytes);
PRE(sys_extattr_get_file)
{
    PRINT("sys_extattr_get_file ( %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,SARG2,ARG3,ARG4,ARG5);
    PRE_REG_READ5(long, "extattr_get_file",
                  const char *, path, int, attrnamespace, const char *, attrname, void *, data, size_t, nbytes);
    PRE_MEM_RASCIIZ("sys_extattr_get_file(path)", ARG1);
    PRE_MEM_RASCIIZ("sys_extattr_get_file(attrname)", ARG3);
    if (ARG4)
    {
        PRE_MEM_WRITE("sys_extattr_get_file(data)", ARG4, ARG5);
    }
}

POST(sys_extattr_get_file)
{
    if (ARG4)
    {
        POST_MEM_WRITE(ARG4, ARG5);
    }
}

PRE(sys___acl_get_link)
{
   PRINT("sys___acl_get_link ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_get_link",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_WRITE( "__acl_get_link(aclp)", ARG3, sizeof(struct vki_acl) );
}

POST(sys___acl_get_link)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG3, sizeof(struct vki_acl) );
   }
}

PRE(sys___acl_set_link)
{
   PRINT("sys___acl_set_link ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_set_link",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_set_link(aclp)", ARG3, sizeof(struct vki_acl) );
}

PRE(sys___acl_delete_link)
{
   PRINT("sys___acl_delete_link ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u )", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "__acl_delete_link",
                 const char *, path, int, acltype);
}

PRE(sys___acl_aclcheck_link)
{
   PRINT("sys___acl_aclcheck_link ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1,(char *)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "__acl_aclcheck_link",
                 const char *, path, int, acltype, struct vki_acl *, aclp);
   PRE_MEM_READ( "__acl_aclcheck_link(aclp)", ARG3, sizeof(struct vki_acl) );
}

PRE(sys_sigwait)
{
   *flags |= SfMayBlock;
   PRINT("sys_sigwait ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         ARG1,ARG2);
   PRE_REG_READ2(long, "sigwait",
                 const vki_sigset_t *, set, int *, sig);
   if (ARG1 != 0)
      PRE_MEM_READ(  "sigwait(set)",  ARG1, sizeof(vki_sigset_t));
   if (ARG2 != 0)
      PRE_MEM_WRITE( "sigwait(sig)", ARG2, sizeof(int));
}

POST(sys_sigwait)
{
   if (ARG2 != 0)
      POST_MEM_WRITE( ARG2, sizeof(int));
}

POST(sys_getcontext)
{
   POST_MEM_WRITE( ARG1, sizeof(struct vki_ucontext) );
}

POST(sys_swapcontext)
{
   if (SUCCESS)
      POST_MEM_WRITE( ARG1, sizeof(struct vki_ucontext) );
}

PRE(sys_fcntl)
{
   switch (ARG2) {
   // These ones ignore ARG3.
   case VKI_F_GETFD:
   case VKI_F_GETFL:
   case VKI_F_GETOWN:
      PRINT("sys_fcntl ( %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2);
      PRE_REG_READ2(long, "fcntl", unsigned int, fd, unsigned int, cmd);
      break;

   // These ones use ARG3 as "arg".
   case VKI_F_DUPFD:
   case VKI_F_DUPFD_CLOEXEC:
   case VKI_F_SETFD:
   case VKI_F_SETFL:
   case VKI_F_SETOWN:
   case VKI_F_READAHEAD:
   case VKI_F_RDAHEAD:
      PRINT("sys_fcntl[ARG3=='arg'] ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd, unsigned long, arg);
      break;

   // These ones use ARG3 as "lock" - obsolete.
   case VKI_F_OSETLKW:
      *flags |= SfMayBlock;
      /* FALLTHROUGH */
   case VKI_F_OGETLK:
   case VKI_F_OSETLK:
      PRINT("sys_fcntl[ARG3=='lock'] ( %lu, %lu, %#lx )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct oflock *, lock);
      break;

   // This one uses ARG3 as "oldd" and ARG4 as "newd".
   case VKI_F_DUP2FD:
   case VKI_F_DUP2FD_CLOEXEC:
      PRINT("sys_fcntl[ARG3=='oldd', ARG4=='newd'] ( %lu, %lu, %lu, %lu )",
         ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    unsigned long, oldd, unsigned long, newd);
      break;

   // These ones use ARG3 as "lock".
   case VKI_F_SETLKW:
      *flags |= SfMayBlock;
      /* FALLTHROUGH */
   case VKI_F_GETLK:
   case VKI_F_SETLK:
   case VKI_F_SETLK_REMOTE:
      PRINT("sys_fcntl[ARG3=='lock'] ( %lu, %lu, %#lx )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct flock *, lock);
      break;

   default:
      PRINT("sys_fcntl[UNKNOWN] ( %lu, %lu, %lu )", ARG1,ARG2,ARG3);
      I_die_here;
   }
}

POST(sys_fcntl)
{
   vg_assert(SUCCESS);
   if (ARG2 == VKI_F_DUPFD) {
      if (!ML_(fd_allowed)(RES, "fcntl(DUPFD)", tid, True)) {
         VG_(close)(RES);
         SET_STATUS_Failure( VKI_EMFILE );
      } else {
         if (VG_(clo_track_fds))
            ML_(record_fd_open_named)(tid, RES);
      }
   } else if (ARG2 == VKI_F_DUPFD_CLOEXEC) {
      if (!ML_(fd_allowed)(RES, "fcntl(DUPFD_CLOEXEC)", tid, True)) {
         VG_(close)(RES);
         SET_STATUS_Failure( VKI_EMFILE );
      } else {
         if (VG_(clo_track_fds))
            ML_(record_fd_open_named)(tid, RES);
      }
   }
}

PRE(sys_ioctl)
{
   UInt dir  = _VKI_IOC_DIR(ARG2);
   UInt size = _VKI_IOC_SIZE(ARG2);
   *flags |= SfMayBlock;
   PRINT("sys_ioctl ( %" FMT_REGWORD "u, 0x%" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "ioctl",
                 unsigned int, fd, unsigned int, request, unsigned long, arg);

/* On FreeBSD, ALL ioctl's are IOR/IOW encoded.  Just use the default decoder */
   if (SimHintiS(SimHint_lax_ioctls, VG_(clo_sim_hints))) {
      /*
      * Be very lax about ioctl handling; the only
      * assumption is that the size is correct. Doesn't
      * require the full buffer to be initialized when
      * writing.  Without this, using some device
      * drivers with a large number of strange ioctl
      * commands becomes very tiresome.
      */
   } else if (/* size == 0 || */ dir == _VKI_IOC_NONE) {
      static UWord unknown_ioctl[10];
      static Int moans = sizeof(unknown_ioctl) / sizeof(unknown_ioctl[0]);
      if (moans > 0 && !VG_(clo_xml)) {
         /* Check if have not already moaned for this request. */
         UInt i;
         for (i = 0; i < sizeof(unknown_ioctl)/sizeof(unknown_ioctl[0]); i++) {
            if (unknown_ioctl[i] == ARG2)
               break;
            if (unknown_ioctl[i] == 0) {
               unknown_ioctl[i] = ARG2;
               moans--;
               VG_(umsg)("Warning: noted but unhandled ioctl 0x%lx"
                         " with no size/direction hints.\n", ARG2);
               VG_(umsg)("   This could cause spurious value errors to appear.\n");
               VG_(umsg)("   See README_MISSING_SYSCALL_OR_IOCTL for "
                         "guidance on writing a proper wrapper.\n" );
               //VG_(get_and_pp_StackTrace)(tid, VG_(clo_backtrace_size));
               return;
            }
         }
      }
   } else {
     if ((dir & _VKI_IOC_WRITE) && size > 0)
        PRE_MEM_READ( "ioctl(generic)", ARG3, size);
     if ((dir & _VKI_IOC_READ) && size > 0)
        PRE_MEM_WRITE( "ioctl(generic)", ARG3, size);
   }

   // The block below is from Ryan Stone
   // https://bitbucket.org/rysto32/valgrind-freebsd/commits/5323c22be9f6c71a00e842c3ddfa1fa8a7feb279
   // however it drags in hundreds of lines of headers into vki-freebsd.h.
   // How stable are these structures? -> maintainability is a concern
   // Also there are no testcases for this.
   // Hence #if 0
#if 0
   /* Handle specific ioctls which pass structures which may have pointers to other
      buffers */
   switch (ARG2 /* request */) {
   case VKI_SIOCGIFMEDIA:
      if (ARG3) {
         struct vki_ifmediareq* imr = (struct vki_ifmediareq*)ARG3;
         if (imr->ifm_ulist) {
            PRE_MEM_WRITE("ioctl(SIOCGIFMEDIA).ifm_ulist",
                          (Addr)(imr->ifm_ulist), imr->ifm_count * sizeof(int));
         }
      }
      break;

   case VKI_PCIOCGETCONF:
      if (ARG3) {
         struct vki_pci_conf_io* pci = (struct vki_pci_conf_io*)ARG3;
         PRE_MEM_READ("ioctl(PCIOCGETCONF).patterns",
                      (Addr)(pci->patterns), pci->pat_buf_len);
         PRE_MEM_WRITE("ioctl(PCIOCGETCONF).matches",
                      (Addr)(pci->matches), pci->match_buf_len);
      }
      break;

   case VKI_CAMIOCOMMAND:
      if (ARG3) {
         union vki_ccb* ccb = (union vki_ccb*)ARG3;
         if (ccb->ccb_h.func_code == VKI_XPT_DEV_MATCH) {
             PRE_MEM_WRITE("ioctl(CAMIOCOMMAND:XPT_DEV_MATCH).matches",
                           (Addr)(ccb->cdm.matches), ccb->cdm.match_buf_len);
         } else if (ccb->ccb_h.func_code == VKI_XPT_SCSI_IO) {
            struct vki_ccb_scsiio* scsiio = (struct vki_ccb_scsiio*)ccb;
            if (scsiio->dxfer_len) {
               if ((scsiio->ccb_h.flags & VKI_CAM_DIR_MASK) == VKI_CAM_DIR_IN) {
                  PRE_MEM_WRITE("ioctl(CAMIOCOMMAND:XPT_SCSI_IO).data_ptr",
                                (Addr)(scsiio->data_ptr), scsiio->dxfer_len);
               } else if ((scsiio->ccb_h.flags & VKI_CAM_DIR_MASK) == VKI_CAM_DIR_OUT) {
                  PRE_MEM_READ("ioctl(CAMIOCOMMAND:XPT_SCSI_IO).data_ptr",
                               (Addr)(scsiio->data_ptr), scsiio->dxfer_len);
               }
            }
         } else if (ccb->ccb_h.func_code == VKI_XPT_GDEV_TYPE ||
                    ccb->ccb_h.func_code == VKI_XPT_PATH_INQ ||
                    ccb->ccb_h.func_code == VKI_XPT_GET_TRAN_SETTINGS) {
            // do nothing
         } else {
            VG_(message)(Vg_UserMsg,
                "Warning: unhandled ioctl CAMIOCOMMAND function 0x%lx\n",
                ccb->ccb_h.func_code);
         }
      }
      break;
   }
#endif
}

POST(sys_ioctl)
{
  UInt dir  = _VKI_IOC_DIR(ARG2);
  UInt size = _VKI_IOC_SIZE(ARG2);
  vg_assert(SUCCESS);
  if (size > 0 && (dir & _VKI_IOC_READ)
     && RES == 0 && ARG3 != (Addr)NULL)
     POST_MEM_WRITE(ARG3, size);

#if 0
   /* Handle specific ioctls which pass structures which may have pointers to other
      buffers */
   switch (ARG2 /* request */) {
   case VKI_SIOCGIFMEDIA:
      if (ARG3) {
         struct vki_ifmediareq* imr = (struct vki_ifmediareq*)ARG3;
         if (imr->ifm_ulist) {
            POST_MEM_WRITE((Addr)(imr->ifm_ulist), imr->ifm_count * sizeof(int));
         }
      }
      break;

   case VKI_PCIOCGETCONF:
      if (ARG3) {
         struct vki_pci_conf_io* pci = (struct vki_pci_conf_io*)ARG3;
         POST_MEM_WRITE((Addr)(pci->matches), pci->num_matches * sizeof(struct vki_pci_conf));
      }
      break;

   case VKI_CAMIOCOMMAND:
      if (ARG3) {
         union vki_ccb* ccb = (union vki_ccb*)ARG3;
         if (ccb->ccb_h.func_code == VKI_XPT_DEV_MATCH) {
             POST_MEM_WRITE((Addr)(ccb->cdm.matches), ccb->cdm.num_matches*sizeof(struct vki_dev_match_result));
         } else if (ccb->ccb_h.func_code == VKI_XPT_SCSI_IO) {
            struct vki_ccb_scsiio* scsiio = (struct vki_ccb_scsiio*)ccb;
            if (scsiio->dxfer_len) {
               if ((scsiio->ccb_h.flags & VKI_CAM_DIR_MASK) == VKI_CAM_DIR_IN) {
                  POST_MEM_WRITE((Addr)(scsiio->data_ptr), scsiio->dxfer_len);
               }
            }
         }
      }
      break;
   }
#endif
}

PRE(sys_ptrace)
{
   struct vki_ptrace_io_desc *io_desc;
   PRINT("sys_ptrace ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, 0x%" FMT_REGWORD "x, %" FMT_REGWORD "u)", ARG1, ARG2, ARG3, ARG4);

   PRE_REG_READ4(int, "ptrace", int, request, int, pid, char *, addr, int, data);

   switch (ARG1) {
      case VKI_PTRACE_TRACEME:
         break;
      case VKI_PTRACE_READ_I:
      case VKI_PTRACE_READ_D:
         break;

      case VKI_PTRACE_WRITE_I:
      case VKI_PTRACE_WRITE_D:
         break;

      case VKI_PTRACE_IO:
         PRE_MEM_READ("ptrace", ARG3, sizeof(struct vki_ptrace_io_desc));
         io_desc = (struct vki_ptrace_io_desc *)ARG3;
         switch (io_desc->piod_op) {
            case VKI_PIOD_READ_D:
            case VKI_PIOD_READ_I:
               PRE_MEM_WRITE( "ptrace", (UWord)io_desc->piod_addr, io_desc->piod_len);
               break;
            case VKI_PIOD_WRITE_D:
            case VKI_PIOD_WRITE_I:
               PRE_MEM_READ( "ptrace", (UWord)io_desc->piod_addr, io_desc->piod_len);
               break;
         }
         break;

      case VKI_PTRACE_CONTINUE:
         break;

      case VKI_PTRACE_STEP:
         break;

      case VKI_PTRACE_KILL:
         break;

      case VKI_PTRACE_ATTACH:
         break;

      case VKI_PTRACE_DETACH:
         break;

      case VKI_PTRACE_GETREGS:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(struct vki_reg_struct));
         break;

      case VKI_PTRACE_SETREGS:
         PRE_MEM_READ( "ptrace", ARG3, sizeof(struct vki_reg_struct));
         break;

      case VKI_PTRACE_GETFPREGS:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(struct vki_fpreg));
         break;

      case VKI_PTRACE_SETFPREGS:
         PRE_MEM_READ( "ptrace", ARG3, sizeof(struct vki_fpreg));
         break;

      case VKI_PTRACE_GETDBREGS:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(struct vki_dbreg));
         break;

      case VKI_PTRACE_SETDBREGS:
         PRE_MEM_READ( "ptrace", ARG3, sizeof(struct vki_dbreg));
         break;

      case VKI_PTRACE_LWPINFO:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(struct vki_ptrace_lwpinfo));
         break;

      case VKI_PTRACE_GETNUMLWPS:
         break;

      case VKI_PTRACE_GETLWPLIST:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(vki_lwpid_t) * ARG4);
         break;

      case VKI_PTRACE_SETSTEP:
         break;

      case VKI_PTRACE_CLEARSTEP:
         break;

      case VKI_PTRACE_SUSPEND:
         break;

      case VKI_PTRACE_RESUME:
         break;

      case VKI_PTRACE_TO_SCE:
         break;

      case VKI_PTRACE_TO_SCX:
         break;

      case VKI_PTRACE_SYSCALL:
         break;

      case VKI_PTRACE_VM_TIMESTAMP:
         break;

      case VKI_PTRACE_VM_ENTRY:
         PRE_MEM_WRITE( "ptrace", ARG3, sizeof(struct vki_ptrace_vm_entry));
         break;
   }
}

POST(sys_ptrace)
{
   struct vki_ptrace_io_desc *io_desc;

   switch (ARG1) {
      case VKI_PTRACE_TRACEME:
         break;
      case VKI_PTRACE_READ_I:
      case VKI_PTRACE_READ_D:
         break;

      case VKI_PTRACE_WRITE_I:
      case VKI_PTRACE_WRITE_D:
         break;

      case VKI_PTRACE_IO:
         io_desc = (struct vki_ptrace_io_desc *)ARG3;
         switch (io_desc->piod_op) {
            case VKI_PIOD_READ_D:
            case VKI_PIOD_READ_I:
               if ((Word)RES != -1)
                  POST_MEM_WRITE((UWord)io_desc->piod_addr, io_desc->piod_len);
               break;
            case VKI_PIOD_WRITE_D:
            case VKI_PIOD_WRITE_I:
               break;
         }
         break;

      case VKI_PTRACE_CONTINUE:
         break;

      case VKI_PTRACE_STEP:
         break;

      case VKI_PTRACE_KILL:
         break;

      case VKI_PTRACE_ATTACH:
         break;

      case VKI_PTRACE_DETACH:
         break;

      case VKI_PTRACE_GETREGS:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(struct vki_reg_struct));
         break;

      case VKI_PTRACE_SETREGS:
         break;

      case VKI_PTRACE_GETFPREGS:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(struct vki_fpreg));
         break;

      case VKI_PTRACE_SETFPREGS:
         break;

      case VKI_PTRACE_GETDBREGS:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(struct vki_dbreg));
         break;

      case VKI_PTRACE_SETDBREGS:
         break;

      case VKI_PTRACE_LWPINFO:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(struct vki_ptrace_lwpinfo));
         break;

      case VKI_PTRACE_GETNUMLWPS:
         break;

      case VKI_PTRACE_GETLWPLIST:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(vki_lwpid_t) * RES);
         break;

      case VKI_PTRACE_SETSTEP:
         break;

      case VKI_PTRACE_CLEARSTEP:
         break;

      case VKI_PTRACE_SUSPEND:
         break;

      case VKI_PTRACE_RESUME:
         break;

      case VKI_PTRACE_TO_SCE:
         break;

      case VKI_PTRACE_TO_SCX:
         break;

      case VKI_PTRACE_SYSCALL:
         break;

      case VKI_PTRACE_VM_TIMESTAMP:
         break;

      case VKI_PTRACE_VM_ENTRY:
         if ((Word)RES != -1)
            POST_MEM_WRITE(ARG3, sizeof(struct vki_ptrace_vm_entry));
         break;
   }
}

PRE(sys_cpuset_setaffinity)
{

    PRINT("sys_cpuset_setaffinity ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1, ARG2,
        ARG3, ARG4, ARG5);
    PRE_REG_READ5(int, "cpuset_setaffinity",
        int, level, int, which, long, id,
        size_t, setsize, void *, mask);
    PRE_MEM_READ("cpuset_setaffinity", ARG5, ARG4);
}

PRE(sys_cpuset_getaffinity)
{
    PRINT("sys_cpuset_getaffinity ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1, ARG2,
        ARG3, ARG4, ARG5);
    PRE_REG_READ5(int, "cpuset_getaffinity",
        int, level, int, which, long, id,
        size_t, setsize, void *, mask);
    PRE_MEM_WRITE("cpuset_getaffinity", ARG5, ARG4);
}

POST(sys_cpuset_getaffinity)
{
    vg_assert(SUCCESS);
    if (RES == 0)
        POST_MEM_WRITE( ARG5, ARG4 );
}

struct pselect_adjusted_sigset {
    vki_sigset_t adjusted_ss;
};

/*
int
pselect(int nfds, fd_set * restrict readfds, fd_set * restrict writefds,
    fd_set * restrict exceptfds,
    const struct timespec * restrict timeout,
    const sigset_t * restrict newsigmask);
*/
PRE(sys_pselect)
{
   *flags |= SfMayBlock | SfPostOnFail;
   PRINT("sys_pselect ( %ld, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %#"
         FMT_REGWORD "x, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         SARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   PRE_REG_READ6(long, "pselect",
                 int, n, vki_fd_set *, readfds, vki_fd_set *, writefds,
                 vki_fd_set *, exceptfds, struct vki_timespec *, timeout,
                 void *, sig);
   // XXX: this possibly understates how much memory is read.
   if (ARG2 != 0)
      PRE_MEM_READ( "pselect(readfds)",   
             ARG2, ARG1/8 /* __FD_SETSIZE/8 */ );
   if (ARG3 != 0)
      PRE_MEM_READ( "pselect(writefds)",  
             ARG3, ARG1/8 /* __FD_SETSIZE/8 */ );
   if (ARG4 != 0)
      PRE_MEM_READ( "pselect(exceptfds)", 
             ARG4, ARG1/8 /* __FD_SETSIZE/8 */ );
   if (ARG5 != 0)
      PRE_MEM_READ( "pselect(timeout)", ARG5, sizeof(struct vki_timeval) );
   if (ARG6 != 0) {
      vki_sigset_t *ss = (vki_sigset_t *)(Addr)ARG6;
      PRE_MEM_READ( "pselect(sig)", ARG6, sizeof(*ss) );
      if (!ML_(safe_to_deref)(ss, sizeof(*ss))) {
         ARG6 = 1; /* Something recognisable to POST() hook. */
      } else {
         vki_sigset_t *adjss;
         adjss = VG_(malloc)("syswrap.pselect.1", sizeof(*adjss));
         *adjss = *ss;
         VG_(sanitize_client_sigmask)(adjss);
         ARG6 = (Addr)adjss;
      }
   }
}

POST(sys_pselect)
{
   if (ARG6 != 0 && ARG6 != 1) {
       VG_(free)((struct pselect_adjusted_sigset *)(Addr)ARG6);
   }
}

// note extra 1st argument for the internal function which is not present
// in the public interface
// int __cap_rights_get(int version, int fd, cap_rights_t *rights);
PRE(sys_cap_rights_get)
{
   PRINT("sys_cap_rights_get ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "cap_rights_get", int, version, int, fd, vki_cap_rights_t*, rights);
   PRE_MEM_WRITE("cap_rights_get(rights)", ARG3, sizeof(vki_cap_rights_t));
}

POST(sys_cap_rights_get)
{
   POST_MEM_WRITE(ARG2, sizeof(vki_cap_rights_t));
}

PRE(sys_cap_enter)
{
   PRINT("%s", "sys_cap_enter ( )");
   PRE_REG_READ0(long, "cap_enter");
   static Bool warning_given = False;
   if (!warning_given) {
      warning_given = True;
      capabiltyMode = True;
      VG_(umsg)(
         "WARNING: Valgrind may not operate correctly in capability mode.\n"
         "         Please consider disabling capability by using the RUNNING_ON_VALGRIND mechanism.\n"
         "         See http://valgrind.org/docs/manual/manual-core-adv.html#manual-core-adv.clientreq\n");
   }
}

// int cap_getmode(u_int *modep);
PRE(sys_cap_getmode)
{
   PRINT("sys_cap_getmode ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(int, "cap_getmode", u_int*, modep);
   PRE_MEM_WRITE("cap_getmode(modep)", ARG1, sizeof(u_int));
}

POST(sys_cap_getmode)
{
   POST_MEM_WRITE(ARG1, sizeof(u_int));
}

static vki_sigset_t pdfork_saved_mask;

// pid_t pdfork(int *fdp, int flags);
PRE(sys_pdfork)
{
    Bool is_child;
    Int child_pid;
    vki_sigset_t mask;

   PRINT("sys_pdfork ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1, ARG2);
   PRE_REG_READ2(long, "pdfork", int*, fdp, int, flags);

   /* Block all signals during fork, so that we can fix things up in
      the child without being interrupted. */
   VG_(sigfillset)(&mask);
   VG_(sigprocmask)(VKI_SIG_SETMASK, &mask, &pdfork_saved_mask);

   VG_(do_atfork_pre)(tid);

   SET_STATUS_from_SysRes( VG_(do_syscall2)(__NR_pdfork, ARG1, ARG2) );

   if (!SUCCESS) return;

   // RES is 0 for child, non-0 (the child's PID) for parent.
   is_child = ( RES == 0 ? True : False );
   child_pid = ( is_child ? -1 : RES );

   if (is_child)
   {
      VG_(do_atfork_child)(tid);

      /* restore signal mask */
      VG_(sigprocmask)(VKI_SIG_SETMASK, &pdfork_saved_mask, NULL);
   } else {
      VG_(do_atfork_parent)(tid);

      PRINT("   fork: process %d created child %d\n", VG_(getpid)(), child_pid);

      /* restore signal mask */
      VG_(sigprocmask)(VKI_SIG_SETMASK, &pdfork_saved_mask, NULL);
   }

   if (ARG1)
   {
      PRE_MEM_WRITE( "pdfork(fdp)", ARG1, sizeof(int) );
   }
}

POST(sys_pdfork)
{
    if (ARG1)
    {
        POST_MEM_WRITE( ARG1, sizeof(int) );
    }
}

//int pdkill(int fd, int signum)
PRE(sys_pdkill)
{
   PRINT("sys_pdkill ( %" FMT_REGWORD "u, %" FMT_REGWORD "d )", ARG1, SARG2);
   PRE_REG_READ2(long, "pdkill", int, ARG1, int, ARG2);

   if (!ML_(client_signal_OK)(ARG2)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   /* If we're sending SIGKILL, check to see if the target is one of
      our threads and handle it specially. */
   if (ARG2 == VKI_SIGKILL && ML_(do_sigkill)(ARG1, -1))
      SET_STATUS_Success(0);

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "pdkill: sent signal %ld to fd %ld\n",
           SARG2, SARG1);

   /* This kill might have given us a pending signal.  Ask for a check once
      the syscall is done. */
   *flags |= SfPollAfter;

}

// int pdgetpid(int fd, pid_t *pidp);
PRE(sys_pdgetpid)
{
   PRINT("pdgetpid ( %" FMT_REGWORD "d, %#lx )", SARG1, ARG2);
   PRE_REG_READ2(int, "pdgetpid",
                 int, fd, pid_t*, pidp);
   PRE_MEM_WRITE( "pdgetpid(pidp))", ARG2, sizeof(vki_pid_t) );
}

POST(sys_pdgetpid)
{
   POST_MEM_WRITE( ARG2, sizeof(vki_pid_t) );
}

//int cap_rights_limit(int fd, const cap_rights_t *rights);
PRE(sys_cap_rights_limit)
{
   PRINT("cap_rights_limit ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x )", SARG1, ARG2);
   PRE_REG_READ2(int, "cap_rights_limit",
                 int, fd, const cap_rights_t *, rights);
   PRE_MEM_READ( "cap_rights_limit(rights)", ARG2, sizeof(struct vki_cap_rights) );
}

// int cap_ioctls_limit(int fd, const unsigned long *cmds, size_t ncmds);
PRE(sys_cap_ioctls_limit)
{
   PRINT("cap_ioctls_limit ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "cap_ioctls_limit",
                 int, fd, unsigned long*, rights, vki_size_t, ncmds);
   if (ARG3 <= 256 )
   {
       PRE_MEM_READ( "cap_ioctls_limit(cmds))", ARG2, ARG3*sizeof(long) );
   }
}

//int cap_fcntls_limit(int fd, uint32_t fcntlrights);
PRE(sys_cap_fcntls_limit)
{
   PRINT("cap_fcntls_limit ( %" FMT_REGWORD "d, %" FMT_REGWORD "u )", SARG1, ARG2);
   PRE_REG_READ2(long, "cap_fcntls_limit",
                 int, fd, vki_uint32_t, fcntlrights);
}

#if (FREEBSD_VERS >= FREEBSD_12)

PRE(sys_fstat)
{
   PRINT("sys_fstat ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fstat", unsigned long, fd, struct stat *, buf);
   PRE_MEM_WRITE( "fstat(buf)", ARG2, sizeof(struct vki_stat) );
}

POST(sys_fstat)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat) );
}

// ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep);
PRE(sys_getdirentries)
{
   *flags |= SfMayBlock;
   PRINT("sys_getdirentries ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", SARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(ssize_t, "getdirentries",
                 int, fd, char *, buf,
                 size_t, nbytes,
                 off_t, basep);
   PRE_MEM_WRITE( "getdirentries(buf)", ARG2, ARG3 );
   if (ARG4)
      PRE_MEM_WRITE("getdirentries(buf)", ARG4, sizeof (vki_off_t));
}

POST(sys_getdirentries)
{
   vg_assert(SUCCESS);
   if (RES > 0) {
      POST_MEM_WRITE( ARG2, RES );
      if ( ARG4 != 0 )
         POST_MEM_WRITE( ARG4, sizeof (vki_off_t));
   }
}

PRE(sys_statfs)
{
   PRINT("sys_statfs ( %#" FMT_REGWORD "x(%s), %#" FMT_REGWORD "x )",ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long, "statfs", const char *, path, struct statfs *, buf);
   PRE_MEM_RASCIIZ( "statfs(path)", ARG1 );
   PRE_MEM_WRITE( "statfs(buf)", ARG2, sizeof(struct vki_statfs) );
}

POST(sys_statfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_statfs) );
}

PRE(sys_fstatfs)
{
   PRINT("sys_fstatfs ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fstatfs",
                 unsigned int, fd, struct statfs *, buf);
   PRE_MEM_WRITE( "fstatfs(buf)", ARG2, sizeof(struct vki_statfs) );
}

POST(sys_fstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_statfs) );
}

PRE(sys_getfsstat)
{
   PRINT("sys_getfsstat ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getfsstat", struct vki_statfs *, buf, long, len, int, flags);
   PRE_MEM_WRITE( "getfsstat(buf)", ARG1, ARG2 );
}

POST(sys_getfsstat)
{
   vg_assert(SUCCESS);
   if ((Word)RES != -1) {
      POST_MEM_WRITE( ARG1, RES * sizeof(struct vki_statfs) );
   }
}

PRE(sys_fhstatfs)
{
   PRINT("sys_fhstatfs ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",ARG1,ARG2);
   PRE_REG_READ2(long, "fhstatfs",
                 struct fhandle *, fhp, struct statfs *, buf);
   PRE_MEM_READ( "fhstatfs(fhp)", ARG1, sizeof(struct vki_fhandle) );
   PRE_MEM_WRITE( "fhstatfs(buf)", ARG2, sizeof(struct vki_statfs) );
}

POST(sys_fhstatfs)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_statfs) );
}


// ssize_t  getrandom(void *buf, size_t buflen, unsigned int flags);
PRE(sys_getrandom)
{
   PRINT("sys_getrandom ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u )" , ARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "getrandom",
                 char *, buf, vki_size_t, count, unsigned int, flags);
   PRE_MEM_WRITE( "getrandom(cpu)", ARG1, ARG2 );
}

POST(sys_getrandom)
{
   POST_MEM_WRITE( ARG1, ARG2 );
}

// int getfhat(int fd, const char *path, fhandle_t *fhp, int flag);
PRE(sys_getfhat)
{
   PRINT("sys_getfhat ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %" FMT_REGWORD "x, %" FMT_REGWORD "d ", SARG1, ARG2, ARG3, SARG4);
   PRE_REG_READ4(int, "getfh", int, fd, const char*, path, vki_fhandle_t*, fhp, int, flag);
   PRE_MEM_RASCIIZ( "getfhat(path)", ARG2 );
   PRE_MEM_WRITE("getfhat(fhp)", ARG3, sizeof(vki_fhandle_t));
}

POST(sys_getfhat)
{
   POST_MEM_WRITE(ARG3, sizeof(vki_fhandle_t));
}

#endif

#undef PRE
#undef POST

const SyscallTableEntry ML_(syscall_table)[] = {
   // syscall (handled specially)                       // 0
   BSDX_(__NR_exit,             sys_exit),              // 1
   BSDX_(__NR_fork,             sys_fork),              // 2
   GENXY(__NR_read,             sys_read),              // 3

   GENX_(__NR_write,            sys_write),             // 4
   GENXY(__NR_open,             sys_open),              // 5
   GENXY(__NR_close,            sys_close),             // 6
   GENXY(__NR_wait4,            sys_wait4),             // 7

   // 4.3 creat                                            8
   GENX_(__NR_link,             sys_link),              // 9
   GENX_(__NR_unlink,           sys_unlink),            // 10
   // obsol execv                                          11

   GENX_(__NR_chdir,            sys_chdir),             // 12
   GENX_(__NR_fchdir,           sys_fchdir),            // 13
   GENX_(__NR_freebsd11_mknod,  sys_mknod),             // 14
   GENX_(__NR_chmod,            sys_chmod),             // 15

   GENX_(__NR_chown,            sys_chown),             // 16
   GENX_(__NR_break,            sys_brk),               // 17
   // freebsd 4 getfsstat                                  18
   // 4.3 lseek                                            19

   GENX_(__NR_getpid,           sys_getpid),            // 20
   BSDX_(__NR_mount,            sys_mount),             // 21
   BSDX_(__NR_unmount,          sys_unmount),           // 22
   GENX_(__NR_setuid,           sys_setuid),            // 23

   GENX_(__NR_getuid,           sys_getuid),            // 24
   GENX_(__NR_geteuid,          sys_geteuid),           // 25
   BSDXY(__NR_ptrace,           sys_ptrace),            // 26
   BSDXY(__NR_recvmsg,          sys_recvmsg),           // 27

   BSDX_(__NR_sendmsg,          sys_sendmsg),           // 28
   BSDXY(__NR_recvfrom,         sys_recvfrom),          // 29
   BSDXY(__NR_accept,           sys_accept),            // 30
   BSDXY(__NR_getpeername,      sys_getpeername),       // 31

   BSDXY(__NR_getsockname,      sys_getsockname),       // 32
   GENX_(__NR_access,           sys_access),            // 33
   BSDX_(__NR_chflags,          sys_chflags),           // 34
   BSDX_(__NR_fchflags,         sys_fchflags),          // 35

   GENX_(__NR_sync,             sys_sync),              // 36
   GENX_(__NR_kill,             sys_kill),              // 37
   // 4.3 stat                                             38
   GENX_(__NR_getppid,          sys_getppid),           // 39

   // 4.3 lstat                                            40
   GENXY(__NR_dup,              sys_dup),               // 41

   BSDXY(__NR_freebsd10_pipe,   sys_pipe),              // 42
   GENX_(__NR_getegid,          sys_getegid),           // 43

   GENX_(__NR_profil,           sys_ni_syscall),        // 44
   GENX_(__NR_ktrace,           sys_ni_syscall),        // 45
   // 4.3 sigaction                                        46
   GENX_(__NR_getgid,           sys_getgid),            // 47

   // 4.3 sigaction (int sigset)                           48
   BSDXY(__NR_getlogin,         sys_getlogin),          // 49
   BSDX_(__NR_setlogin,         sys_setlogin),          // 50
   GENX_(__NR_acct,             sys_acct),              // 51

   // 4.3 sigpending                                       52
   GENXY(__NR_sigaltstack,      sys_sigaltstack),       // 53
   BSDXY(__NR_ioctl,            sys_ioctl),             // 54
// BSDX_(__NR_reboot,           sys_reboot),            // 55

   BSDX_(__NR_revoke,           sys_revoke),            // 56
   GENX_(__NR_symlink,          sys_symlink),           // 57
   GENX_(__NR_readlink,         sys_readlink),          // 58
   GENX_(__NR_execve,           sys_execve),            // 59

   GENX_(__NR_umask,            sys_umask),             // 60
   GENX_(__NR_chroot,           sys_chroot),            // 61
   // 4.3 fstat                                            62
   // 4.3 getgerninfo                                      63

   // 4.3 getpagesize                                      64
   GENX_(__NR_msync,            sys_msync),             // 65
   BSDX_(__NR_vfork,            sys_fork),              // 66
   // obsol vread                                          67

   // obsol vwrite                                         68
   BSDX_(__NR_sbrk,             sys_sbrk),              // 69
   // no implemented sstk,                              // 70
   // 4.3 mmap                                             71

   // 4.2 vadvise                                          72
   GENXY(__NR_munmap,           sys_munmap),            // 73
   GENXY(__NR_mprotect,         sys_mprotect),          // 74
   GENX_(__NR_madvise,          sys_madvise),           // 75

   // obsol vhangup                                        76
   // obsol vlimit                                         77
   GENXY(__NR_mincore,          sys_mincore),           // 78
   GENXY(__NR_getgroups,        sys_getgroups),         // 79

   GENX_(__NR_setgroups,        sys_setgroups),         // 80
   GENX_(__NR_getpgrp,          sys_getpgrp),           // 81
   GENX_(__NR_setpgid,          sys_setpgid),           // 82
   GENXY(__NR_setitimer,        sys_setitimer),         // 83

   // 4.3 wait                                             84
   BSDX_(__NR_swapon,           sys_swapon),            // 85
   GENXY(__NR_getitimer,        sys_getitimer),         // 86
   // 4.3 gethostname                                      87

   // 4.3 sethostname                                      88
   BSDX_(__NR_getdtablesize,    sys_getdtablesize),     // 89
   GENXY(__NR_dup2,             sys_dup2),              // 90
   // unimpl getdopt                                       91

   BSDXY(__NR_fcntl,            sys_fcntl),             // 92
   GENX_(__NR_select,           sys_select),            // 93
   // unimpl setdopt                                       94
   GENX_(__NR_fsync,            sys_fsync),             // 95

   GENX_(__NR_setpriority,      sys_setpriority),       // 96
   BSDXY(__NR_socket,           sys_socket),            // 97
   BSDX_(__NR_connect,          sys_connect),           // 98
   // 4.3 accept                                           99

   GENX_(__NR_getpriority,      sys_getpriority),       // 100
   // 4.3 send                                             101
   // 4.3 recv                                             102
   // 4.3 sigreturn                                        103

   BSDX_(__NR_bind,             sys_bind),              // 104
   BSDX_(__NR_setsockopt,       sys_setsockopt),        // 105
   BSDX_(__NR_listen,           sys_listen),            // 106
   // obsol vtimes                                         107

   // 4.3 sigvec                                           108
   // 4.3 sigblock                                         109
   // 4.3 sigsetmask                                       110
   // 4.3 sigsuspend                                       111

   // 4.3 sigstack                                         112
   // 4.3 recvmsg                                          113
   // 4.3 sendmsg                                          114
   // 4.3 vtrace                                           115

   GENXY(__NR_gettimeofday,     sys_gettimeofday),      // 116
   GENXY(__NR_getrusage,        sys_getrusage),         // 117
   BSDXY(__NR_getsockopt,       sys_getsockopt),        // 118
   // unimpl resuba                                        119

   GENXY(__NR_readv,            sys_readv),             // 120
   GENX_(__NR_writev,           sys_writev),            // 121
   GENX_(__NR_settimeofday,     sys_settimeofday),      // 122
   GENX_(__NR_fchown,           sys_fchown),            // 123

   GENX_(__NR_fchmod,           sys_fchmod),            // 124
   // 4.3 recvfrom                                         125
   GENX_(__NR_setreuid,         sys_setreuid),          // 126
   GENX_(__NR_setregid,         sys_setregid),          // 127

   GENX_(__NR_rename,           sys_rename),            // 128
   // 4.3 truncate                                         129
   // 4.3 ftruncate                                        130
   GENX_(__NR_flock,            sys_flock),             // 131

   BSDX_(__NR_mkfifo,           sys_mkfifo),            // 132
   BSDX_(__NR_sendto,           sys_sendto),            // 133
   BSDX_(__NR_shutdown,         sys_shutdown),          // 134
   BSDXY(__NR_socketpair,       sys_socketpair),        // 135

   GENX_(__NR_mkdir,            sys_mkdir),             // 136
   GENX_(__NR_rmdir,            sys_rmdir),             // 137
   GENX_(__NR_utimes,           sys_utimes),            // 138
   // 4.2 sigreturn                                        139

   BSDXY(__NR_adjtime,          sys_adjtime),           // 140
   // 4.3 getpeername                                      141
   // 4.3 gethostid                                        142
   // 4.3 sethostid                                        143

   // 4.3 getrlimit`                                       144
   // 4.3 setrlimit                                        145
   // 4.3 killpg                                           146
   GENX_(__NR_setsid,           sys_setsid),            // 147

   BSDX_(__NR_quotactl,         sys_quotactl),          // 148
   // 4.3 quota                                            149
   // 4.3 getsockname                                      150
   // bsd/os sem_lock                                      151

   // bsd/os sem_wakeup                                    152
   // bsd/os asyncdaemon                                   153

   // no idea what the following syscall does
   // SYS_nlm_syscall                                      154

   // a somewhat complicated NFS API
   // takes a flag and a void* that can point to one of
   // three different types of struct depending on the flag
   // BSDXY(__NR_nfssvc,        sys_nfssvc),            // 155

   // 4.3 getdirentries                                    156
   // freebsd 4 statfs                                     157
   // freebsd 4 fstatfs                                    158
   // nosys                                                159

   BSDXY(__NR_lgetfh,           sys_lgetfh),            // 160
   BSDXY(__NR_getfh,            sys_getfh),             // 161
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDXY(__NR_freebsd4_getdomainname, sys_freebsd4_getdomainname), // 162
   BSDX_(__NR_freebsd4_setdomainname, sys_freebsd4_setdomainname), // 163
   BSDXY(__NR_freebsd4_uname,   sys_freebsd4_uname),    // 164
#endif
   BSDXY(__NR_sysarch,          sys_sysarch),           // 165
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
#if (FREEBSD_VERS >= FREEBSD_12)
   BSDXY(__NR_freebsd11_getdirentries, sys_freebsd11_getdirentries), // 196
#else
   BSDXY(__NR_getdirentries,    sys_getdirentries),     // 196
#endif
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDX_(__NR_freebsd6_mmap,    sys_freebsd6_mmap),     // 197
#endif
   // __syscall (handled specially)                     // 198
#if (FREEBSD_VERS <= FREEBSD_10)
   BSDX_(__NR_freebsd6_lseek,    sys_freebsd6_lseek),   // 199
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

   BSDXY(__NR_freebsd7_msgctl,  sys_freebsd7_msgctl),   // 224
   BSDX_(__NR_msgget,           sys_msgget),            // 225
   BSDX_(__NR_msgsnd,           sys_msgsnd),            // 226
   BSDXY(__NR_msgrcv,           sys_msgrcv),            // 227

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
   BSDX_(__NR_mkfifoat,         sys_mkfifoat),          // 497
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
   BSDXY(__NR_msgctl,           sys_msgctl),            // 511
   BSDXY(__NR_shmctl,           sys_shmctl),            // 512
    // lpathconf                                           513
    /* 514 is obsolete cap_new */
    BSDXY(__NR___cap_rights_get, sys_cap_rights_get),   // 515
    BSDX_(__NR_cap_enter,       sys_cap_enter),         // 516
    BSDXY(__NR_cap_getmode,     sys_cap_getmode),       // 517
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
    BSDX_(__NR_cap_rights_limit, sys_cap_rights_limit), // 533
    BSDX_(__NR_cap_ioctls_limit, sys_cap_ioctls_limit), // 534
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


    /* 548 is obsolete numa_getaffinity */
    /* 549 is obsolete numa_setaffinity */
    // fdatasync                                           550

#endif // FREEBSD_VERS >= FREEBSD_11

#if (FREEBSD_VERS >= FREEBSD_12)
   BSDXY(__NR_fstat,            sys_fstat),             // 551
    // fstatat                                             552
    // fhstat                                              553
    BSDXY(__NR_getdirentries,   sys_getdirentries),     // 554
    BSDXY(__NR_statfs,          sys_statfs),            // 555
    BSDXY(__NR_fstatfs,         sys_fstatfs),           // 556
    BSDXY(__NR_getfsstat,       sys_getfsstat),         // 557
    BSDXY(__NR_fhstatfs,        sys_fhstatfs),          // 558
    // mknodat                                             559
    // kevent                                              560
    // cpuset_getdomain                                    561
    // cpuset_setdomain                                    562
   BSDXY(__NR_getrandom,        sys_getrandom),         // 563
   BSDXY(__NR_getfhat,          sys_getfhat),           // 564
    // fhlink                                              565
    // fhlinkat                                            566
    // fhreadlink                                          567
#endif // FREEBSD_VERS >= FREEBSD_12
   BSDX_(__NR_fake_sigreturn,   sys_fake_sigreturn),    // 1000, fake sigreturn

};

const UInt ML_(syscall_table_size) =
        sizeof(ML_(syscall_table)) / sizeof(ML_(syscall_table)[0]);

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

#endif // defined(VGO_freebsd)
