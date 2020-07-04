
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.        syswrap-x86-freebsd.c ---*/
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

#if defined(VGP_x86_freebsd)

/* TODO/FIXME jrs 20050207: assignments to the syscall return result
   in interrupted_syscall() need to be reviewed.  They don't seem
   to assign the shadow state.
*/

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_libcsetjmp.h"    // to keep _threadstate.h happy
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_machine.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"      // For VG_(sigframe_destroy)()
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "pub_core_stacks.h"        // VG_(register_stack)

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"    /* for decls of generic wrappers */
#include "priv_syswrap-freebsd.h"      /* for decls of linux-ish wrappers */
#include "priv_syswrap-main.h"

/* ---------------------------------------------------------------------
   clone() handling
   ------------------------------------------------------------------ */

/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f.*/
__attribute__((noreturn))
void ML_(call_on_new_stack_0_1) ( Addr stack,
			          Addr retaddr,
			          void (*f)(Word),
                                  Word arg1 );
//  4(%esp) == stack
//  8(%esp) == retaddr
// 12(%esp) == f
// 16(%esp) == arg1
asm(
".text\n"
".globl vgModuleLocal_call_on_new_stack_0_1\n"
"vgModuleLocal_call_on_new_stack_0_1:\n"
"   movl %esp, %esi\n"     // remember old stack pointer
"   movl 4(%esi), %esp\n"  // set stack
"   pushl 16(%esi)\n"      // arg1 to stack
"   pushl  8(%esi)\n"      // retaddr to stack
"   pushl 12(%esi)\n"      // f to stack
"   movl $0, %eax\n"       // zero all GP regs
"   movl $0, %ebx\n"
"   movl $0, %ecx\n"
"   movl $0, %edx\n"
"   movl $0, %esi\n"
"   movl $0, %edi\n"
"   movl $0, %ebp\n"
"   ret\n"                 // jump to f
"   ud2\n"                 // should never get here
".previous\n"
);


#if 0
/*
        Perform a rfork system call.  rfork is strange because it has
        fork()-like return-twice semantics, so it needs special
        handling here.

        Upon entry, we have:

            int (fn)(void*)     in  0+FSZ(%esp)
            void* child_stack   in  4+FSZ(%esp)
            int flags           in  8+FSZ(%esp)
            void* arg           in 12+FSZ(%esp)
            pid_t* child_tid    in 16+FSZ(%esp)
            pid_t* parent_tid   in 20+FSZ(%esp)
            void* tls_ptr       in 24+FSZ(%esp)

        System call requires:

            int    $__NR_clone  in %eax
            int    flags        in %ebx
            void*  child_stack  in %ecx
            pid_t* parent_tid   in %edx
            pid_t* child_tid    in %edi
            void*  tls_ptr      in %esi

	Returns an Int encoded in the linux-x86 way, not a SysRes.
 */
#define FSZ               "4+4+4+4" /* frame size = retaddr+ebx+edi+esi */
#define __NR_CLONE        VG_STRINGIFY(__NR_clone)
#define __NR_EXIT         VG_STRINGIFY(__NR_exit)

extern
Int do_syscall_clone_x86_freebsd ( Word (*fn)(void *), 
                                 void* stack, 
                                 Int   flags, 
                                 void* arg,
                                 Int*  child_tid, 
                                 Int*  parent_tid, 
                                 vki_modify_ldt_t * );
asm(
".text\n"
"do_syscall_clone_x86_freebsd:\n"
"        push    %ebx\n"
"        push    %edi\n"
"        push    %esi\n"

         /* set up child stack with function and arg */
"        movl     4+"FSZ"(%esp), %ecx\n"    /* syscall arg2: child stack */
"        movl    12+"FSZ"(%esp), %ebx\n"    /* fn arg */
"        movl     0+"FSZ"(%esp), %eax\n"    /* fn */
"        lea     -8(%ecx), %ecx\n"          /* make space on stack */
"        movl    %ebx, 4(%ecx)\n"           /*   fn arg */
"        movl    %eax, 0(%ecx)\n"           /*   fn */

         /* get other args to clone */
"        movl     8+"FSZ"(%esp), %ebx\n"    /* syscall arg1: flags */
"        movl    20+"FSZ"(%esp), %edx\n"    /* syscall arg3: parent tid * */
"        movl    16+"FSZ"(%esp), %edi\n"    /* syscall arg5: child tid * */
"        movl    24+"FSZ"(%esp), %esi\n"    /* syscall arg4: tls_ptr * */
"        movl    $"__NR_CLONE", %eax\n"
"        int     $0x80\n"                   /* clone() */
"        testl   %eax, %eax\n"              /* child if retval == 0 */
"        jnz     1f\n"

         /* CHILD - call thread function */
"        popl    %eax\n"
"        call    *%eax\n"                   /* call fn */

         /* exit with result */
"        movl    %eax, %ebx\n"              /* arg1: return value from fn */
"        movl    $"__NR_EXIT", %eax\n"
"        int     $0x80\n"

         /* Hm, exit returned */
"        ud2\n"

"1:\n"   /* PARENT or ERROR */
"        pop     %esi\n"
"        pop     %edi\n"
"        pop     %ebx\n"
"        ret\n"
".previous\n"
);

#undef FSZ
#undef __NR_CLONE
#undef __NR_EXIT


// forward declarations
static void setup_child ( ThreadArchState*, ThreadArchState*, Bool );

/* 
   When a client clones, we need to keep track of the new thread.  This means:
   1. allocate a ThreadId+ThreadState+stack for the the thread

   2. initialize the thread's new VCPU state

   3. create the thread using the same args as the client requested,
   but using the scheduler entrypoint for EIP, and a separate stack
   for ESP.
 */
static SysRes do_rfork ( ThreadId ptid, 
                         UInt flags)
{
   static const Bool debug = False;

   Addr         esp;
   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(ptid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   UWord*       stack;
   NSegment const* seg;
   SysRes       res;
   Int          eax;
   vki_sigset_t blockall, savedmask;

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(ptid));
   vg_assert(VG_(is_valid_tid)(ctid));

   stack = (UWord*)ML_(allocstack)(ctid);
   if (stack == NULL) {
      res = VG_(mk_SysRes_Error)( VKI_ENOMEM );
      goto out;
   }

   /* Copy register state

      Both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL esp for the new thread, then
      it actually gets a copy of the parent's esp.
   */
   /* Note: the clone call done by the Quadrics Elan3 driver specifies
      clone flags of 0xF00, and it seems to rely on the assumption
      that the child inherits a copy of the parent's GDT.  
      setup_child takes care of setting that up. */
   setup_child( &ctst->arch, &ptst->arch, True );

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_EAX = 0;

   /* Assume linuxthreads port storing its intended stack in %esi */
   esp = ctst->arch.vex.guest_ESI;

   ctst->os_state.parent = ptid;

   /* inherit signal mask */
   ctst->sig_mask     = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* We don't really know where the client stack is, because its
      allocated by the client.  The best we can do is look at the
      memory mappings and try to derive some useful information.  We
      assume that esp starts near its highest possible value, and can
      only go down to the start of the mmaped segment. */
   seg = VG_(am_find_nsegment)((Addr)esp);
   if (seg && seg->kind != SkResvn) {
      ctst->client_stack_highest_byte = (Addr)VG_PGROUNDUP(esp);
      ctst->client_stack_szB = ctst->client_stack_highest_byte - seg->start;

      ctst->os_state.stk_id = VG_(register_stack)(seg->start, ctst->client_stack_highest_byte);

      if (debug)
	 VG_(printf)("tid %d: guessed client stack range %#lx-%#lx\n",
		     ctid, seg->start, VG_PGROUNDUP(esp));
   } else {
      VG_(message)(Vg_UserMsg, "!? New thread %d starts with ESP(%#lx) unmapped\n",
		   ctid, esp);
      ctst->client_stack_szB  = 0;
   }

   /* Assume the clone will succeed, and tell any tool that wants to
      know that this thread has come into existence.  We cannot defer
      it beyond this point because sys_set_thread_area, just below,
      causes tCheck to assert by making references to the new ThreadId
      if we don't state the new thread exists prior to that point.
      If the clone fails, we'll send out a ll_exit notification for it
      at the out: label below, to clean up. */
   VG_TRACK ( pre_thread_ll_create, ptid, ctid );

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Create the new thread */
   /* XXX need to see what happens with tids etc with rfork */
   eax = do_syscall_clone_x86_freebsd(
            ML_(start_thread_NORETURN), stack, flags /*, &VG_(threads)[ctid], NULL*/ );
   res = VG_(mk_SysRes_x86_freebsd)( eax ); /* XXX edx returns too! */

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

  out:
   if (res.isError) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   }

   return res;
}
#endif

/* Translate a struct modify_ldt_ldt_s to a VexGuestX86SegDescr */

static
void translate_to_hw_format ( /* IN  */ void* base,
                              /* OUT */ VexGuestX86SegDescr* out)
{
   UInt entry_1, entry_2;
   UInt base_addr = (UInt) base;
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   if (0)
      VG_(printf)("translate_to_hw_format: base %p\n", base );

   /* Allow LDTs to be cleared by the user. */
   if (base == 0) {
      entry_1 = 0;
      entry_2 = 0;
      goto install;
   }
   /* base as specified, no limit, read/write/accessed etc */
   entry_1 = ((base_addr & 0x0000ffff) << 16) | 0x0ffff;
   entry_2 = (base_addr & 0xff000000) |
             ((base_addr & 0x00ff0000) >> 16) | 0x00cff300;

   /* Install the new entry ...  */
  install:
   out->LdtEnt.Words.word1 = entry_1;
   out->LdtEnt.Words.word2 = entry_2;
}

/* Create a zeroed-out GDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_GDT ( void )
{
   Int nbytes = VEX_GUEST_X86_GDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, "di.syswrap-x86.azxG.1", nbytes, 1);
}

#if 0
/* Create a zeroed-out LDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_LDT ( void )
{
   Int nbytes = VEX_GUEST_X86_LDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, "di.syswrap-x86.azxL.1", nbytes, 1);
}

/* Free up an LDT or GDT allocated by the above fns. */
static void free_LDT_or_GDT ( VexGuestX86SegDescr* dt )
{
   vg_assert(dt);
   VG_(arena_free)(VG_AR_CORE, (void*)dt);
}

/* Copy contents between two existing LDTs. */
static void copy_LDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_LDT_NENT; i++)
      dst[i] = src[i];
}

/* Copy contents between two existing GDTs. */
static void copy_GDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_GDT_NENT; i++)
      dst[i] = src[i];
}

/* Free this thread's DTs, if it has any. */
static void deallocate_LGDTs_for_thread ( VexGuestX86State* vex )
{
   vg_assert(sizeof(HWord) == sizeof(void*));

   if (0)
      VG_(printf)("deallocate_LGDTs_for_thread: "
                  "ldt = 0x%x, gdt = 0x%x\n", 
                  vex->guest_LDT, vex->guest_GDT );

   if (vex->guest_LDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_LDT );
      vex->guest_LDT = (HWord)NULL;
   }

   if (vex->guest_GDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_GDT );
      vex->guest_GDT = (HWord)NULL;
   }
}
#endif

static SysRes sys_set_thread_area ( ThreadId tid, Int *idxptr, void *base)
{
   VexGuestX86SegDescr* gdt;
   Int idx;

   vg_assert(8 == sizeof(VexGuestX86SegDescr));
   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }

   idx = *idxptr;
   if (idx == -1) {
      /* Find and use the first free entry.  Don't allocate entry
         zero, because the hardware will never do that, and apparently
         doing so confuses some code (perhaps stuff running on
         Wine). */
      for (idx = 1; idx < VEX_GUEST_X86_GDT_NENT; idx++) {
         if (gdt[idx].LdtEnt.Words.word1 == 0
             && gdt[idx].LdtEnt.Words.word2 == 0)
            break;
      }

      if (idx == VEX_GUEST_X86_GDT_NENT)
         return VG_(mk_SysRes_Error)( VKI_ESRCH );
   } else if (idx < 0 || idx == 0 || idx >= VEX_GUEST_X86_GDT_NENT) {
      /* Similarly, reject attempts to use GDT[0]. */
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   translate_to_hw_format(base, &gdt[idx]);

   *idxptr = idx;
   return VG_(mk_SysRes_Success)( 0 );
}

static SysRes sys_get_thread_area ( ThreadId tid, Int idx, void ** basep )
{
   VexGuestX86SegDescr* gdt;
   UInt base;

   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }
   
   base = ( gdt[idx].LdtEnt.Bits.BaseHi << 24 ) |
          ( gdt[idx].LdtEnt.Bits.BaseMid << 16 ) |
            gdt[idx].LdtEnt.Bits.BaseLow;
   *basep = (void *)base;

   return VG_(mk_SysRes_Success)( 0 );
}

/* ---------------------------------------------------------------------
   More thread stuff
   ------------------------------------------------------------------ */

void VG_(cleanup_thread) ( ThreadArchState* arch )
{
}  


/* ---------------------------------------------------------------------
   PRE/POST wrappers for x86/FreeBSD-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(freebsd, name)
#define POST(name)      DEFN_POST_TEMPLATE(freebsd, name)

// SYS_sysarch	165
// int sysarch(int number, void *args);
PRE(sys_sysarch)
{
   ThreadState *tst;
   Int idx;
   void **p;

   PRINT("sys_sysarch ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x )", ARG1, ARG2);
   PRE_REG_READ2(int, "sysarch", int, number, void *, args);
   switch (ARG1) {
   case VKI_I386_SET_GSBASE:
      PRINT("sys_i386_set_gsbase ( %#lx )", ARG2);

      if (ML_(safe_to_deref)((void**)ARG2, sizeof(void*))) {
         /* On FreeBSD, the syscall loads the %gs selector for us, so do it now. */
         tst = VG_(get_ThreadState)(tid);
         p = (void**)ARG2;
         tst->arch.vex.guest_GS = (1 << 3) | 3;   /* GSEL(GUGS_SEL, SEL_UPL) */
         /* "do" the syscall ourselves; the kernel never sees it */
         idx = 1;
         SET_STATUS_from_SysRes( sys_set_thread_area( tid, &idx, *p ) );
      } else {
         // ????
         SET_STATUS_Failure( VKI_EINVAL );
      }

      break;
   case VKI_I386_GET_GSBASE:
      PRINT("sys_i386_get_gsbase ( %#lx )", ARG2);
      PRE_MEM_WRITE( "i386_get_gsbase(basep)", ARG2, sizeof(void *) );
       if (ML_(safe_to_deref)((void**)ARG2, sizeof(void*))) {
         /* "do" the syscall ourselves; the kernel never sees it */
         SET_STATUS_from_SysRes( sys_get_thread_area( tid, 2, (void **)ARG2 ) );
       } else {
          SET_STATUS_Failure( VKI_EINVAL );
       }
      break;
   case VKI_I386_GET_XFPUSTATE:
      PRINT("sys_i386_get_xfpustate ( %#lx )", ARG2);
      PRE_MEM_WRITE( "i386_get_xfpustate(basep)", ARG2, sizeof(void *) );
      /* "do" the syscall ourselves; the kernel never sees it */
      tst = VG_(get_ThreadState)(tid);
      SET_STATUS_Success2( tst->arch.vex.guest_FPTAG[0], tst->arch.vex.guest_FPTAG[0] );
      break;
   default:
      VG_(message) (Vg_UserMsg, "unhandled sysarch cmd %lu", ARG1);
      VG_(unimplemented) ("unhandled sysarch cmd");
      break;
   }
}

POST(sys_sysarch)
{
   switch (ARG1) {
   case VKI_AMD64_SET_FSBASE:
      break;
   case VKI_AMD64_GET_FSBASE:
      POST_MEM_WRITE( ARG2, sizeof(void *) );
      break;
   case VKI_AMD64_GET_XFPUSTATE:
      POST_MEM_WRITE( ARG2, sizeof(void *) );
      break;
   default:
      break;
   }
}

// freebsd6_pread 173
#if (FREEBSD_VERS <= FREEBSD_10)
PRE(sys_freebsd6_pread)
{
   *flags |= SfMayBlock;
   PRINT("sys_freebsd6_pread ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3, ARG5, ARG6);
   PRE_REG_READ6(ssize_t, "pread",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 int, pad, unsigned int, off_low, unsigned int, off_high);

   if (!ML_(fd_allowed)(ARG1, "freebsd6_pread", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_WRITE( "freebsd6_pread(buf)", ARG2, ARG3 );
}

POST(sys_freebsd6_pread)
{
   vg_assert(SUCCESS);
   POST_MEM_WRITE( ARG2, RES );
}
#endif

// freebsd6_pwrite 174
#if (FREEBSD_VERS <= FREEBSD_10)
PRE(sys_freebsd6_pwrite)
{
   Bool ok;
   *flags |= SfMayBlock;
   PRINT("sys_freebsd6_pwrite ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3, ARG5, ARG6);
   PRE_REG_READ6(ssize_t, "freebsd6_pwrite",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 int, pad, unsigned int, off_low, unsigned int, off_high);
   /* check to see if it is allowed.  If not, try for an exemption from
      --sim-hints=enable-outer (used for self hosting). */
   ok = ML_(fd_allowed)(ARG1, "freebsd6_pwrite", tid, False);
   if (!ok && ARG1 == 2/*stderr*/
           && SimHintiS(SimHint_enable_outer, VG_(clo_sim_hints)))
      ok = True;
   if (!ok)
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_READ( "freebsd6_write(buf)", ARG2, ARG3 );
}
#endif

// SYS_freebsd6_mmap 197
#if (FREEBSD_VERS <= FREEBSD_10)
/* This is here because on x86 the off_t is passed in 2 regs. Don't ask about pad.  */

/* caddr_t mmap(caddr_t addr, size_t len, int prot, int flags, int fd, int pad, off_t pos); */
/*              ARG1           ARG2       ARG3      ARG4       ARG5    ARG6     ARG7+ARG8 */

PRE(sys_freebsd6_mmap)
{
   SysRes r;

   PRINT("sys_freebsd6_mmap ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, pad%" FMT_REGWORD "u, lo0x%" FMT_REGWORD "x hi0x%" FMT_REGWORD "x)",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8 );
   PRE_REG_READ8(long, "mmap",
                 char *, addr, unsigned long, len, int, prot,  int, flags,
                 int, fd,  int, pad, unsigned long, lo, unsigned long, hi);

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, MERGE64(ARG7,ARG8) );
   SET_STATUS_from_SysRes(r);
}
#endif

// freebsd6_lseek 199
#if (FREEBSD_VERS <= FREEBSD_10)
PRE(sys_freebsd6_lseek)
{
   PRINT("sys_freebsd6_lseek ( %" FMT_REGWORD "u, 0x%" FMT_REGWORD "x, 0x%" FMT_REGWORD "x, %" FMT_REGWORD "u )", ARG1,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "lseek",
                 unsigned int, fd, int, pad, unsigned int, offset_low,
                 unsigned int, offset_high, unsigned int, whence);
}
#endif

// freebsd6_truncate 200
#if (FREEBSD_VERS <= FREEBSD_10)
PRE(sys_freebsd6_truncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#" FMT_REGWORD "x(%s), %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,(char *)ARG1,ARG3,ARG4);
   PRE_REG_READ4(long, "truncate",
                 const char *, path, int, pad,
       unsigned int, length_low, unsigned int, length_high);
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}
#endif

// freebsd6_ftruncate 201
#if (FREEBSD_VERS <= FREEBSD_10)
PRE(sys_freebsd6_ftruncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1,ARG3,ARG4);
   PRE_REG_READ4(long, "ftruncate", unsigned int, fd, int, pad,
        unsigned int, length_low, unsigned int, length_high);
}
#endif

// SYS_rfork 251
// pid_t rfork(int flags);
PRE(sys_rfork)
{
   PRINT("sys_rfork ( %" FMT_REGWORD "x )",ARG1);
   PRE_REG_READ1(int, "rfork",
                 unsigned int, flags);

#if 0
   cloneflags = ARG1;

   if (!ML_(client_signal_OK)(ARG1 & VKI_CSIGNAL)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   SET_STATUS_from_SysRes( do_clone(tid, ARG1));

   if (SUCCESS) {
      *flags |= SfYieldAfter;
   }
#else
   VG_(message)(Vg_UserMsg, "fork() not implemented");
   VG_(unimplemented)("Valgrind does not support rfork() yet.");
   SET_STATUS_Failure( VKI_ENOSYS );
#endif
}

// SYS_preadv	289
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
PRE(sys_preadv)
{
   Int i;
   struct vki_iovec * vec;
   *flags |= SfMayBlock;
   PRINT("sys_preadv ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %"
         FMT_REGWORD "d, %llu )", SARG1, ARG2, SARG3, MERGE64(ARG4,ARG5));
   PRE_REG_READ5(ssize_t, "preadv",
                 int, fd, const struct iovec *, iovr,
                 int, iovcnt, vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset));
   if (!ML_(fd_allowed)(ARG1, "preadv", tid, False)) {
      SET_STATUS_Failure( VKI_EBADF );
   } else {
      if ((Int)ARG3 >= 0)
         PRE_MEM_READ( "preadv(iov)", ARG2, ARG3 * sizeof(struct vki_iovec) );

      if (ML_(safe_to_deref)((struct vki_iovec *)ARG2, ARG3 * sizeof(struct vki_iovec))) {
         vec = (struct vki_iovec *)(Addr)ARG2;
         for (i = 0; i < (Int)ARG3; i++)
            PRE_MEM_WRITE( "preadv(iov[...])",
                           (Addr)vec[i].iov_base, vec[i].iov_len );
      }
   }
}

POST(sys_preadv)
{
   vg_assert(SUCCESS);
   if (RES > 0) {
      Int i;
      struct vki_iovec * vec = (struct vki_iovec *)(Addr)ARG2;
      Int remains = RES;

      /* RES holds the number of bytes read. */
      for (i = 0; i < (Int)ARG3; i++) {
         Int nReadThisBuf = vec[i].iov_len;
         if (nReadThisBuf > remains) nReadThisBuf = remains;
            POST_MEM_WRITE( (Addr)vec[i].iov_base, nReadThisBuf );
         remains -= nReadThisBuf;
         if (remains < 0) VG_(core_panic)("preadv: remains < 0");
      }
   }
}

// SYS_pwritev	290
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
PRE(sys_pwritev)
{
   Int i;
   struct vki_iovec * vec;
   *flags |= SfMayBlock;
   PRINT("sys_pwritev ( %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %"
         FMT_REGWORD "d, %llu )", SARG1, ARG2, SARG3, MERGE64(ARG4,ARG5));

   PRE_REG_READ5(ssize_t, "pwritev",
                 int, fd, const struct iovec *, iov,
                 int, iovcnt,
                 vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset));
   if (!ML_(fd_allowed)(ARG1, "pwritev", tid, False)) {
      SET_STATUS_Failure( VKI_EBADF );
   } else {
      if ((Int)ARG3 >= 0)
         PRE_MEM_READ( "pwritev(vector)", ARG2, ARG3 * sizeof(struct vki_iovec) );
      if (ML_(safe_to_deref)((struct vki_iovec *)ARG2, ARG3 * sizeof(struct vki_iovec))) {
         vec = (struct vki_iovec *)(Addr)ARG2;
         for (i = 0; i < (Int)ARG3; i++)
            PRE_MEM_READ( "pwritev(iov[...])",
                           (Addr)vec[i].iov_base, vec[i].iov_len );
      }
   }
}

// SYS_sendfile	393
// int sendfile(int fd, int s, off_t offset, size_t nbytes,
//         struct sf_hdtr *hdtr, off_t *sbytes, int flags);
PRE(sys_sendfile)
{
   *flags |= SfMayBlock;
   PRINT("sys_sendfile ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %llu, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x, %" FMT_REGWORD "d )",
         SARG1,SARG2,LOHI64(ARG3,ARG4),ARG5,ARG6,ARG7,SARG8);
   PRE_REG_READ8(int, "sendfile",
                 int, fd, int, s, unsigned int, offset_low,
                 unsigned int, offset_high, size_t, nbytes,
                 void *, hdtr, vki_off_t *, sbytes, int, flags);

   if (ARG6 != 0)
      PRE_MEM_READ("sendfile(hdtr)", ARG6, sizeof(struct vki_sf_hdtr));

   if (ARG7 != 0)
      PRE_MEM_WRITE( "sendfile(sbytes)", ARG7, sizeof(vki_off_t) );
}

POST(sys_sendfile)
{
   if (ARG7 != 0 ) {
      POST_MEM_WRITE( ARG7, sizeof( vki_off_t ) );
   }
}

// SYS_sigreturn	417
// int sigreturn(const ucontext_t *scp);
PRE(sys_sigreturn)
{
   PRINT("sys_sigreturn ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(int, "sigreturn",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
}


static void restore_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   tst->arch.vex.guest_EAX     = sc->eax;
   tst->arch.vex.guest_ECX     = sc->ecx;
   tst->arch.vex.guest_EDX     = sc->edx;
   tst->arch.vex.guest_EBX     = sc->ebx;
   tst->arch.vex.guest_EBP     = sc->ebp;
   tst->arch.vex.guest_ESP     = sc->esp;
   tst->arch.vex.guest_ESI     = sc->esi;
   tst->arch.vex.guest_EDI     = sc->edi;
   tst->arch.vex.guest_EIP     = sc->eip;
   tst->arch.vex.guest_CS      = sc->cs;
   tst->arch.vex.guest_SS      = sc->ss;
   tst->arch.vex.guest_DS      = sc->ds;
   tst->arch.vex.guest_ES      = sc->es;
   tst->arch.vex.guest_FS      = sc->fs;
   tst->arch.vex.guest_GS      = sc->gs;
   /*
    * XXX: missing support for other flags.
    */
   if (sc->eflags & 0x0001)
      LibVEX_GuestX86_put_eflag_c(1, &tst->arch.vex);
   else
      LibVEX_GuestX86_put_eflag_c(0, &tst->arch.vex);
}

static void fill_mcontext(ThreadState *tst, struct vki_mcontext *sc)
{
   sc->eax = tst->arch.vex.guest_EAX;
   sc->ecx = tst->arch.vex.guest_ECX;
   sc->edx = tst->arch.vex.guest_EDX;
   sc->ebx = tst->arch.vex.guest_EBX;
   sc->ebp = tst->arch.vex.guest_EBP;
   sc->esp = tst->arch.vex.guest_ESP;
   sc->esi = tst->arch.vex.guest_ESI;
   sc->edi = tst->arch.vex.guest_EDI;
   sc->eip = tst->arch.vex.guest_EIP;
   sc->cs = tst->arch.vex.guest_CS;
   sc->ss = tst->arch.vex.guest_SS;
   sc->ds = tst->arch.vex.guest_DS;
   sc->es = tst->arch.vex.guest_ES;
   sc->fs = tst->arch.vex.guest_FS;
   sc->gs = tst->arch.vex.guest_GS;
   sc->eflags = LibVEX_GuestX86_get_eflags(&tst->arch.vex);
/*
   not yet.
   VG_(memcpy)(&sc->fpstate, fpstate, sizeof(*fpstate));
*/
   sc->fpformat = VKI_FPFMT_NODEV;
   sc->ownedfp = VKI_FPOWNED_NONE;
   sc->len = sizeof(*sc);
   VG_(memset)(sc->spare2, 0, sizeof(sc->spare2));
}

// SYS_getcontext	421
// int getcontext(ucontext_t *ucp);
PRE(sys_getcontext)
{
   ThreadState* tst;
   struct vki_ucontext *uc;
   
   PRINT("sys_getcontext ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(int, "getcontext",
                 struct vki_ucontext *, ucp);
   PRE_MEM_WRITE( "getcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );
   uc = (struct vki_ucontext *)ARG1;
   if (!ML_(safe_to_deref)(uc, sizeof(struct vki_ucontext))) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   tst = VG_(get_ThreadState)(tid);
   fill_mcontext(tst, &uc->uc_mcontext);
   uc->uc_mcontext.eax = 0;
   uc->uc_mcontext.edx = 0;
   uc->uc_mcontext.eflags &= ~0x0001;   /* PSL_C */
   uc->uc_sigmask = tst->sig_mask;
   VG_(memset)(uc->__spare__, 0, sizeof(uc->__spare__));
   SET_STATUS_Success(0);
}

// SYS_setcontext	422
// int setcontext(const ucontext_t *ucp);
PRE(sys_setcontext)
{
   ThreadState* tst;
   struct vki_ucontext *uc;

   PRINT("sys_setcontext ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "setcontext",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "setcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "setcontext(ucp)", ARG1, sizeof(struct vki_ucontext) );

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   tst = VG_(get_ThreadState)(tid);
   uc = (struct vki_ucontext *)ARG1;
   if (!ML_(safe_to_deref)(uc, sizeof(struct vki_ucontext)) || uc->uc_mcontext.len != sizeof(uc->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   
   restore_mcontext(tst, &uc->uc_mcontext);
   tst->sig_mask = uc->uc_sigmask;
                                  
   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

// SYS_swapcontext	423
// int swapcontext(ucontext_t *oucp, const ucontext_t *ucp);
PRE(sys_swapcontext)
{
   struct vki_ucontext *ucp, *oucp;
   ThreadState* tst;

   PRINT("sys_swapcontext ( %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )", ARG1, ARG2);
   PRE_REG_READ2(long, "swapcontext",
                 struct vki_ucontext *, oucp, struct vki_ucontext *, ucp);
 
   PRE_MEM_READ( "swapcontext(ucp)", ARG2, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "swapcontext(oucp)", ARG1, sizeof(struct vki_ucontext) );
 
   oucp = (struct vki_ucontext *)ARG1;
   ucp = (struct vki_ucontext *)ARG2;
   if (!ML_(safe_to_deref)(oucp, sizeof(struct vki_ucontext)) ||
       !ML_(safe_to_deref)(ucp, sizeof(struct vki_ucontext)) ||
       ucp->uc_mcontext.len != sizeof(ucp->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }
   tst = VG_(get_ThreadState)(tid);

   /*
    * Save the context.
    */
   fill_mcontext(tst, &oucp->uc_mcontext);
   oucp->uc_mcontext.eax = 0;
   oucp->uc_mcontext.edx = 0;
   oucp->uc_mcontext.eflags &= ~0x0001; /* PSL_C */
   oucp->uc_sigmask = tst->sig_mask;
   VG_(memset)(oucp->__spare__, 0, sizeof(oucp->__spare__));
 
   /*
    * Switch to new one.
    */
   restore_mcontext(tst, &ucp->uc_mcontext);
   tst->sig_mask = ucp->uc_sigmask;

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

// SYS_thr_new	455
// int thr_new(struct thr_param *param, int param_size);
PRE(sys_thr_new)
{
   static const Bool debug = False;

   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(tid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   SysRes       res;
   vki_sigset_t blockall, savedmask;
   struct vki_thr_param tp;
   Int idx = -1;
   Addr stk;

   PRINT("thr_new ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u )",ARG1,ARG2);
   PRE_REG_READ2(int, "thr_new",
                 struct thr_param *, param,
                 int, param_size);

   PRE_MEM_READ( "thr_new(param)", ARG1, offsetof(struct vki_thr_param, spare));
   if (!ML_(safe_to_deref)( (void*)ARG1, offsetof(struct vki_thr_param, spare))) {
      SET_STATUS_Failure( VKI_EFAULT );
      return;
   }
   VG_(memset)(&tp, 0, sizeof(tp));
   VG_(memcpy)(&tp, (void *)ARG1, offsetof(struct vki_thr_param, spare));
   PRE_MEM_WRITE("clone(parent_tidptr)", (Addr)tp.parent_tid, sizeof(long));
   PRE_MEM_WRITE("clone(child_tidptr)", (Addr)tp.child_tid, sizeof(long));

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(tid));
   vg_assert(VG_(is_valid_tid)(ctid));

   /* Copy register state

      On linux, both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.
      On FreeBSD, thr_new arranges a direct call.  We don't actually need any
      of this gunk.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL rsp for the new thread, then
      it actually gets a copy of the parent's rsp.
   */
   /* We inherit our parent's guest state. */
   ctst->arch.vex = ptst->arch.vex;
   ctst->arch.vex_shadow1 = ptst->arch.vex_shadow1;
   ctst->arch.vex_shadow2 = ptst->arch.vex_shadow2;

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_EAX = 0;
   ctst->arch.vex.guest_EDX = 0;
   LibVEX_GuestX86_put_eflag_c(0, &ctst->arch.vex);

   ctst->os_state.parent = tid;

   /* inherit signal mask */
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* Linux has to guess, we don't */
   ctst->client_stack_highest_byte = (Addr)tp.stack_base + tp.stack_size;
   ctst->client_stack_szB = tp.stack_size;
   ctst->os_state.stk_id = VG_(register_stack)((Addr)tp.stack_base, (Addr)tp.stack_base + tp.stack_size);

   /* Assume the clone will succeed, and tell any tool that wants to
      know that this thread has come into existence.  If the clone
      fails, we'll send out a ll_exit notification for it at the out:
      label below, to clean up. */
   VG_TRACK ( pre_thread_ll_create, tid, ctid );

   if (debug)
      VG_(printf)("clone child has SETTLS: tls at %#lx\n", (Addr)tp.tls_base);
   sys_set_thread_area( ctid, &idx, tp.tls_base );
   ctst->arch.vex.guest_GS = (idx << 3) | 3;   /* GSEL(GUGS_SEL, SEL_UPL) */
   tp.tls_base = 0;	/* Don't have the kernel do it too */

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Set the client state for scheduler to run libthr's trampoline */
   ctst->arch.vex.guest_ESP = (Addr)tp.stack_base + tp.stack_size - 8;
   ctst->arch.vex.guest_EIP = (Addr)tp.start_func;
   *(UWord *)(ctst->arch.vex.guest_ESP + 4) = (UWord)tp.arg;	/* Client arg */
   *(UWord *)(ctst->arch.vex.guest_ESP + 0) = 0;		/* fake return addr */

   /* Set up valgrind's trampoline on its own stack */
   stk = ML_(allocstack)(ctid);
   tp.stack_base = (void *)ctst->os_state.valgrind_stack_base;
   tp.stack_size = (Addr)stk - (Addr)tp.stack_base;
   /* This is for thr_new() to run valgrind's trampoline */
   tp.start_func = (void *)ML_(start_thread_NORETURN);
   tp.arg = &VG_(threads)[ctid];

   /* Create the new thread */
   res = VG_(do_syscall2)(__NR_thr_new, (UWord)&tp, sizeof(tp));

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

   if (sr_isError(res)) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   } else {

      POST_MEM_WRITE((Addr)tp.parent_tid, sizeof(long));
      POST_MEM_WRITE((Addr)tp.child_tid, sizeof(long));
      POST_MEM_WRITE((Addr)ctst->arch.vex.guest_ESP, 8);

      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }

   /* "Complete" the syscall so that the wrapper doesn't call the kernel again. */
   SET_STATUS_from_SysRes(res);
}

// SYS_pread 475
// ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset);
PRE(sys_pread)
{
   *flags |= SfMayBlock;
   PRINT("sys_pread ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(ssize_t, "pread",
                 unsigned int, fd, char *, buf, vki_size_t, count,
                 unsigned int, off_low, unsigned int, off_high);

   if (!ML_(fd_allowed)(ARG1, "pread", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_WRITE( "pread(buf)", ARG2, ARG3 );
}

POST(sys_pread)
{
   vg_assert(SUCCESS);
   POST_MEM_WRITE( ARG2, RES );
}

// SYS_pwrite	476
// ssize_t pwrite(int fd, const void *buf, size_t nbytes, off_t offset);
PRE(sys_pwrite)
{
   Bool ok;
   *flags |= SfMayBlock;
   PRINT("sys_pwrite ( %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %llu )", ARG1, ARG2, ARG3, MERGE64(ARG4, ARG5));
   PRE_REG_READ5(ssize_t, "pwrite",
                 unsigned int, fd, const char *, buf, vki_size_t, count,
                 vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset));
   /* check to see if it is allowed.  If not, try for an exemption from
      --sim-hints=enable-outer (used for self hosting). */
   ok = ML_(fd_allowed)(ARG1, "pwrite", tid, False);
   if (!ok && ARG1 == 2/*stderr*/
           && SimHintiS(SimHint_enable_outer, VG_(clo_sim_hints)))
      ok = True;
   if (!ok)
      SET_STATUS_Failure( VKI_EBADF );
   else
      PRE_MEM_READ( "pwrite(buf)", ARG2, ARG3 );
}

// SYS_mmap	477
// void * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
PRE(sys_mmap)
{
   SysRes r;

   PRINT("sys_mmap ( %#" FMT_REGWORD "x, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %" FMT_REGWORD "u, %llu )",
         ARG1, (UWord)ARG2, ARG3, ARG4, ARG5, MERGE64(ARG6, ARG7) );
   PRE_REG_READ7(void *, "mmap",
                 void *, addr, size_t, len, int, prot,  int, flags, int, fd,
                 vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset));

   r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, MERGE64(ARG6,ARG7) );
   SET_STATUS_from_SysRes(r);
}

// SYS_lseek 478
// off_t lseek(int fildes, off_t offset, int whence);
PRE(sys_lseek)
{
   PRINT("sys_lseek ( %" FMT_REGWORD "d, %llu, %" FMT_REGWORD "d )", SARG1,MERGE64(ARG2,ARG3),SARG4);
   PRE_REG_READ4(long, "lseek",
                 unsigned int, fd,
                 vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset),
                 unsigned int, whence);
}

// SYS_truncate 479
// int truncate(const char *path, off_t length);
PRE(sys_truncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_truncate ( %#" FMT_REGWORD "x(%s), %llu )", ARG1,(char *)ARG1,MERGE64(ARG2,ARG3));
   PRE_REG_READ3(long, "truncate",
                 const char *, path,
                 vki_uint32_t, MERGE64_FIRST(length),
                 vki_uint32_t, MERGE64_SECOND(length));
   PRE_MEM_RASCIIZ( "truncate(path)", ARG1 );
}

// SYS_ftruncate	480
// int ftruncate(int fd, off_t length);
PRE(sys_ftruncate)
{
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %" FMT_REGWORD "d, %" FMT_REGWORD "u, %" FMT_REGWORD "u )", SARG1,ARG2,ARG3);
   PRE_REG_READ3(int, "ftruncate", int, fd,
                 vki_uint32_t, MERGE64_FIRST(length),
                 vki_uint32_t, MERGE64_SECOND(length));
}

// SYS_cpuset_setid	485
// int cpuset_setid(cpuwhich_t which, id_t id, cpusetid_t setid);
PRE(sys_cpuset_setid)
{
   PRINT("sys_cpuset_setid ( %" FMT_REGWORD "d, %llu, %#" FMT_REGWORD "x )",
         SARG1, MERGE64(ARG2,ARG3), ARG4);
   PRE_REG_READ4(int, "cpuset_setid", vki_cpuwhich_t, which,
                 vki_uint32_t, MERGE64_FIRST(id),
                 vki_uint32_t, MERGE64_SECOND(id),
                 vki_cpusetid_t,setid);
}

// SYS_cpuset_getid	486
// int cpuset_getid(cpulevel_t level, cpuwhich_t which, id_t id,
//                  cpusetid_t *setid);
PRE(sys_cpuset_getid)
{
    PRINT("sys_cpuset_getid ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %llu, %#" FMT_REGWORD "x )",
          SARG1, SARG2, MERGE64(ARG3, ARG4), ARG5);
    PRE_REG_READ5(int, "cpuset_getid", vki_cpulevel_t, level,
                  vki_cpuwhich_t, which,
                  vki_uint32_t, MERGE64_FIRST(id),
                  vki_uint32_t, MERGE64_SECOND(id),
                  vki_cpusetid_t *,setid);
    PRE_MEM_WRITE("cpuset_getid(setid)", ARG4, sizeof(vki_cpusetid_t));
}

POST(sys_cpuset_getid)
{
   POST_MEM_WRITE(ARG5, sizeof(vki_cpusetid_t));
}



// SYS_posix_fallocate 530
// int posix_fallocate(int fd, off_t offset, off_t len);
PRE(sys_posix_fallocate)
{
   PRINT("sys_posix_fallocate ( %" FMT_REGWORD "d, %llu, %llu )",
         SARG1, MERGE64(ARG2,ARG3), MERGE64(ARG4, ARG5));
   PRE_REG_READ5(long, "posix_fallocate",
                 int, fd, vki_uint32_t, MERGE64_FIRST(offset),
                 vki_uint32_t, MERGE64_SECOND(offset),
                 vki_uint32_t, MERGE64_FIRST(len),
                 vki_uint32_t, MERGE64_SECOND(len));
}

// SYS_posix_fadvise	531
// int posix_fadvise(int fd, off_t offset, off_t len, int advice);
PRE(sys_posix_fadvise)
{
   PRINT("sys_posix_fadvise ( %" FMT_REGWORD "d, %llu, %llu, %" FMT_REGWORD "d )",
         SARG1, MERGE64(ARG2,ARG3), MERGE64(ARG4,ARG5), SARG6);
   PRE_REG_READ6(long, "posix_fadvise",
                int, fd, vki_uint32_t, MERGE64_FIRST(offset),
                vki_uint32_t, MERGE64_SECOND(offset),
                vki_uint32_t, MERGE64_FIRST(len),
                vki_uint32_t, MERGE64_SECOND(len),
                int, advice);
}

// SYS_wait6	532
// pid_t wait6(idtype_t idtype, id_t id, int *status, int options,
//             struct __wrusage *wrusage, siginfo_t *infop);
PRE(sys_wait6)
{
   PRINT("sys_wait6 ( %" FMT_REGWORD "d, %llu, %#" FMT_REGWORD "x, %" FMT_REGWORD "d, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         SARG1, MERGE64(ARG2, ARG3), ARG4, SARG5, ARG6, ARG7);
   PRE_REG_READ7(pid_t, "wait6", vki_idtype_t, idtype,
                 vki_uint32_t, MERGE64_FIRST(id),
                 vki_uint32_t, MERGE64_SECOND(id),
                 int *, status, int, options,
                 struct vki___wrusage *, wrusage, vki_siginfo_t *,infop);
   PRE_MEM_WRITE("wait6(status)", ARG4, sizeof(int));
   if (ARG6) {
      PRE_MEM_WRITE("wait6(wrusage)", ARG6, sizeof(struct vki___wrusage));
   }
   if (ARG7) {
      PRE_MEM_WRITE("wait6(infop)", ARG7, sizeof(vki_siginfo_t));
   }
}

POST(sys_wait6)
{
   POST_MEM_WRITE(ARG4, sizeof(int));
   if (ARG6) {
      POST_MEM_WRITE(ARG6, sizeof(struct vki___wrusage));
   }

   if (ARG7) {
      POST_MEM_WRITE(ARG7, sizeof(vki_siginfo_t));
   }
}

// the man page is inconsistent for the last argument
// See https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=247386
// will stick to 'arg' for simplicity

// SYS_procctl	544
// int procctl(idtype_t idtype, id_t id, int cmd, void *arg);
PRE(sys_procctl)
{
   PRINT("sys_procctl ( %" FMT_REGWORD "d, %llu, %" FMT_REGWORD"d, %#" FMT_REGWORD "x )",
         SARG1, MERGE64(ARG2, ARG3), SARG4, ARG5);
   PRE_REG_READ5(int, "procctl", vki_idtype_t, idtype,
                 vki_uint32_t, MERGE64_FIRST(id),
                 vki_uint32_t, MERGE64_SECOND(id),
                 int, cmd, void *, arg);
   switch (ARG4)
   {
   case PROC_ASLR_CTL:
   case PROC_SPROTECT:
   case PROC_TRACE_CTL:
   case PROC_TRAPCAP_CTL:
   case PROC_PDEATHSIG_CTL:
   case PROC_STACKGAP_CTL:
      PRE_MEM_READ("procctl(arg)", ARG5, sizeof(int));
      break;
   case PROC_REAP_STATUS:
      PRE_MEM_READ("procctl(arg)", ARG5, sizeof(struct vki_procctl_reaper_status));
      break;
   case PROC_REAP_GETPIDS:
      PRE_MEM_READ("procctl(arg)", ARG5, sizeof(struct vki_procctl_reaper_pids));
      break;
   case PROC_REAP_KILL:
      /* The first three fields are reads
       * int rk_sig;
       * u_int rk_flags;
       * pid_t rk_subtree;
       *
       * The last two fields are writes
       * u_int rk_killed;
       * pid_t	rk_fpid;
       *
       * There is also a pad field
       */
      PRE_MEM_READ("procctl(arg)", ARG5, sizeof(int) + sizeof(u_int) + sizeof(vki_pid_t));
      PRE_MEM_WRITE("procctl(arg)", ARG5+offsetof(struct vki_procctl_reaper_kill, rk_killed), sizeof(u_int) + sizeof(vki_pid_t));
      break;
   case PROC_ASLR_STATUS:
   case PROC_PDEATHSIG_STATUS:
   case PROC_STACKGAP_STATUS:
   case PROC_TRAPCAP_STATUS:
   case PROC_TRACE_STATUS:
      PRE_MEM_WRITE("procctl(arg)", ARG5, sizeof(int));
   case PROC_REAP_ACQUIRE:
   case PROC_REAP_RELEASE:
   default:
      break;
   }
}

POST(sys_procctl)
{
   switch (ARG4)
   {
   case PROC_REAP_KILL:
      POST_MEM_WRITE(ARG5+offsetof(struct vki_procctl_reaper_kill, rk_killed), sizeof(u_int) + sizeof(vki_pid_t));
      break;
   case PROC_ASLR_STATUS:
   case PROC_PDEATHSIG_STATUS:
   case PROC_STACKGAP_STATUS:
   case PROC_TRAPCAP_STATUS:
   case PROC_TRACE_STATUS:
      POST_MEM_WRITE(ARG5, sizeof(int));
   default:
      break;
   }
}

#if (FREEBSD_VERS >= FREEBSD_12)

// SYS_cpuset_getdomain	561
// int cpuset_getdomain(cpulevel_t level, cpuwhich_t which, id_t id,
//                      size_t setsize, domainset_t *mask, int *policy);
PRE(sys_cpuset_getdomain)
{
   PRINT("sys_cpuset_getdomain ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %llu, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %#" FMT_REGWORD "x )",
         SARG1, SARG2, MERGE64(ARG3, ARG4), ARG5, ARG6, ARG7);
   PRE_REG_READ7(int, "cpuset_getdomain",
                 cpulevel_t, level, cpuwhich_t, which,
                 vki_uint32_t, MERGE64_FIRST(id),
                 vki_uint32_t, MERGE64_SECOND(id),
                 size_t, setsize, vki_domainset_t *, mask, int *, policy);
   // man page says that setsize (ARG4) "is usually provided by calling sizeof(mask)"
   PRE_MEM_WRITE( "cpuset_getdomain(mask)", ARG6, ARG5 );
   PRE_MEM_WRITE( "cpuset_getdomain(policy)", ARG7, sizeof(int) );
}

POST(sys_cpuset_getdomain)
{
   POST_MEM_WRITE(ARG5, ARG4 );
   POST_MEM_WRITE(ARG6, sizeof(int) );
}

// SYS_cpuset_setdomain	562
// int cuset_setdomain(cpulevel_t level, cpuwhich_t which, id_t id,
//                     size_t setsize, const domainset_t *mask, int policy);
PRE(sys_cpuset_setdomain)
{
   PRINT("sys_cpuget_getdomain ( %" FMT_REGWORD "d, %" FMT_REGWORD "d, %llu, %" FMT_REGWORD "u, %#" FMT_REGWORD "x, %" FMT_REGWORD "d )",
         SARG1, SARG2, MERGE64(ARG3, ARG4), ARG5, ARG6, SARG7);
   PRE_REG_READ7(int, "cpuset_getdomain",
                 cpulevel_t, level, cpuwhich_t, which,
                 vki_uint32_t, MERGE64_FIRST(id),
                 vki_uint32_t, MERGE64_SECOND(id),
                 size_t, setsize, vki_domainset_t *, mask, int, policy);
   // man page says that setsize (ARG4) "is usually provided by calling sizeof(mask)"
   PRE_MEM_READ( "cpuset_getdomain(mask)", ARG6, ARG5 );
}

#endif

PRE(sys_fake_sigreturn)
{
   /* See comments on PRE(sys_rt_sigreturn) in syswrap-amd64-linux.c for
      an explanation of what follows. */

   ThreadState* tst;
   struct vki_ucontext *uc;
   PRINT("sys_sigreturn ( %#" FMT_REGWORD "x )", ARG1);
   PRE_REG_READ1(long, "sigreturn",
                 struct vki_ucontext *, ucp);

   PRE_MEM_READ( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );
   PRE_MEM_WRITE( "sigreturn(ucp)", ARG1, sizeof(struct vki_ucontext) );

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   /* Adjust esp to point to start of frame; skip back up over handler
      ret addr */
   tst = VG_(get_ThreadState)(tid);
   tst->arch.vex.guest_ESP -= sizeof(Addr);	/* QQQ should be redundant */

   uc = (struct vki_ucontext *)ARG1;
   if (uc == NULL || uc->uc_mcontext.len != sizeof(uc->uc_mcontext)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }

   /* This is only so that the EIP is (might be) useful to report if
      something goes wrong in the sigreturn */
   ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);

   /* Restore register state from frame and remove it */
   VG_(sigframe_destroy)(tid);

   /* For unclear reasons, it appears we need the syscall to return
      without changing %EAX.  Since %EAX is the return value, and can
      denote either success or failure, we must set up so that the
      driver logic copies it back unchanged.  Also, note %EAX is of
      the guest registers written by VG_(sigframe_destroy). */
   int eflags = LibVEX_GuestX86_get_eflags(&tst->arch.vex);
   SET_STATUS_from_SysRes( VG_(mk_SysRes_x86_freebsd)( tst->arch.vex.guest_EAX,
       tst->arch.vex.guest_EDX, (eflags & 1) != 0 ? True : False) );

   /*
    * Signal handler might have changed the signal mask.  Respect that.
    */
   tst->sig_mask = uc->uc_sigmask;
   tst->tmp_sig_mask = uc->uc_sigmask;

   /* Tell the driver not to update the guest state with the "result",
      and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

#undef PRE
#undef POST

const UChar ML_(syscall_arg_counts)[] = {
   8, // syscall 0
   1, // __NR_exit 1
   0, // _NR_fork 2
   3, // __NR_read 3
   3, // __NR_write 4
   3, // __NR_open 5
   1, // __NR_close 6
   4, // __NR_wait4 7
   8, // 4.3 creat 8
   2, // __NR_link 9
   1, // __NR_unlink 10
   8, // obsol execv 11
   1, // __NR_chdir 12
   1, // __NR_fchdir 13
   3, // __NR_freebsd11_mknod 14
   2, // __NR_chmod 15
   3, // __NR_chown 16
   1, // __NR_break 17
   8, // freebsd 4 getfsstat 18
   8, // 4.3 lseek 19
   0, // __NR_getpid 20
   4, // __NR_mount 21
   2, // __NR_unmount 22
   1, // __NR_setuid 23
   0, // __NR_getuid 24
   0, // __NR_geteuid 25
   4, // __NR_ptrace 26
   3, // __NR_recvmsg 27
   3, // __NR_sendmsg 28
   6, // __NR_recvfrom 29
   3, // __NR_accept 30
   3, // __NR_getpeername 31
   3, // __NR_getsockname 32
   2, // __NR_access 33
   2, // __NR_chflags 34
   2, // __NR_fchflags 35
   0, // __NR_sync 36
   2, // __NR_kill 37
   8, // 4.3 stat 38
   0, // __NR_getppid
   8, // 4.3 lstat 40
   1, // __NR_dup 41
   0, // __NR_freebsd10_pipe 42
   0, // __NR_getegid 43
   8, // ni _NR_profil 44
   8, // ni __NR_ktrace 45
   8, // 4.3 sigaction 46
   0, // __NR_getgid 47
   8, // 4.3 sigaction (int sigset) 48
   2, // __NR_getlogin 49
   1, // __NR_setlogin 50
   1, // __NR_acct 51
   8, // 4.3 sigpending 52
   2, // __NR_sigaltstack 53
   3, // __NR_ioctl 54
   1, // __NR_reboot 55
   1, // __NR_revoke 56
   2, // __NR_symlink 57
   3, // __NR_readlink 58
   2, // __NR_execve 59
   1, // __NR_umask 60
   1, // __NR_chroot 61
   8, // 4.3 fstat 62
   8, // 4.3 getgerninfo 63
   8, // 4.3 getpagesize 64
   3, // __NR_msync 65
   0, // _NR_vfork 66
   8, // obsol vread 67
   8, // obsol vwrite 68
   1, // __NR_sbrk 69
   8, // not implemented in OS sstk 70
   8, // 4.3 mmap 71
   8, // freebsd11 vadvise 72
   2, // __NR_munmap 73
   3, // __NR_mprotect 74
   3, // __NR_madvise 75
   8, // obsol vhangup 76
   8, // obsol vlimit 77
   3, // __NR_mincore 78
   2, // __NR_getgroups 79
   2, // __NR_setgroups 80
   0, // __NR_getpgrp 81
   1, // __NR_setpgid 82
   3, // __NR_setitimer 83
   8, // 4.3 wait 84
   1, // __NR_swapon 85
   2, // __NR_getitimer 86
   8, // 4.3 gethostname 87
   8, // 4.3 sethostname 88
   0, // __NR_getdtablesize 89
   2, // __NR_dup2 90
   8, // 91
   3, // __NR_fcntl 92
   5, // __NR_select 93
   8, // 94
   1, // __NR_fsync 95
   3, // __NR_setpriority 96
   3, // __NR_socket 97
   3, // __NR_connect 98
   8, // 4.3 accept 99
   2, // __NR_getpriority 100
   8, // 4.3 send 101
   8, // 4.3 recv 102
   8, // 4.3 sigreturn 103
   3, // __NR_bind 104
   5, // __NR_setsockopt 105
   2, // __NR_listen 106
   8, // obsol vtimes 107
   8, // 4.3 sigvec 108
   8, // 4.3 sigblock 109
   8, // 4.3 sigsetmask 110
   8, // 4.3 sigsuspend 111
   8, // 4.3 sigstack 112
   8, // 4.3 recvmsg 113
   8, // 4.3 sendmsg 114
   8, // 4.3 vtrace 115
   2, // __NR_gettimeofday 116
   2, // __NR_getrusage 117
   5, // __NR_getsockopt 118
   8, // 119
   3, // __NR_readv 120
   3, // __NR_writev 121
   2, // __NR_settimeofday 122
   3, // __NR_fchown  123
   2, // __NR_fchmod 124
   8, // 4.3 recvfrom 125
   2, // __NR_setreuid 126
   2, // __NR_setregid 127
   2, // __NR_rename 128
   8, // 4.3 truncate 129
   8, // 4.3 ftruncate 130
   2, // __NR_flock 131
   2, // __NR_mkfifo 132
   6, // __NR_sendto 133
   2, // __NR_shutdown 134
   4, // __NR_socketpair 135
   2, // __NR_mkdir 136
   1, // __NR_rmdir 137
   2, // __NR_utimes 138
   8, // 4.2 sigreturn 139
   2, // __NR_adjtime 140
   8, // 4.3 getpeername 141
   8, // 4.3 gethostid 142
   8, // 4.3 sethostid 143
   8, // 4.3 getrlimit`144
   8, // 4.3 setrlimit 145
   8, // 4.3 killpg 146
   0, // __NR_setsid 147
   4, // __NR_quotactl 148
   8, // 4.3 quota 149
   8, // 4.3 getsockname 150
   8, // bsd/os sem_lock 151
   8, // bsd/os sem_wakeup 152
   8, // bsd/os asyncdaemon 153
   8, // unimp SYS_nlm_syscall 154
   8, // unimp SYS_nfssvc 155
   8, // 4.3 getdirentries 156
   8, // freebsd 4 statfs 157
   8, // freebsd 4 fstatfs 158
   8, // 159
   2, // __NR_lgetfh 160
   2, // __NR_getfh 161
   2, // __NR_freebsd4_getdomainname 162
   2, // __NR_freebsd4_setdomainname 163
   2, // __NR_freebsd4_uname 164
   2, // __NR_sysarch 165
   3, // __NR_rtprio 166
   8, // 167
   8, // 168
   8, // semsys 169
   8, // msgsys 170
   8, // shmsys 171
   9, // 172
   6, // __NR_freebsd6_pread 173 64 5
   6, // __NR_freebsd6_pwrite 174 64 5
   1, // __NR_setfib 175
   8, // unimpl __NR_ntp_adjtime 176
   8, // bsd/os sfork 177
   8, // bsd/os getdescriptor 178
   8, // bsd/os setdescriptor 179
   8, // 180
   1, // __NR_setgid 181
   1, // __NR_setegid 182
   1, // __NR_seteuid 183
   8, // obs lfs_bmapv 184
   8, // obs lfs_markv 185
   8, // obs lfs_segclean 186
   8, // obs lfs_segwait 187
   2, // __NR_freebsd11_stat 188
   2, // __NR_freebsd11_fstat 189
   2, // __NR_freebsd11_lstat 190
   2, // __NR_pathconf 191
   2, // __NR_fpathconf 192
   8, // 193
   2, // __NR_getrlimit 194
   2, // __NR_setrlimit, 195
   4, // __NR_freebsd11_getdirentries 196
   8, // __NR_freebsd6_mmap 197 64 7
   8, // __syscall (handled specially) 198
   5, // __NR_freebsd6_lseek 199 64 4
   4, // __NR_freebsd6_truncate 200 64 3
   4, // __NR_freebsd6_ftruncate 201 64 3
   6, // __NR___sysctl 202
   2, // __NR_mlock 203
   2, // __NR_munlock 204
   1, // __NR_undelete 205
   2, // __NR_futimes 206
   1, // __NR_getpgid 207
   8, // netbsd newreboot 208
   3, // __NR_poll 209
   8, // 210
   8, // 211
   8, // 212
   8, // 213
   8, // 214
   8, // 215
   8, // 216
   8, // 217
   8, // 218
   8, // 219
   4, // __NR_freebsd7___semctl 220
   3, // __NR_semget 221
   3, // __NR_semop 222
   8, // obs semconfig 223
   3, // __NR_freebsd7_msgctl 224
   2, // __NR_msgget 225
   4, // __NR_msgsnd 226
   5, // _NR_msgrcv 227
   3, // __NR_shmat 228
   3, // __NR_freebsd7_shmctl 229
   1, // __NR_shmdt 230
   2, // __NR_shmget 231
   2, // __NR_clock_gettime 232
   2, // __NR_clock_settime 233
   2, // __NR_clock_getres 234
   3, // __NR_ktimer_create 235
   1, // __NR_ktimer_delete 236
   4, // __NR_ktimer_settime 237
   2, // __NR_ktimer_gettime 238
   1, // __NR_ktimer_getoverrun 239
   2, // _NR_nanosleep 240
   8, // unimpl SYS_ffclock_getcounter 241
   8, // unimpl SYS_ffclock_setestimate 242
   8, // unimpl SYS_ffclock_getestimate 243
   4, // __NR_clock_nanosleep 244
   8, // 245
   8, // 246
   8, // unimpl SYS_clock_getcpuclockid2 247
   8, // unimpl SYS_ntp_gettime 248
   8, // 249
   3, // __NR_minherit 250
   1, // __NR_rfork 251
   8, // openbsd_poll 252
   0, // __NR_issetugid 253
   3, // __NR_lchown 254
   1, // __NR_aio_read 255
   1, // __NR_aio_write 256
   4, // __NR_lio_listio 257
   8, // 258
   8, // 259
   8, // 260
   8, // 261
   8, // 262
   8, // 263
   8, // 264
   8, // 265
   8, // 266
   8, // 267
   8, // 268
   8, // 269
   8, // 270
   8, // 271
   3, // __NR_freebsd11_getdents 272
   8, // 273
   2, // __NR_lchmod 274
   8, // netbsd_lchown 275
   2, // __NR_lutimes 276
   8, // netbsd msync 277
   8, // unimpl SYS_freebsd11_nstat 278
   8, // unimpl SYS_freebsd11_nfstat 279
   8, // unimpl SYS_freebsd11_nlstat 280
   8, // 281
   8, // 282
   8, // 283
   8, // 284
   8, // 285
   8, // 286
   8, // 287
   8, // 288
   5, // __NR_preadv 289 4 64
   5, // __NR_pwritev 290 4 64
   8, // 291
   8, // 292
   8, // 293
   8, // 294
   8, // 295
   8, // 296
   8, // freebsd 4 fhstatfs 297
   2, // __NR_fhopen 298
   2, // __NR_freebsd11_fhstat 299
   1, // __NR_modnext 300
   2, // __NR_modstat 301
   1, // __NR_modfnext 302
   1, // __NR_modfind 303
   1, // __NR_kldload 304
   1, // __NR_kldunload 305
   1, // __NR_kldfind 306
   1, // __NR_kldnext 307
   2, // __NR_kldstat 308
   1, // __NR_kldfirstmod 309
   1, // __NR_getsid 310
   3, // __NR_setresuid 311
   3, // __NR_setresgid 312
   8, // obsol signanosleep 313
   1, // __NR_aio_return 314
   3, // __NR_aio_suspend 315
   2, // __NR_aio_cancel 316
   1, // __NR_aio_error 317
   8, // freebsd 6 aio_read 318
   8, // freebsd 6 aio_write 319
   8, // freebsd 6 lio_listio 320
   0, // __NR_yield 321
   8, // obs thr_sleep 322
   8, // obs thr_wakeup 323
   1, // __NR_mlockall 324
   0, // __NR_munlockall 325
   2, // __NR___getcwd 326
   2, // __NR_sched_setparam 327
   2, // __NR_sched_getparam 328
   3, // __NR_sched_setscheduler 329
   1, // __NR_sched_getscheduler 330
   0, // __NR_sched_yield 331
   1, // __NR_sched_get_priority_max 332
   1, // __NR_sched_get_priority_min 333
   2, // __NR_sched_rr_get_interval 334
   2, // __NR_utrace 335
   8, // freebsd 4 sendfile 336
   3, // __NR_kldsym 337
   1, // __NR_jail 338
   8, // unimpl SYS_nnpfs_syscall 339
   3, // __NR_sigprocmask 340
   1, // __NR_sigsuspend 341
   8, // freebsd 4 sigaction 342
   1, // __NR_sigpending 343
   8, // freebsd 4 sigreturn 344
   3, // __NR_sigtimedwait 345
   2, // __NR_sigwaitinfo 346
   3, // __NR___acl_get_file 347
   3, // __NR___acl_set_file 348
   3, // __NR___acl_get_fd 349
   3, // __NR___acl_set_fd 350
   2, // __NR___acl_delete_file 351
   2, // __NR___acl_delete_fd 352
   3, // __NR___acl_aclcheck_file 353
   3, // __NR___acl_aclcheck_fd 354
   5, // __NR_extattrctl 355
   5, // __NR_extattr_set_file 356
   5, // __NR_extattr_get_file 357
   3, // __NR_extattr_delete_file 358
   2, // __NR_aio_waitcomplete 359
   3, // __NR_getresuid 360
   3, // __NR_getresgid 361
   0, // __NR_kqueue 362
   6, // __NR_freebsd11_kevent 363
   8, // obs __cap_get_proc 364
   8, // obs __cap_set_proc 365
   8, // obs __cap_get_fd 366
   8, // obs __cap_get_file 367
   8, // obs __cap_set_fd 368
   8, // obs __cap_set_file 369
   8, // 370
   5, // __NR_extattr_set_fd 371
   5, // __NR_extattr_get_fd 372
   3, // __NR_extattr_delete_fd 373
   1, // __NR___setugid 374
   8, // obs nfsclnt 375
   2, // __NR_eaccess 376
   8, // unimpl afs3_syscall 377
   3, // __NR_nmount 378
   8, // obs kse_exit 379
   8, // obs kse_wakeup 380
   8, // obs kse_create 381
   8, // obs kse_thr_interrupt 382
   8, // obs kse_release 383
   8, // unimpl __mac_get_proc 384
   8, // unimpl __mac_set_proc 385
   8, // unimpl __mac_get_fd 386
   8, // unimpl __mac_get_file 387
   8, // unimpl __mac_set_fd 388
   8, // unimpl __mac_set_file 389
   4, // __NR_kenv 390
   2, // __NR_lchflags 391
   2, // __NR_uuidgen 392
   8, // __NR_sendfile 393 7 64
   8, // unimpl mac_syscall 394
   3, // __NR_freebsd11_getfsstat 395
   2, // __NR_freebsd11_statfs 396
   2, // __NR_freebsd11_fstatfs 397
   2, // __NR_freebsd11_fhstatfs 398
   8, // 399
   8, // unimpl ksem_close 400
   8, // unimpl ksem_post 401
   8, // unimpl ksem_wait 402
   8, // unimpl ksem_trywait 403
   8, // unimpl ksem_init 404
   8, // unimpl ksem_open 405
   8, // unimpl ksem_unlink 406
   8, // unimpl ksem_getvalue 407
   8, // unimpl ksem_destroy 408
   8, // unimpl __mac_get_pid 409
   8, // unimpl __mac_get_link 410
   8, // unimpl __mac_set_link 411
   5, // __NR_extattr_set_link 412
   5, // __NR_extattr_get_link 413
   3, // __NR_extattr_delete_link 414
   8, // unimpl __mac_execve 415
   3, // __NR_sigaction 416
   1, // __NR_sigreturn 417
   8, // 418
   8, // 419
   8, // 420
   1, // __NR_getcontext 421
   1, // __NR_setcontext 422
   2, // __NR_swapcontext 423
   1, // __NR_swapoff 424
   3, // __NR___acl_get_link 425
   3, // __NR___acl_set_link 426
   2, // __NR___acl_delete_link 427
   3, // __NR___acl_aclcheck_link 428
   2, // __NR_sigwait 429
   3, // __NR_thr_create 430
   1, // __NR_thr_exit 431
   1, // __NR_thr_self 432
   2, // __NR_thr_kill 433
   1, // __NR__umtx_lock 434
   1, // __NR__umtx_unlock 435
   1, // __NR_jail_attach 436
   4, // __NR_extattr_list_fd 437
   4, // __NR_extattr_list_file 438
   4, // __NR_extattr_list_link 439
   8, // obs kse_switchin 440
   8, // unimpl ksem_timedwait 441
   1, // __NR_thr_suspend 442
   1, // __NR_thr_wake 443
   2, // __NR_kldunloadf 444
   8, // unimpl audit 445
   8, // unimpl auditon 446
   8, // unimpl getauid 447
   8, // unimpl setauid 448
   8, // unimpl getaudit 449
   8, // unimpl setaudit 450
   8, // unimpl getaudit_addr 451
   8, // unimpl setaudit_addr 452
   8, // unimpl auditctl 453
   5, // __NR__umtx_op 454
   2, // __NR_thr_new 455
   3, // __NR_sigqueue 456
   4, // __NR_kmq_open 457
   3, // __NR_kmq_setattr 458
   5, // __NR_kmq_timedreceive 459
   5, // __NR_kmq_timedsend 460
   2, // __NR_kmq_notify 461
   1, // __NR_kmq_unlink 462
   3, // __NR_abort2 463
   2, // __NR_thr_set_name 464
   2, // __NR_aio_fsync 465
   3, // __NR_rtprio_thread 466
   8, // 467
   8, // 468
   8, // 469
   8, // 470
   8, // unimpl sctp_peeloff 471
   8, // unimpl sctp_generic_sendmsg 472
   8, // unimpl sctp_generic_sendmsg_iov 473
   8, // unimpl sctp_generic_recvmsg 474
   5, // __NR_pread 475 64 4
   5, // __NR_pwrite 476 64 4
   7, // __NR_mmap 477 64 6
   4, // __NR_lseek 478 64 3
   3, // __NR_truncate 479 64 2
   3, // __NR_ftruncate 480 64 2
   3, // __NR_thr_kill2 481
   3, // __NR_shm_open 482
   1, // __NR_shm_unlink 483
   1, // __NR_cpuset 484
   4, // __NR_cpuset_setidt_setid 485 64 3
   5, // __NR_cpuset_getid 486 64 4
   5, // __NR_cpuset_getaffinity 487
   5, // __NR_cpuset_setaffinity 488
   3, // __NR_faccessat 489
   4, // __NR_fchmodat 490
   5, // __NR_fchownat 491
   3, // __NR_fexecve 492
   4, // __NR_freebsd11_fstatat 493
   3, // __NR_futimesat 494
   5, // __NR_linkat 495
   3, // __NR_mkdirat 496
   3, // __NR_mkfifoat 497
   4, // __NR_freebsd11_mknodat 498
   4, // __NR_openat 499
   4, // __NR_readlinkat 500
   4, // __NR_renameat 501
   3, // __NR_symlinkat 502
   3, // __NR_unlinkat 503
   1, // __NR_posix_openpt 504
   8, // unimp gssd_syscall 505
   3, // __NR_jail_get 506
   3, // __NR_jail_set 507
   1, // __NR_jail_remove 508
   1, // __NR_closefrom 509
   4, // __NR___semctl 510
   3, // __NR_msgctl 511
   3, // __NR_shmctl 512
   2, // __NR_lpathconf 513
   8, /* 514 is obsolete cap_new */
   3, // __NR___cap_rights_get 515
   0, // __NR_cap_enter 516
   1, // __NR_cap_getmode 517
   2, // __NR_pdfork 518
   2, // __NR_pdkill 519
   2, // __NR_pdgetpid 520
   8, // 521
   6, // __NR_pselect 522
   2, // __NR_getloginclass 523
   1, // __NR_setloginclass 524
   4, // __NR_rctl_get_racct 525
   4, // __NR_rctl_get_rules 526
   4, // __NR_rctl_get_limits 527
   2, // __NR_rctl_add_rule 528
   2, // __NR_rctl_remove_rule 529
   5, // __NR_posix_fallocate 530 64 3
   6, // __NR_posix_fadvise 531 64 4
   7, // __NR_wait6 532 64 6
   2, // __NR_cap_rights_limit 533
   3, // __NR_cap_ioctls_limit 534
   3, // __NR_cap_ioctls_get 535
   2, // __NR_cap_fcntls_limit 536
   2, // __NR_cap_fcntls_get 537
   4, // __NR_bindat 538
   4, // __NR_connectat 539
   4, // __NR_chflagsat 540
   4, // __NR_accept4m541
   2, // __NR_pipe2 542
   1, // __NR_aio_mlock 543
   5, // __NR_procctl 544 64 4
#if (FREEBSD_VERS >= FREEBSD_10)
   4, // __NR_ppoll 545
   2, // __NR_futimens 546
   4, // __NR_utimensat 547
#endif // FREEBSD_VERS >= FREEBSD_11
#if (FREEBSD_VERS >= FREEBSD_11)
   8, /* 548 is obsolete numa_getaffinity */
   8, /* 549 is obsolete numa_setaffinity */
   1, // __NR_fdatasync 550
#endif // FREEBSD_VERS >= FREEBSD_11
#if (FREEBSD_VERS >= FREEBSD_12)
   2, // __NR_fstat 551
   4, // __NR_fstatat 552
   2, // __NR_fhstat 553
   4, // __NR_getdirentries 554
   2, // _NR_statfs 555
   2, // __NR_fstatfs 556
   3, // __NR_getfsstat 557
   2, // _NR_fhstatfs 558
   4, // __NR_mknodat 559
   6, // __NR_kevent 560
   7, // __NR_cpuset_getdomain 561 64 6
   7, // __NR_cpuset_setdomain 562 64 6
   3, // __NR_getrandom 563
   4, // __NR_getfhat 564
   2, // __NR_fhlink 565
   3, // __NR_fhlinkat 566
   3, // __NR_fhreadlink 567
#endif // FREEBSD_VERS >= FREEBSD_12
};

STATIC_ASSERT(sizeof(ML_(syscall_arg_counts))/sizeof(ML_(syscall_arg_counts)[0]) == __NR_max_syscall+1);


#endif /* defined(VGP_x86_freebsd) */


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
