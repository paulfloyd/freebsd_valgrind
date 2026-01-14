/*---------------------------------------------------------------*/
/*--- begin                               guest_generic_sse.h ---*/
/*---------------------------------------------------------------*/

/*
     This file is part of Valgrind, a dynamic binary instrumentation
     framework.

     Copyright (C) 2025-2026 Alexandra Hájková <ahajkova@redhat.com>

     This program is free software; you can redistribute it and/or
     modify it under the terms of the GNU General Public License as
     published by the Free Software Foundation; either version 3 of the
     License, or (at your option) any later version.

     This program is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with this program; if not, see <http://www.gnu.org/licenses/>.

     The GNU General Public License is contained in the file COPYING.
*/

/*   This file contains functions for SSE/SSE2/SSE3/SSE4-specific
     operations.  Both the amd64 and x86 front ends (guests) call
     these functions.  By putting them here, code duplication is
     avoided.  Some of these functions are tricky and hard to verify,
     so there is much to be said for only having one copy thereof.

     IMPORTANT: This header must be included AFTER the following
     helper functions/macros are defined in the including file:
       - newTemp(IRType)          - allocate a new IRTemp
       - assign(IRTemp, IRExpr*)  - create assignment statement
       - mkV128(UShort)           - create V128 constant expression
       - binop(IROp, IRExpr*, IRExpr*)  - create binary operation
       - unop(IROp, IRExpr*)      - create unary operation
       - mkexpr(IRTemp)           - create IRTemp expression
       - vassert(Bool)            - assertion macro

     These helper functions are defined locally in each guest_*_toIR.c
     file because they rely on file-local global state, particularly
     the 'irsb' variable (the IR super block being built). Moving them
     to a shared header would require either passing 'irsb' as a
     parameter to each call (breaking thousands of call sites) or
     making 'irsb' a shared extern (architecturally problematic).

     Therefore, this header is included after those helpers are defined,
     typically around line 300 in guest_*_toIR.c files.
*/

#ifndef __VEX_GUEST_GENERIC_SSE_H
#define __VEX_GUEST_GENERIC_SSE_H

#include "libvex_basictypes.h"
#include "libvex_ir.h"
#include "libvex.h"


/* BLENDPD 128-bit */
static inline IRTemp math_BLENDPD_128 ( IRTemp sV, IRTemp dV, UInt imm8 )
{
   UShort imm8_mask_16;
   IRTemp imm8_mask = newTemp(Ity_V128);

   switch( imm8 & 3 ) {
      case 0:  imm8_mask_16 = 0x0000; break;
      case 1:  imm8_mask_16 = 0x00FF; break;
      case 2:  imm8_mask_16 = 0xFF00; break;
      case 3:  imm8_mask_16 = 0xFFFF; break;
      default: vassert(0);            break;
   }
   assign( imm8_mask, mkV128( imm8_mask_16 ) );

   IRTemp res = newTemp(Ity_V128);
   assign ( res, binop( Iop_OrV128,
                        binop( Iop_AndV128, mkexpr(sV),
                                            mkexpr(imm8_mask) ),
                        binop( Iop_AndV128, mkexpr(dV),
                               unop( Iop_NotV128, mkexpr(imm8_mask) ) ) ) );
   return res;
}

#endif /* ndef __VEX_GUEST_GENERIC_SSE_H */

/*---------------------------------------------------------------*/
/*--- end                                 guest_generic_sse.h ---*/
/*---------------------------------------------------------------*/
