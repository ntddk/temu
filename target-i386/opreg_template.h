/*
 *  i386 micro operations (templates for various register related
 *  operations)
 * 
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

void OPPROTO glue(op_movl_A0,REGNAME)(void)
{
    A0 = (uint32_t)REG; 
#if TAINT_ENABLED
     taintcheck_reg2reg(NB_REG, R_A0, 4);
#endif

}

void OPPROTO glue(op_movw_A0,REGNAME)(void)
{
    A0 = (uint32_t)REG; 
#if TAINT_ENABLED
     taintcheck_reg2reg(NB_REG, R_A0, 2);
#endif

}


void OPPROTO glue(op_addl_A0,REGNAME)(void)
{
    A0 = (uint32_t)(A0 + REG);
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 4);
#endif
}

void OPPROTO glue(op_addw_A0,REGNAME)(void)
{
    A0 = (uint32_t)(A0 + REG);
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 2);
#endif
}


void OPPROTO glue(glue(op_addl_A0,REGNAME),_s1)(void)
{
    A0 = (uint32_t)(A0 + (REG << 1));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 4);
#endif
}

void OPPROTO glue(glue(op_addw_A0,REGNAME),_s1)(void)
{
    A0 = (uint32_t)(A0 + (REG << 1));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 2);
#endif
}


void OPPROTO glue(glue(op_addl_A0,REGNAME),_s2)(void)
{
    A0 = (uint32_t)(A0 + (REG << 2));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 4);
#endif
}

void OPPROTO glue(glue(op_addw_A0,REGNAME),_s2)(void)
{
    A0 = (uint32_t)(A0 + (REG << 2));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 2);
#endif
}

void OPPROTO glue(glue(op_addl_A0,REGNAME),_s3)(void)
{
    A0 = (uint32_t)(A0 + (REG << 3));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 4);
#endif
}

void OPPROTO glue(glue(op_addw_A0,REGNAME),_s3)(void)
{
    A0 = (uint32_t)(A0 + (REG << 3));
#if TAINT_ENABLED
    taintcheck_fn2regs(R_A0, NB_REG, R_A0, 2);
#endif
}


#ifdef TARGET_X86_64
void OPPROTO glue(op_movq_A0,REGNAME)(void)
{
    A0 = REG;
}

void OPPROTO glue(op_addq_A0,REGNAME)(void)
{
    A0 = (A0 + REG);
}

void OPPROTO glue(glue(op_addq_A0,REGNAME),_s1)(void)
{
    A0 = (A0 + (REG << 1));
}

void OPPROTO glue(glue(op_addq_A0,REGNAME),_s2)(void)
{
    A0 = (A0 + (REG << 2));
}

void OPPROTO glue(glue(op_addq_A0,REGNAME),_s3)(void)
{
    A0 = (A0 + (REG << 3));
}
#endif

void OPPROTO glue(op_movl_T0,REGNAME)(void)
{
    T0 = REG;
#if TAINT_ENABLED
    taintcheck_reg2reg(NB_REG, R_T0, 4);
#endif
}

/*
  I add two fake functions movb and movw, which are the same as movl, except 
  for the taint propagation.  --Heng yin
*/
void OPPROTO glue(op_movb_T0,REGNAME)(void) 
{
    T0 = REG;
#if TAINT_ENABLED
    taintcheck_reg2TN(NB_REG, R_T0, 1);
#endif
}

void OPPROTO glue(op_movw_T0,REGNAME)(void)
{
    T0 = REG;
#if TAINT_ENABLED
    taintcheck_reg2TN(NB_REG, R_T0, 2);
#endif
}


void OPPROTO glue(op_movl_T1,REGNAME)(void)
{
    T1 = REG;
#if TAINT_ENABLED
    taintcheck_reg2reg(NB_REG, R_T1, 4);
#endif
}

/*
  I add two fake functions movb and movw, which are the same as movl, except 
  for the taint propagation.  --Heng yin
*/
void OPPROTO glue(op_movb_T1,REGNAME)(void)
{
    T1 = REG;
#if TAINT_ENABLED
    taintcheck_reg2TN(NB_REG, R_T1, 1);
#endif
}

void OPPROTO glue(op_movw_T1,REGNAME)(void)
{
    T1 = REG;
#if TAINT_ENABLED
    taintcheck_reg2TN(NB_REG, R_T1, 2);
#endif
}


void OPPROTO glue(op_movh_T0,REGNAME)(void)
{
    T0 = REG >> 8;
#if TAINT_ENABLED
    taintcheck_regh2TN(NB_REG, R_T0);
#endif	
}

void OPPROTO glue(op_movh_T1,REGNAME)(void)
{
    T1 = REG >> 8;
#if TAINT_ENABLED
    taintcheck_regh2TN(NB_REG, R_T1);
#endif	
}

void OPPROTO glue(glue(op_movl,REGNAME),_T0)(void)
{
    REG = (uint32_t)T0;
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T0, NB_REG, 4);
#endif
}

void OPPROTO glue(glue(op_movl,REGNAME),_T1)(void)
{
    REG = (uint32_t)T1;
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T1, NB_REG, 4);
#endif
}

void OPPROTO glue(glue(op_movl,REGNAME),_A0)(void)
{
    REG = (uint32_t)A0;
#if TAINT_ENABLED
    taintcheck_reg2reg(R_A0, NB_REG, 4);
#endif
}

#ifdef TARGET_X86_64
void OPPROTO glue(glue(op_movq,REGNAME),_T0)(void)
{
    REG = T0;
}

void OPPROTO glue(glue(op_movq,REGNAME),_T1)(void)
{
    REG = T1;
}

void OPPROTO glue(glue(op_movq,REGNAME),_A0)(void)
{
    REG = A0;
}
#endif

/* mov T1 to REG if T0 is true */
void OPPROTO glue(glue(op_cmovw,REGNAME),_T1_T0)(void)
{
    if (T0)
        REG = (REG & ~0xffff) | (T1 & 0xffff);
#if TAINT_ENABLED
    if (T0)
        taintcheck_reg2reg(R_T1, NB_REG, 2);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_cmovl,REGNAME),_T1_T0)(void)
{
    if (T0)
        REG = (uint32_t)T1;
#if TAINT_ENABLED
    if (T0)
        taintcheck_reg2reg(R_T1, NB_REG, 4);
#endif

    FORCE_RET();
}

#ifdef TARGET_X86_64
void OPPROTO glue(glue(op_cmovq,REGNAME),_T1_T0)(void)
{
    if (T0)
        REG = T1;
    FORCE_RET();
}
#endif

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_movw,REGNAME),_T0)(void)
{
    REG = (REG & ~0xffff) | (T0 & 0xffff);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T0, NB_REG, 2);
#endif
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_movw,REGNAME),_T1)(void)
{
    REG = (REG & ~0xffff) | (T1 & 0xffff);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T1, NB_REG, 2);
#endif
}

/* NOTE: A0 high order bits are ignored */
void OPPROTO glue(glue(op_movw,REGNAME),_A0)(void)
{
    REG = (REG & ~0xffff) | (A0 & 0xffff);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_A0, NB_REG, 2);
#endif
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_movb,REGNAME),_T0)(void)
{
    REG = (REG & ~0xff) | (T0 & 0xff);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T0, NB_REG, 1);
#endif
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_movh,REGNAME),_T0)(void)
{
    REG = (REG & ~0xff00) | ((T0 & 0xff) << 8);
#if TAINT_ENABLED
    taintcheck_reg2reg_shift(R_T0*4, NB_REG*4+1, 1);
#endif
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_movb,REGNAME),_T1)(void)
{
    REG = (REG & ~0xff) | (T1 & 0xff);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_T1, NB_REG, 1);
#endif
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_movh,REGNAME),_T1)(void)
{
    REG = (REG & ~0xff00) | ((T1 & 0xff) << 8);
#if TAINT_ENABLED
    taintcheck_reg2reg_shift(R_T1*4, NB_REG*4+1, 1);
#endif
}

#if TAINT_ENABLED
#include "opt_opreg_template.h"
#endif
