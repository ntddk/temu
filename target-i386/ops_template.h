/*
 *  i386 micro operations (included several times to generate
 *  different operand sizes)
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#define DATA_BITS (1 << (3 + SHIFT))
#if TAINT_ENABLED
#define DATA_BYTES ((DATA_BITS<=32)? DATA_BITS/8:4)
#endif

#define SHIFT_MASK (DATA_BITS - 1)
#define SIGN_MASK (((target_ulong)1) << (DATA_BITS - 1))
#if DATA_BITS <= 32
#define SHIFT1_MASK 0x1f
#else
#define SHIFT1_MASK 0x3f
#endif

#if DATA_BITS == 8
#define SUFFIX b
#define DATA_TYPE uint8_t
#define DATA_STYPE int8_t
#define DATA_MASK 0xff
#elif DATA_BITS == 16
#define SUFFIX w
#define DATA_TYPE uint16_t
#define DATA_STYPE int16_t
#define DATA_MASK 0xffff
#elif DATA_BITS == 32
#define SUFFIX l
#define DATA_TYPE uint32_t
#define DATA_STYPE int32_t
#define DATA_MASK 0xffffffff
#elif DATA_BITS == 64
#define SUFFIX q
#define DATA_TYPE uint64_t
#define DATA_STYPE int64_t
#define DATA_MASK 0xffffffffffffffffULL
#else
#error unhandled operand size
#endif

/* dynamic flags computation */

#if TAINT_FLAGS
extern uint32_t TEMU_eflags;
#define CC_MASK (CC_C|CC_P|CC_A|CC_Z|CC_S|CC_O)
#define UPDATE_CC_FLAGS(ccflags) \
  do { \
    TEMU_eflags = env->eflags & ~CC_MASK; \
    TEMU_eflags |= CC_MASK & (ccflags); \
  }while (0);

#define UPDATE_CF(cf) \
  do { \
    TEMU_eflags = env->eflags & ~CC_C; \
    TEMU_eflags |= (cf) & CC_C; \
  }while (0);
  
#define UPDATE_SOME_FLAGS(mask, flags) \
  do { \
    TEMU_eflags = env->eflags & ~(mask); \
    TEMU_eflags |= (flags) & (mask); \
  }while (0);
  
#endif

static int glue(compute_all_add, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_SRC;
    src2 = CC_DST - CC_SRC;
    cf = (DATA_TYPE)CC_DST < (DATA_TYPE)src1;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_add, SUFFIX)(void)
{
    int cf;
    target_long src1;
    src1 = CC_SRC;
    cf = (DATA_TYPE)CC_DST < (DATA_TYPE)src1;
#if TAINT_FLAGS
	UPDATE_CF(cf);
    taintcheck_update_eflags(CC_C); 
#endif
    return cf;
}

static int glue(compute_all_adc, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_SRC;
    src2 = CC_DST - CC_SRC - 1;
    cf = (DATA_TYPE)CC_DST <= (DATA_TYPE)src1;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2 ^ -1) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_adc, SUFFIX)(void)
{
    int cf;
    target_long src1;
    src1 = CC_SRC;
    cf = (DATA_TYPE)CC_DST <= (DATA_TYPE)src1;
#if TAINT_FLAGS
	UPDATE_CF(cf);
    taintcheck_update_eflags(CC_C);
#endif
    return cf;
}

static int glue(compute_all_sub, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;
    cf = (DATA_TYPE)src1 < (DATA_TYPE)src2;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_sub, SUFFIX)(void)
{
    int cf;
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;
    cf = (DATA_TYPE)src1 < (DATA_TYPE)src2;
#if TAINT_FLAGS
	UPDATE_CF(cf);
    taintcheck_update_eflags(CC_C);
#endif
    return cf;
}

static int glue(compute_all_sbb, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_DST + CC_SRC + 1;
    src2 = CC_SRC;
    cf = (DATA_TYPE)src1 <= (DATA_TYPE)src2;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_sbb, SUFFIX)(void)
{
    int cf;
    target_long src1, src2;
    src1 = CC_DST + CC_SRC + 1;
    src2 = CC_SRC;
    cf = (DATA_TYPE)src1 <= (DATA_TYPE)src2;
#if TAINT_FLAGS
	UPDATE_CF(cf);
    taintcheck_update_eflags(CC_C);
#endif
    return cf;
}

static int glue(compute_all_logic, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    cf = 0;
    pf = parity_table[(uint8_t)CC_DST];
    af = 0;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = 0;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_logic, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_CF(0);
    taintcheck_reg_clean(R_CC_SRC);
    taintcheck_reg_clean(R_CC_DST);
    taintcheck_update_eflags(CC_C);
#endif
    return 0;
}

static int glue(compute_all_inc, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_DST - 1;
    src2 = 1;
    cf = CC_SRC;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = ((CC_DST & DATA_MASK) == SIGN_MASK) << 11;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

#if DATA_BITS == 32
static int glue(compute_c_inc, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_CF(CC_SRC);
    taintcheck_reg_clean(R_CC_SRC);
    taintcheck_reg_clean(R_CC_DST);
    taintcheck_update_eflags(CC_C);
#endif
    return CC_SRC;
}
#endif

static int glue(compute_all_dec, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    target_long src1, src2;
    src1 = CC_DST + 1;
    src2 = 1;
    cf = CC_SRC;
    pf = parity_table[(uint8_t)CC_DST];
    af = (CC_DST ^ src1 ^ src2) & 0x10;
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = ((CC_DST & DATA_MASK) == ((target_ulong)SIGN_MASK - 1)) << 11;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_all_shl, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    cf = (CC_SRC >> (DATA_BITS - 1)) & CC_C;
    pf = parity_table[(uint8_t)CC_DST];
    af = 0; /* undefined */
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    /* of is defined if shift count == 1 */
    of = lshift(CC_SRC ^ CC_DST, 12 - DATA_BITS) & CC_O;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

static int glue(compute_c_shl, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_CF((CC_SRC >> (DATA_BITS - 1)) & CC_C);
    taintcheck_update_eflags(CC_C);
#endif
    return (CC_SRC >> (DATA_BITS - 1)) & CC_C;
}

#if DATA_BITS == 32
static int glue(compute_c_sar, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_CF(CC_SRC & 1);
    taintcheck_update_eflags(CC_C);
#endif
    return CC_SRC & 1;
}
#endif

static int glue(compute_all_sar, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    cf = CC_SRC & 1;
    pf = parity_table[(uint8_t)CC_DST];
    af = 0; /* undefined */
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    /* of is defined if shift count == 1 */
    of = lshift(CC_SRC ^ CC_DST, 12 - DATA_BITS) & CC_O; 
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

#if DATA_BITS == 32
static int glue(compute_c_mul, SUFFIX)(void)
{
    int cf;
    cf = (CC_SRC != 0);
#if TAINT_FLAGS
	UPDATE_CF(cf);
    taintcheck_update_eflags(CC_C);
#endif
    return cf;
}
#endif

/* NOTE: we compute the flags like the P4. On olders CPUs, only OF and
   CF are modified and it is slower to do that. */
static int glue(compute_all_mul, SUFFIX)(void)
{
    int cf, pf, af, zf, sf, of;
    cf = (CC_SRC != 0);
    pf = parity_table[(uint8_t)CC_DST];
    af = 0; /* undefined */
    zf = ((DATA_TYPE)CC_DST == 0) << 6;
    sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    of = cf << 11;
#if TAINT_FLAGS
	UPDATE_CC_FLAGS(cf | pf | af | zf | sf | of);
    taintcheck_update_all_eflags();
#endif
    return cf | pf | af | zf | sf | of;
}

/* various optimized jumps cases */

void OPPROTO glue(op_jb_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;
#if TAINT_FLAGS
	UPDATE_CF((DATA_TYPE)src1 < (DATA_TYPE)src2);
    taintcheck_update_eflags(CC_C);
#endif

    if ((DATA_TYPE)src1 < (DATA_TYPE)src2)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jz_sub, SUFFIX)(void)
{
#if TAINT_FLAGS
    UPDATE_SOME_FLAGS(CC_Z, ((DATA_TYPE)CC_DST == 0)? CC_Z : 0);
    taintcheck_update_eflags(CC_Z);
#endif
    if ((DATA_TYPE)CC_DST == 0)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jnz_sub, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_Z, ((DATA_TYPE)CC_DST == 0)? CC_Z : 0);
    taintcheck_update_eflags(CC_Z);
#endif
    if ((DATA_TYPE)CC_DST != 0)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jbe_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_C|CC_Z, (((DATA_TYPE)src1 == (DATA_TYPE)src2)? CC_Z : 0) |
					 (((DATA_TYPE)src1 < (DATA_TYPE)src2)? CC_C : 0));
    taintcheck_update_eflags(CC_C|CC_Z);
#endif

    if ((DATA_TYPE)src1 <= (DATA_TYPE)src2)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_js_sub, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_S, (CC_DST & SIGN_MASK)? CC_S : 0);
    taintcheck_update_eflags(CC_S);
#endif
    if (CC_DST & SIGN_MASK)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jl_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;
#if TAINT_FLAGS
    int sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    int of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
    UPDATE_SOME_FLAGS(CC_S | CC_O, sf | of);
    taintcheck_update_eflags(CC_S | CC_O);
#endif

    if ((DATA_STYPE)src1 < (DATA_STYPE)src2)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jle_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

#if TAINT_FLAGS
    int sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    int of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
    int zf =  ((DATA_STYPE)src1 == (DATA_STYPE)src2)? CC_Z: 0;
    UPDATE_SOME_FLAGS(CC_S | CC_O | CC_Z, sf | of | zf);
    taintcheck_update_eflags(CC_S | CC_O | CC_Z);
#endif

    if ((DATA_STYPE)src1 <= (DATA_STYPE)src2)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

/* oldies */

#if DATA_BITS >= 16

void OPPROTO glue(op_loopnz, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_Z, T0 & CC_Z);
    //FIXME
#endif
    if ((DATA_TYPE)ECX != 0 && !(T0 & CC_Z))
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_loopz, SUFFIX)(void)
{
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_Z, T0 & CC_Z);
    //FIXME
#endif
    if ((DATA_TYPE)ECX != 0 && (T0 & CC_Z))
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jz_ecx, SUFFIX)(void)
{
    if ((DATA_TYPE)ECX == 0)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

void OPPROTO glue(op_jnz_ecx, SUFFIX)(void)
{
    if ((DATA_TYPE)ECX != 0)
        GOTO_LABEL_PARAM(1);
    FORCE_RET();
}

#endif

/* various optimized set cases */

void OPPROTO glue(op_setb_T0_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

    T0 = ((DATA_TYPE)src1 < (DATA_TYPE)src2);
#if TAINT_ENABLED
	taintcheck_fn2regs(R_CC_SRC, R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
    UPDATE_CF(T0? CC_C:0);
    //FIXME
#endif

}

void OPPROTO glue(op_setz_T0_sub, SUFFIX)(void)
{
    T0 = ((DATA_TYPE)CC_DST == 0);
#if TAINT_ENABLED
    taintcheck_reg2reg(R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_Z, T0? CC_Z:0);
    //FIXME
#endif

}

void OPPROTO glue(op_setbe_T0_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

    T0 = ((DATA_TYPE)src1 <= (DATA_TYPE)src2);
#if TAINT_ENABLED
	taintcheck_fn2regs(R_CC_SRC, R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
    int zf = ((DATA_TYPE)src1 == (DATA_TYPE)src2)? CC_Z : 0;
    int cf = ((DATA_TYPE)src1 < (DATA_TYPE)src2)? CC_C : 0;
    UPDATE_SOME_FLAGS(CC_Z | CC_C, zf | cf);
    taintcheck_update_eflags(CC_Z | CC_C);
#endif

}

void OPPROTO glue(op_sets_T0_sub, SUFFIX)(void)
{
    T0 = lshift(CC_DST, -(DATA_BITS - 1)) & 1;
#if TAINT_ENABLED
    taintcheck_reg2reg(R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
	UPDATE_SOME_FLAGS(CC_S, T0? CC_S : 0);
    //FIXME
#endif
}

void OPPROTO glue(op_setl_T0_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

    T0 = ((DATA_STYPE)src1 < (DATA_STYPE)src2);
#if TAINT_ENABLED
	taintcheck_fn2regs(R_CC_SRC, R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
    int sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    int of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
    UPDATE_SOME_FLAGS(CC_S | CC_O, sf | of);
    taintcheck_update_eflags(CC_S | CC_O);
#endif
}

void OPPROTO glue(op_setle_T0_sub, SUFFIX)(void)
{
    target_long src1, src2;
    src1 = CC_DST + CC_SRC;
    src2 = CC_SRC;

    T0 = ((DATA_STYPE)src1 <= (DATA_STYPE)src2);
#if TAINT_ENABLED
	taintcheck_fn2regs(R_CC_SRC, R_CC_DST, R_T0, 4);
#endif
#if TAINT_FLAGS
    int zf = ((DATA_TYPE)CC_DST == 0) << 6;
    int sf = lshift(CC_DST, 8 - DATA_BITS) & 0x80;
    int of = lshift((src1 ^ src2) & (src1 ^ CC_DST), 12 - DATA_BITS) & CC_O;
    UPDATE_SOME_FLAGS(CC_S | CC_O | CC_Z, sf | of | zf);
    taintcheck_update_eflags(CC_S | CC_O | CC_Z);
#endif
}

/* shifts */

void OPPROTO glue(glue(op_shl, SUFFIX), _T0_T1)(void)
{
    int count;
    count = T1 & SHIFT1_MASK;
    T0 = T0 << count;
#if TAINT_ENABLED
    taintcheck_fn2regs(R_T0, R_T1, R_T0, 2);
    taintcheck_fn1reg(R_T0, 4);
#endif
    
    FORCE_RET();
}

void OPPROTO glue(glue(op_shr, SUFFIX), _T0_T1)(void)
{
    int count;
    count = T1 & SHIFT1_MASK;
    T0 &= DATA_MASK;
    T0 = T0 >> count;
#if TAINT_ENABLED
	taintcheck_reg_clean2(R_T1*4+2, 2);
	taintcheck_reg_clean2(R_T0*4+DATA_BYTES, 4-DATA_BYTES);
    taintcheck_fn2regs(R_T0, R_T1, R_T0, DATA_BYTES);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_sar, SUFFIX), _T0_T1)(void)
{
    int count;
    target_long src;

    count = T1 & SHIFT1_MASK;
    src = (DATA_STYPE)T0;
    T0 = src >> count;
#if TAINT_ENABLED
//	taintcheck_reg_clean2(R_T1*4+2, 2);
//	taintcheck_reg_clean2(R_T0*4+DATA_BYTES, 4-DATA_BYTES);
    taintcheck_fn2regs(R_T0, R_T1, R_T0, DATA_BYTES);
#endif
    FORCE_RET();
}

#undef MEM_WRITE
#include "ops_template_mem.h"

#define MEM_WRITE 0
#include "ops_template_mem.h"

#if !defined(CONFIG_USER_ONLY)
#define MEM_WRITE 1
#include "ops_template_mem.h"

#define MEM_WRITE 2
#include "ops_template_mem.h"
#endif

/* bit operations */
#if DATA_BITS >= 16

void OPPROTO glue(glue(op_bt, SUFFIX), _T0_T1_cc)(void)
{
    int count;
    count = T1 & SHIFT_MASK;
    CC_SRC = T0 >> count;
#if TAINT_FLAGS
//	taintcheck_reg_clean2(R_T1*4+1, 3);
	taintcheck_reg2reg(R_T0, R_CC_SRC, 4);
#endif
}

void OPPROTO glue(glue(op_bts, SUFFIX), _T0_T1_cc)(void)
{
    int count;
    count = T1 & SHIFT_MASK;
    T1 = T0 >> count;
    T0 |= (((target_long)1) << count);
#if TAINT_ENABLED
	taintcheck_reg_clean2(R_T1*4+1, 3);
    taintcheck_fn2regs(R_T0, R_T1, R_T0, 4);
    taintcheck_reg2reg(R_T0, R_T1, 4); //not very correct
#endif
}

void OPPROTO glue(glue(op_btr, SUFFIX), _T0_T1_cc)(void)
{
    int count;
    count = T1 & SHIFT_MASK;
    T1 = T0 >> count;
    T0 &= ~(((target_long)1) << count);
#if TAINT_ENABLED
	taintcheck_reg_clean2(R_T1*4+1, 3);
    taintcheck_fn2regs(R_T0, R_T1, R_T0, 4);
    taintcheck_reg2reg(R_T0, R_T1, 4);
#endif
}

void OPPROTO glue(glue(op_btc, SUFFIX), _T0_T1_cc)(void)
{
    int count;
    count = T1 & SHIFT_MASK;
    T1 = T0 >> count;
    T0 ^= (((target_long)1) << count);
#if TAINT_ENABLED
	taintcheck_reg_clean2(R_T1*4+1, 3);
    taintcheck_fn2regs(R_T0, R_T1, R_T0, 4);
    taintcheck_reg2reg(R_T0, R_T1, 4);
#endif
}

void OPPROTO glue(glue(op_add_bit, SUFFIX), _A0_T1)(void)
{
    A0 += ((DATA_STYPE)T1 >> (3 + SHIFT)) << SHIFT;
#if TAINT_ENABLED
	taintcheck_reg_clean2(R_T1*4+DATA_BYTES, 4-DATA_BYTES);
    taintcheck_fn2regs(R_A0, R_T1, R_A0, 4);
#endif
}

void OPPROTO glue(glue(op_bsf, SUFFIX), _T0_cc)(void)
{
    int count;
    target_long res;
    
    res = T0 & DATA_MASK;
    if (res != 0) {
        count = 0;
        while ((res & 1) == 0) {
            count++;
            res >>= 1;
        }
        T1 = count;
#if TAINT_ENABLED
		taintcheck_reg_clean2(R_T0*4+DATA_BYTES, 4-DATA_BYTES); 
        taintcheck_reg2reg(R_T0, R_T1, 4);
        taintcheck_fn1reg(R_T1, 4);
#endif
        CC_DST = 1; /* ZF = 0 */
    } else {
        CC_DST = 0; /* ZF = 1 */
    }
#if TAINT_FLAGS
	taintcheck_reg_clean(R_CC_DST);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_bsr, SUFFIX), _T0_cc)(void)
{
    int count;
    target_long res;

    res = T0 & DATA_MASK;
    if (res != 0) {
        count = DATA_BITS - 1;
        while ((res & SIGN_MASK) == 0) {
            count--;
            res <<= 1;
        }
        T1 = count;
#if TAINT_ENABLED
		taintcheck_reg_clean2(R_T0*4+DATA_BYTES, 4-DATA_BYTES); 
        taintcheck_reg2reg(R_T0, R_T1, 4);
        taintcheck_fn1reg(R_T1, 4);
#endif
        CC_DST = 1; /* ZF = 0 */
    } else {
        CC_DST = 0; /* ZF = 1 */
    }
#if TAINT_FLAGS
	taintcheck_reg_clean(R_CC_DST);
#endif
    FORCE_RET();
}

#endif

#if DATA_BITS == 32
void OPPROTO op_update_bt_cc(void)
{
    CC_SRC = T1;
#if TAINT_FLAGS
	taintcheck_reg2reg(R_T1, R_CC_SRC, 4);
#endif
}
#endif

/* string operations */

void OPPROTO glue(op_movl_T0_Dshift, SUFFIX)(void)
{
    T0 = DF << SHIFT;
#if TAINT_ENABLED
    taintcheck_reg_clean(R_T0);
#endif
}

/* port I/O */
#if DATA_BITS <= 32
void OPPROTO glue(glue(op_out, SUFFIX), _T0_T1)(void)
{
    env->tempidx = R_T1;
    glue(cpu_out, SUFFIX)(env, T0, T1 & DATA_MASK);
    env->tempidx = 0;
}

void OPPROTO glue(glue(op_in, SUFFIX), _T0_T1)(void)
{
#if TAINT_ENABLED
    taintcheck_reg_clean(R_T1);
#endif	
    env->tempidx = R_T1;
    T1 = glue(cpu_in, SUFFIX)(env, T0);
    env->tempidx = 0;
}

void OPPROTO glue(glue(op_in, SUFFIX), _DX_T0)(void)
{
#if TAINT_ENABLED
    taintcheck_reg_clean(R_T0);
#endif	
    env->tempidx = R_T0;
    T0 = glue(cpu_in, SUFFIX)(env, EDX & 0xffff);
    env->tempidx = 0;
}

void OPPROTO glue(glue(op_out, SUFFIX), _DX_T0)(void)
{
    env->tempidx = R_T0;
    glue(cpu_out, SUFFIX)(env, EDX & 0xffff, T0);
    env->tempidx = 0;
}

void OPPROTO glue(glue(op_check_io, SUFFIX), _T0)(void)
{
    glue(glue(check_io, SUFFIX), _T0)();
}

void OPPROTO glue(glue(op_check_io, SUFFIX), _DX)(void)
{
    glue(glue(check_io, SUFFIX), _DX)();
}
#endif

#if TAINT_ENABLED
#undef DATA_BYTES
#endif
#undef DATA_BITS
#undef SHIFT_MASK
#undef SHIFT1_MASK
#undef SIGN_MASK
#undef DATA_TYPE
#undef DATA_STYPE
#undef DATA_MASK
#undef SUFFIX
