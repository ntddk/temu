int dyngen_code(uint8_t *gen_code_buf,
                uint16_t *label_offsets, uint16_t *jmp_offsets,
                const uint16_t *opc_buf, const uint32_t *opparam_buf, const long *gen_labels)
{
    uint8_t *gen_code_ptr;
    const uint16_t *opc_ptr;
    const uint32_t *opparam_ptr;

    gen_code_ptr = gen_code_buf;
    opc_ptr = opc_buf;
    opparam_ptr = opparam_buf;
    for(;;) {
        switch(*opc_ptr++) {
case INDEX_op_movl_A0_EAX: {
    extern void op_movl_A0_EAX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movw_A0_EAX: {
    extern void op_movw_A0_EAX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_addl_A0_EAX: {
    extern void op_addl_A0_EAX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EAX+0), 37);
    *(uint32_t *)(gen_code_ptr + 29) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 29) + -4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_addw_A0_EAX: {
    extern void op_addw_A0_EAX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EAX+0), 37);
    *(uint32_t *)(gen_code_ptr + 29) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 29) + -4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_addl_A0_EAX_s1: {
    extern void op_addl_A0_EAX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EAX_s1+0), 39);
    *(uint32_t *)(gen_code_ptr + 31) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 31) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_addw_A0_EAX_s1: {
    extern void op_addw_A0_EAX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EAX_s1+0), 39);
    *(uint32_t *)(gen_code_ptr + 31) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 31) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_addl_A0_EAX_s2: {
    extern void op_addl_A0_EAX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EAX_s2+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_addw_A0_EAX_s2: {
    extern void op_addw_A0_EAX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EAX_s2+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_addl_A0_EAX_s3: {
    extern void op_addl_A0_EAX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EAX_s3+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_addw_A0_EAX_s3: {
    extern void op_addw_A0_EAX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EAX_s3+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_movl_T0_EAX: {
    extern void op_movl_T0_EAX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movb_T0_EAX: {
    extern void op_movb_T0_EAX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movw_T0_EAX: {
    extern void op_movw_T0_EAX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movl_T1_EAX: {
    extern void op_movl_T1_EAX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movb_T1_EAX: {
    extern void op_movb_T1_EAX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movw_T1_EAX: {
    extern void op_movw_T1_EAX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_EAX+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movh_T0_EAX: {
    extern void op_movh_T0_EAX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_EAX+0), 30);
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 22) + -4;
    gen_code_ptr += 30;
}
break;

case INDEX_op_movh_T1_EAX: {
    extern void op_movh_T1_EAX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_EAX+0), 30);
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 22) + -4;
    gen_code_ptr += 30;
}
break;

case INDEX_op_movl_EAX_T0: {
    extern void op_movl_EAX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EAX_T0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movl_EAX_T1: {
    extern void op_movl_EAX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EAX_T1+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movl_EAX_A0: {
    extern void op_movl_EAX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EAX_A0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_cmovw_EAX_T1_T0: {
    extern void op_cmovw_EAX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_EAX_T1_T0+0), 63);
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 51) + -4;
    gen_code_ptr += 63;
}
break;

case INDEX_op_cmovl_EAX_T1_T0: {
    extern void op_cmovl_EAX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_EAX_T1_T0+0), 47);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 47;
}
break;

case INDEX_op_movw_EAX_T0: {
    extern void op_movw_EAX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EAX_T0+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_movw_EAX_T1: {
    extern void op_movw_EAX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EAX_T1+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_movw_EAX_A0: {
    extern void op_movw_EAX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EAX_A0+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_movb_EAX_T0: {
    extern void op_movb_EAX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EAX_T0+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_movh_EAX_T0: {
    extern void op_movh_EAX_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EAX_T0+0), 51);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 43) + -4;
    gen_code_ptr += 51;
}
break;

case INDEX_op_movb_EAX_T1: {
    extern void op_movb_EAX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EAX_T1+0), 40);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_movh_EAX_T1: {
    extern void op_movh_EAX_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EAX_T1+0), 51);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 43) + -4;
    gen_code_ptr += 51;
}
break;

case INDEX_op_opt_movl_A0_EAX: {
    extern void op_opt_movl_A0_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_EAX+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_addl_A0_EAX: {
    extern void op_opt_addl_A0_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EAX+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_addl_A0_EAX_s1: {
    extern void op_opt_addl_A0_EAX_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EAX_s1+0), 9);
    gen_code_ptr += 9;
}
break;

case INDEX_op_opt_addl_A0_EAX_s2: {
    extern void op_opt_addl_A0_EAX_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EAX_s2+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_EAX_s3: {
    extern void op_opt_addl_A0_EAX_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EAX_s3+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_movl_T0_EAX: {
    extern void op_opt_movl_T0_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_EAX+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_movl_T1_EAX: {
    extern void op_opt_movl_T1_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_EAX+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_movh_T0_EAX: {
    extern void op_opt_movh_T0_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_EAX+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_movh_T1_EAX: {
    extern void op_opt_movh_T1_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_EAX+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_movl_EAX_T0: {
    extern void op_opt_movl_EAX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EAX_T0+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_movl_EAX_T1: {
    extern void op_opt_movl_EAX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EAX_T1+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_movl_EAX_A0: {
    extern void op_opt_movl_EAX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EAX_A0+0), 7);
    gen_code_ptr += 7;
}
break;

case INDEX_op_opt_cmovw_EAX_T1_T0: {
    extern void op_opt_cmovw_EAX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_EAX_T1_T0+0), 24);
    gen_code_ptr += 24;
}
break;

case INDEX_op_opt_cmovl_EAX_T1_T0: {
    extern void op_opt_cmovl_EAX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_EAX_T1_T0+0), 15);
    gen_code_ptr += 15;
}
break;

case INDEX_op_opt_movw_EAX_T0: {
    extern void op_opt_movw_EAX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EAX_T0+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movw_EAX_T1: {
    extern void op_opt_movw_EAX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EAX_T1+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movw_EAX_A0: {
    extern void op_opt_movw_EAX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EAX_A0+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movb_EAX_T0: {
    extern void op_opt_movb_EAX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EAX_T0+0), 15);
    gen_code_ptr += 15;
}
break;

case INDEX_op_opt_movh_EAX_T0: {
    extern void op_opt_movh_EAX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EAX_T0+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_opt_movb_EAX_T1: {
    extern void op_opt_movb_EAX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EAX_T1+0), 15);
    gen_code_ptr += 15;
}
break;

case INDEX_op_opt_movh_EAX_T1: {
    extern void op_opt_movh_EAX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EAX_T1+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_movl_A0_ECX: {
    extern void op_movl_A0_ECX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_ECX: {
    extern void op_movw_A0_ECX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_ECX: {
    extern void op_addl_A0_ECX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ECX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_ECX: {
    extern void op_addw_A0_ECX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ECX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_ECX_s1: {
    extern void op_addl_A0_ECX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ECX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_ECX_s1: {
    extern void op_addw_A0_ECX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ECX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_ECX_s2: {
    extern void op_addl_A0_ECX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ECX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ECX_s2: {
    extern void op_addw_A0_ECX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ECX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_ECX_s3: {
    extern void op_addl_A0_ECX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ECX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ECX_s3: {
    extern void op_addw_A0_ECX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ECX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_ECX: {
    extern void op_movl_T0_ECX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_ECX: {
    extern void op_movb_T0_ECX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_ECX: {
    extern void op_movw_T0_ECX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_ECX: {
    extern void op_movl_T1_ECX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_ECX: {
    extern void op_movb_T1_ECX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_ECX: {
    extern void op_movw_T1_ECX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_ECX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_ECX: {
    extern void op_movh_T0_ECX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_ECX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_ECX: {
    extern void op_movh_T1_ECX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_ECX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_ECX_T0: {
    extern void op_movl_ECX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ECX_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ECX_T1: {
    extern void op_movl_ECX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ECX_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ECX_A0: {
    extern void op_movl_ECX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ECX_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_ECX_T1_T0: {
    extern void op_cmovw_ECX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_ECX_T1_T0+0), 66);
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 54) + -4;
    gen_code_ptr += 66;
}
break;

case INDEX_op_cmovl_ECX_T1_T0: {
    extern void op_cmovl_ECX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_ECX_T1_T0+0), 51);
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 39) + -4;
    gen_code_ptr += 51;
}
break;

case INDEX_op_movw_ECX_T0: {
    extern void op_movw_ECX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ECX_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ECX_T1: {
    extern void op_movw_ECX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ECX_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ECX_A0: {
    extern void op_movw_ECX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ECX_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_ECX_T0: {
    extern void op_movb_ECX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ECX_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ECX_T0: {
    extern void op_movh_ECX_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ECX_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_ECX_T1: {
    extern void op_movb_ECX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ECX_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ECX_T1: {
    extern void op_movh_ECX_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ECX_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_ECX: {
    extern void op_opt_movl_A0_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_ECX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ECX: {
    extern void op_opt_addl_A0_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ECX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ECX_s1: {
    extern void op_opt_addl_A0_ECX_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ECX_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_ECX_s2: {
    extern void op_opt_addl_A0_ECX_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ECX_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_ECX_s3: {
    extern void op_opt_addl_A0_ECX_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ECX_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_ECX: {
    extern void op_opt_movl_T0_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_ECX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_ECX: {
    extern void op_opt_movl_T1_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_ECX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_ECX: {
    extern void op_opt_movh_T0_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_ECX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_ECX: {
    extern void op_opt_movh_T1_ECX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_ECX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_ECX_T0: {
    extern void op_opt_movl_ECX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ECX_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ECX_T1: {
    extern void op_opt_movl_ECX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ECX_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ECX_A0: {
    extern void op_opt_movl_ECX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ECX_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_ECX_T1_T0: {
    extern void op_opt_cmovw_ECX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_ECX_T1_T0+0), 27);
    gen_code_ptr += 27;
}
break;

case INDEX_op_opt_cmovl_ECX_T1_T0: {
    extern void op_opt_cmovl_ECX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_ECX_T1_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movw_ECX_T0: {
    extern void op_opt_movw_ECX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ECX_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ECX_T1: {
    extern void op_opt_movw_ECX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ECX_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ECX_A0: {
    extern void op_opt_movw_ECX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ECX_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_ECX_T0: {
    extern void op_opt_movb_ECX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ECX_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ECX_T0: {
    extern void op_opt_movh_ECX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ECX_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_ECX_T1: {
    extern void op_opt_movb_ECX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ECX_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ECX_T1: {
    extern void op_opt_movh_ECX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ECX_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_EDX: {
    extern void op_movl_A0_EDX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_EDX: {
    extern void op_movw_A0_EDX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_EDX: {
    extern void op_addl_A0_EDX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_EDX: {
    extern void op_addw_A0_EDX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_EDX_s1: {
    extern void op_addl_A0_EDX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_EDX_s1: {
    extern void op_addw_A0_EDX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_EDX_s2: {
    extern void op_addl_A0_EDX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EDX_s2: {
    extern void op_addw_A0_EDX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_EDX_s3: {
    extern void op_addl_A0_EDX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EDX_s3: {
    extern void op_addw_A0_EDX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_EDX: {
    extern void op_movl_T0_EDX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_EDX: {
    extern void op_movb_T0_EDX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_EDX: {
    extern void op_movw_T0_EDX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_EDX: {
    extern void op_movl_T1_EDX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_EDX: {
    extern void op_movb_T1_EDX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_EDX: {
    extern void op_movw_T1_EDX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_EDX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_EDX: {
    extern void op_movh_T0_EDX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_EDX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_EDX: {
    extern void op_movh_T1_EDX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_EDX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_EDX_T0: {
    extern void op_movl_EDX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDX_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EDX_T1: {
    extern void op_movl_EDX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDX_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EDX_A0: {
    extern void op_movl_EDX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDX_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_EDX_T1_T0: {
    extern void op_cmovw_EDX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_EDX_T1_T0+0), 59);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 47) + -4;
    gen_code_ptr += 59;
}
break;

case INDEX_op_cmovl_EDX_T1_T0: {
    extern void op_cmovl_EDX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_EDX_T1_T0+0), 48);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 48;
}
break;

case INDEX_op_movw_EDX_T0: {
    extern void op_movw_EDX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDX_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EDX_T1: {
    extern void op_movw_EDX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDX_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EDX_A0: {
    extern void op_movw_EDX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDX_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_EDX_T0: {
    extern void op_movb_EDX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EDX_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EDX_T0: {
    extern void op_movh_EDX_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EDX_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_EDX_T1: {
    extern void op_movb_EDX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EDX_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EDX_T1: {
    extern void op_movh_EDX_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EDX_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_EDX: {
    extern void op_opt_movl_A0_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_EDX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EDX: {
    extern void op_opt_addl_A0_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EDX_s1: {
    extern void op_opt_addl_A0_EDX_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDX_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_EDX_s2: {
    extern void op_opt_addl_A0_EDX_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDX_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_EDX_s3: {
    extern void op_opt_addl_A0_EDX_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDX_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_EDX: {
    extern void op_opt_movl_T0_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_EDX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_EDX: {
    extern void op_opt_movl_T1_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_EDX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_EDX: {
    extern void op_opt_movh_T0_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_EDX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_EDX: {
    extern void op_opt_movh_T1_EDX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_EDX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_EDX_T0: {
    extern void op_opt_movl_EDX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDX_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EDX_T1: {
    extern void op_opt_movl_EDX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDX_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EDX_A0: {
    extern void op_opt_movl_EDX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDX_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_EDX_T1_T0: {
    extern void op_opt_cmovw_EDX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_EDX_T1_T0+0), 26);
    gen_code_ptr += 26;
}
break;

case INDEX_op_opt_cmovl_EDX_T1_T0: {
    extern void op_opt_cmovl_EDX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_EDX_T1_T0+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movw_EDX_T0: {
    extern void op_opt_movw_EDX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDX_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EDX_T1: {
    extern void op_opt_movw_EDX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDX_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EDX_A0: {
    extern void op_opt_movw_EDX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDX_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_EDX_T0: {
    extern void op_opt_movb_EDX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EDX_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EDX_T0: {
    extern void op_opt_movh_EDX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EDX_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_EDX_T1: {
    extern void op_opt_movb_EDX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EDX_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EDX_T1: {
    extern void op_opt_movh_EDX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EDX_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_EBX: {
    extern void op_movl_A0_EBX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_EBX: {
    extern void op_movw_A0_EBX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_EBX: {
    extern void op_addl_A0_EBX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_EBX: {
    extern void op_addw_A0_EBX();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBX+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_EBX_s1: {
    extern void op_addl_A0_EBX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_EBX_s1: {
    extern void op_addw_A0_EBX_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBX_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_EBX_s2: {
    extern void op_addl_A0_EBX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EBX_s2: {
    extern void op_addw_A0_EBX_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBX_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_EBX_s3: {
    extern void op_addl_A0_EBX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EBX_s3: {
    extern void op_addw_A0_EBX_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBX_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_EBX: {
    extern void op_movl_T0_EBX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_EBX: {
    extern void op_movb_T0_EBX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_EBX: {
    extern void op_movw_T0_EBX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_EBX: {
    extern void op_movl_T1_EBX();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_EBX: {
    extern void op_movb_T1_EBX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_EBX: {
    extern void op_movw_T1_EBX();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_EBX+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_EBX: {
    extern void op_movh_T0_EBX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_EBX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_EBX: {
    extern void op_movh_T1_EBX();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_EBX+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_EBX_T0: {
    extern void op_movl_EBX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBX_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EBX_T1: {
    extern void op_movl_EBX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBX_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EBX_A0: {
    extern void op_movl_EBX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBX_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_EBX_T1_T0: {
    extern void op_cmovw_EBX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_EBX_T1_T0+0), 58);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    gen_code_ptr += 58;
}
break;

case INDEX_op_cmovl_EBX_T1_T0: {
    extern void op_cmovl_EBX_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_EBX_T1_T0+0), 49);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 49;
}
break;

case INDEX_op_movw_EBX_T0: {
    extern void op_movw_EBX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBX_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EBX_T1: {
    extern void op_movw_EBX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBX_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EBX_A0: {
    extern void op_movw_EBX_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBX_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_EBX_T0: {
    extern void op_movb_EBX_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EBX_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EBX_T0: {
    extern void op_movh_EBX_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EBX_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_EBX_T1: {
    extern void op_movb_EBX_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EBX_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EBX_T1: {
    extern void op_movh_EBX_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EBX_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_EBX: {
    extern void op_opt_movl_A0_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_EBX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EBX: {
    extern void op_opt_addl_A0_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EBX_s1: {
    extern void op_opt_addl_A0_EBX_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBX_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_EBX_s2: {
    extern void op_opt_addl_A0_EBX_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBX_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_EBX_s3: {
    extern void op_opt_addl_A0_EBX_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBX_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_EBX: {
    extern void op_opt_movl_T0_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_EBX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_EBX: {
    extern void op_opt_movl_T1_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_EBX+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_EBX: {
    extern void op_opt_movh_T0_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_EBX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_EBX: {
    extern void op_opt_movh_T1_EBX();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_EBX+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_EBX_T0: {
    extern void op_opt_movl_EBX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBX_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EBX_T1: {
    extern void op_opt_movl_EBX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBX_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EBX_A0: {
    extern void op_opt_movl_EBX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBX_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_EBX_T1_T0: {
    extern void op_opt_cmovw_EBX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_EBX_T1_T0+0), 27);
    gen_code_ptr += 27;
}
break;

case INDEX_op_opt_cmovl_EBX_T1_T0: {
    extern void op_opt_cmovl_EBX_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_EBX_T1_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movw_EBX_T0: {
    extern void op_opt_movw_EBX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBX_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EBX_T1: {
    extern void op_opt_movw_EBX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBX_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EBX_A0: {
    extern void op_opt_movw_EBX_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBX_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_EBX_T0: {
    extern void op_opt_movb_EBX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EBX_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EBX_T0: {
    extern void op_opt_movh_EBX_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EBX_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_EBX_T1: {
    extern void op_opt_movb_EBX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EBX_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EBX_T1: {
    extern void op_opt_movh_EBX_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EBX_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_ESP: {
    extern void op_movl_A0_ESP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_ESP: {
    extern void op_movw_A0_ESP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_ESP: {
    extern void op_addl_A0_ESP();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESP+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_ESP: {
    extern void op_addw_A0_ESP();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESP+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_ESP_s1: {
    extern void op_addl_A0_ESP_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESP_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_ESP_s1: {
    extern void op_addw_A0_ESP_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESP_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_ESP_s2: {
    extern void op_addl_A0_ESP_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESP_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ESP_s2: {
    extern void op_addw_A0_ESP_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESP_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_ESP_s3: {
    extern void op_addl_A0_ESP_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESP_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ESP_s3: {
    extern void op_addw_A0_ESP_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESP_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_ESP: {
    extern void op_movl_T0_ESP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_ESP: {
    extern void op_movb_T0_ESP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_ESP: {
    extern void op_movw_T0_ESP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_ESP: {
    extern void op_movl_T1_ESP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_ESP: {
    extern void op_movb_T1_ESP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_ESP: {
    extern void op_movw_T1_ESP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_ESP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_ESP: {
    extern void op_movh_T0_ESP();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_ESP+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_ESP: {
    extern void op_movh_T1_ESP();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_ESP+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_ESP_T0: {
    extern void op_movl_ESP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESP_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ESP_T1: {
    extern void op_movl_ESP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESP_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ESP_A0: {
    extern void op_movl_ESP_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESP_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_ESP_T1_T0: {
    extern void op_cmovw_ESP_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_ESP_T1_T0+0), 59);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 47) + -4;
    gen_code_ptr += 59;
}
break;

case INDEX_op_cmovl_ESP_T1_T0: {
    extern void op_cmovl_ESP_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_ESP_T1_T0+0), 48);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 48;
}
break;

case INDEX_op_movw_ESP_T0: {
    extern void op_movw_ESP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESP_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ESP_T1: {
    extern void op_movw_ESP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESP_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ESP_A0: {
    extern void op_movw_ESP_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESP_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_ESP_T0: {
    extern void op_movb_ESP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ESP_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ESP_T0: {
    extern void op_movh_ESP_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ESP_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_ESP_T1: {
    extern void op_movb_ESP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ESP_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ESP_T1: {
    extern void op_movh_ESP_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ESP_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_ESP: {
    extern void op_opt_movl_A0_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_ESP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ESP: {
    extern void op_opt_addl_A0_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ESP_s1: {
    extern void op_opt_addl_A0_ESP_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESP_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_ESP_s2: {
    extern void op_opt_addl_A0_ESP_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESP_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_ESP_s3: {
    extern void op_opt_addl_A0_ESP_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESP_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_ESP: {
    extern void op_opt_movl_T0_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_ESP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_ESP: {
    extern void op_opt_movl_T1_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_ESP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_ESP: {
    extern void op_opt_movh_T0_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_ESP+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_ESP: {
    extern void op_opt_movh_T1_ESP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_ESP+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_ESP_T0: {
    extern void op_opt_movl_ESP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESP_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ESP_T1: {
    extern void op_opt_movl_ESP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESP_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ESP_A0: {
    extern void op_opt_movl_ESP_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESP_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_ESP_T1_T0: {
    extern void op_opt_cmovw_ESP_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_ESP_T1_T0+0), 26);
    gen_code_ptr += 26;
}
break;

case INDEX_op_opt_cmovl_ESP_T1_T0: {
    extern void op_opt_cmovl_ESP_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_ESP_T1_T0+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movw_ESP_T0: {
    extern void op_opt_movw_ESP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESP_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ESP_T1: {
    extern void op_opt_movw_ESP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESP_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ESP_A0: {
    extern void op_opt_movw_ESP_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESP_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_ESP_T0: {
    extern void op_opt_movb_ESP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ESP_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ESP_T0: {
    extern void op_opt_movh_ESP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ESP_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_ESP_T1: {
    extern void op_opt_movb_ESP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ESP_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ESP_T1: {
    extern void op_opt_movh_ESP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ESP_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_EBP: {
    extern void op_movl_A0_EBP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_EBP: {
    extern void op_movw_A0_EBP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_EBP: {
    extern void op_addl_A0_EBP();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBP+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_EBP: {
    extern void op_addw_A0_EBP();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBP+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_EBP_s1: {
    extern void op_addl_A0_EBP_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBP_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_EBP_s1: {
    extern void op_addw_A0_EBP_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBP_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_EBP_s2: {
    extern void op_addl_A0_EBP_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBP_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EBP_s2: {
    extern void op_addw_A0_EBP_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBP_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_EBP_s3: {
    extern void op_addl_A0_EBP_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EBP_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EBP_s3: {
    extern void op_addw_A0_EBP_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EBP_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_EBP: {
    extern void op_movl_T0_EBP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_EBP: {
    extern void op_movb_T0_EBP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_EBP: {
    extern void op_movw_T0_EBP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_EBP: {
    extern void op_movl_T1_EBP();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_EBP: {
    extern void op_movb_T1_EBP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_EBP: {
    extern void op_movw_T1_EBP();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_EBP+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_EBP: {
    extern void op_movh_T0_EBP();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_EBP+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_EBP: {
    extern void op_movh_T1_EBP();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_EBP+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_EBP_T0: {
    extern void op_movl_EBP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBP_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EBP_T1: {
    extern void op_movl_EBP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBP_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EBP_A0: {
    extern void op_movl_EBP_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EBP_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_EBP_T1_T0: {
    extern void op_cmovw_EBP_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_EBP_T1_T0+0), 58);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    gen_code_ptr += 58;
}
break;

case INDEX_op_cmovl_EBP_T1_T0: {
    extern void op_cmovl_EBP_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_EBP_T1_T0+0), 49);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 49;
}
break;

case INDEX_op_movw_EBP_T0: {
    extern void op_movw_EBP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBP_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EBP_T1: {
    extern void op_movw_EBP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBP_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EBP_A0: {
    extern void op_movw_EBP_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EBP_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_EBP_T0: {
    extern void op_movb_EBP_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EBP_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EBP_T0: {
    extern void op_movh_EBP_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EBP_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_EBP_T1: {
    extern void op_movb_EBP_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EBP_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EBP_T1: {
    extern void op_movh_EBP_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EBP_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_EBP: {
    extern void op_opt_movl_A0_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_EBP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EBP: {
    extern void op_opt_addl_A0_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EBP_s1: {
    extern void op_opt_addl_A0_EBP_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBP_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_EBP_s2: {
    extern void op_opt_addl_A0_EBP_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBP_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_EBP_s3: {
    extern void op_opt_addl_A0_EBP_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EBP_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_EBP: {
    extern void op_opt_movl_T0_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_EBP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_EBP: {
    extern void op_opt_movl_T1_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_EBP+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_EBP: {
    extern void op_opt_movh_T0_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_EBP+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_EBP: {
    extern void op_opt_movh_T1_EBP();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_EBP+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_EBP_T0: {
    extern void op_opt_movl_EBP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBP_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EBP_T1: {
    extern void op_opt_movl_EBP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBP_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EBP_A0: {
    extern void op_opt_movl_EBP_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EBP_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_EBP_T1_T0: {
    extern void op_opt_cmovw_EBP_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_EBP_T1_T0+0), 27);
    gen_code_ptr += 27;
}
break;

case INDEX_op_opt_cmovl_EBP_T1_T0: {
    extern void op_opt_cmovl_EBP_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_EBP_T1_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movw_EBP_T0: {
    extern void op_opt_movw_EBP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBP_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EBP_T1: {
    extern void op_opt_movw_EBP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBP_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EBP_A0: {
    extern void op_opt_movw_EBP_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EBP_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_EBP_T0: {
    extern void op_opt_movb_EBP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EBP_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EBP_T0: {
    extern void op_opt_movh_EBP_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EBP_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_EBP_T1: {
    extern void op_opt_movb_EBP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EBP_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EBP_T1: {
    extern void op_opt_movh_EBP_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EBP_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_ESI: {
    extern void op_movl_A0_ESI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_ESI: {
    extern void op_movw_A0_ESI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_ESI: {
    extern void op_addl_A0_ESI();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESI+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_ESI: {
    extern void op_addw_A0_ESI();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESI+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_ESI_s1: {
    extern void op_addl_A0_ESI_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESI_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_ESI_s1: {
    extern void op_addw_A0_ESI_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESI_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_ESI_s2: {
    extern void op_addl_A0_ESI_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESI_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ESI_s2: {
    extern void op_addw_A0_ESI_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESI_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_ESI_s3: {
    extern void op_addl_A0_ESI_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_ESI_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_ESI_s3: {
    extern void op_addw_A0_ESI_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_ESI_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_ESI: {
    extern void op_movl_T0_ESI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_ESI: {
    extern void op_movb_T0_ESI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_ESI: {
    extern void op_movw_T0_ESI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_ESI: {
    extern void op_movl_T1_ESI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_ESI: {
    extern void op_movb_T1_ESI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_ESI: {
    extern void op_movw_T1_ESI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_ESI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_ESI: {
    extern void op_movh_T0_ESI();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_ESI+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_ESI: {
    extern void op_movh_T1_ESI();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_ESI+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_ESI_T0: {
    extern void op_movl_ESI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESI_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ESI_T1: {
    extern void op_movl_ESI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESI_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_ESI_A0: {
    extern void op_movl_ESI_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_ESI_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_ESI_T1_T0: {
    extern void op_cmovw_ESI_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_ESI_T1_T0+0), 59);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 47) + -4;
    gen_code_ptr += 59;
}
break;

case INDEX_op_cmovl_ESI_T1_T0: {
    extern void op_cmovl_ESI_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_ESI_T1_T0+0), 48);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 48;
}
break;

case INDEX_op_movw_ESI_T0: {
    extern void op_movw_ESI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESI_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ESI_T1: {
    extern void op_movw_ESI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESI_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_ESI_A0: {
    extern void op_movw_ESI_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_ESI_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_ESI_T0: {
    extern void op_movb_ESI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ESI_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ESI_T0: {
    extern void op_movh_ESI_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ESI_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_ESI_T1: {
    extern void op_movb_ESI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_ESI_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_ESI_T1: {
    extern void op_movh_ESI_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_ESI_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_ESI: {
    extern void op_opt_movl_A0_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_ESI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ESI: {
    extern void op_opt_addl_A0_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_ESI_s1: {
    extern void op_opt_addl_A0_ESI_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESI_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_ESI_s2: {
    extern void op_opt_addl_A0_ESI_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESI_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_ESI_s3: {
    extern void op_opt_addl_A0_ESI_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_ESI_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_ESI: {
    extern void op_opt_movl_T0_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_ESI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_ESI: {
    extern void op_opt_movl_T1_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_ESI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_ESI: {
    extern void op_opt_movh_T0_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_ESI+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_ESI: {
    extern void op_opt_movh_T1_ESI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_ESI+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_ESI_T0: {
    extern void op_opt_movl_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESI_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ESI_T1: {
    extern void op_opt_movl_ESI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESI_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_ESI_A0: {
    extern void op_opt_movl_ESI_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_ESI_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_ESI_T1_T0: {
    extern void op_opt_cmovw_ESI_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_ESI_T1_T0+0), 26);
    gen_code_ptr += 26;
}
break;

case INDEX_op_opt_cmovl_ESI_T1_T0: {
    extern void op_opt_cmovl_ESI_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_ESI_T1_T0+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_opt_movw_ESI_T0: {
    extern void op_opt_movw_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESI_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ESI_T1: {
    extern void op_opt_movw_ESI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESI_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_ESI_A0: {
    extern void op_opt_movw_ESI_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_ESI_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_ESI_T0: {
    extern void op_opt_movb_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ESI_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ESI_T0: {
    extern void op_opt_movh_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ESI_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_ESI_T1: {
    extern void op_opt_movb_ESI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_ESI_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_ESI_T1: {
    extern void op_opt_movh_ESI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_ESI_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_movl_A0_EDI: {
    extern void op_movl_A0_EDI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_A0_EDI: {
    extern void op_movw_A0_EDI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_A0_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_addl_A0_EDI: {
    extern void op_addl_A0_EDI();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDI+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addw_A0_EDI: {
    extern void op_addw_A0_EDI();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDI+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_addl_A0_EDI_s1: {
    extern void op_addl_A0_EDI_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDI_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addw_A0_EDI_s1: {
    extern void op_addw_A0_EDI_s1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDI_s1+0), 43);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 35) + -4;
    gen_code_ptr += 43;
}
break;

case INDEX_op_addl_A0_EDI_s2: {
    extern void op_addl_A0_EDI_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDI_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EDI_s2: {
    extern void op_addw_A0_EDI_s2();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDI_s2+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addl_A0_EDI_s3: {
    extern void op_addl_A0_EDI_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_EDI_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_addw_A0_EDI_s3: {
    extern void op_addw_A0_EDI_s3();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_A0_EDI_s3+0), 44);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 36) + -4;
    gen_code_ptr += 44;
}
break;

case INDEX_op_movl_T0_EDI: {
    extern void op_movl_T0_EDI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T0_EDI: {
    extern void op_movb_T0_EDI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T0_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T0_EDI: {
    extern void op_movw_T0_EDI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T0_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_EDI: {
    extern void op_movl_T1_EDI();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movb_T1_EDI: {
    extern void op_movb_T1_EDI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_T1_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movw_T1_EDI: {
    extern void op_movw_T1_EDI();
extern char taintcheck_reg2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_T1_EDI+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2TN) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movh_T0_EDI: {
    extern void op_movh_T0_EDI();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T0_EDI+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movh_T1_EDI: {
    extern void op_movh_T1_EDI();
extern char taintcheck_regh2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_T1_EDI+0), 34);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_regh2TN) - (long)(gen_code_ptr + 26) + -4;
    gen_code_ptr += 34;
}
break;

case INDEX_op_movl_EDI_T0: {
    extern void op_movl_EDI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDI_T0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EDI_T1: {
    extern void op_movl_EDI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDI_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_EDI_A0: {
    extern void op_movl_EDI_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_EDI_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmovw_EDI_T1_T0: {
    extern void op_cmovw_EDI_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovw_EDI_T1_T0+0), 58);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    gen_code_ptr += 58;
}
break;

case INDEX_op_cmovl_EDI_T1_T0: {
    extern void op_cmovl_EDI_T1_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmovl_EDI_T1_T0+0), 49);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 49;
}
break;

case INDEX_op_movw_EDI_T0: {
    extern void op_movw_EDI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDI_T0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EDI_T1: {
    extern void op_movw_EDI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDI_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movw_EDI_A0: {
    extern void op_movw_EDI_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_EDI_A0+0), 46);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_movb_EDI_T0: {
    extern void op_movb_EDI_T0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EDI_T0+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EDI_T0: {
    extern void op_movh_EDI_T0();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EDI_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_movb_EDI_T1: {
    extern void op_movb_EDI_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_EDI_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_movh_EDI_T1: {
    extern void op_movh_EDI_T1();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movh_EDI_T1+0), 53);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_opt_movl_A0_EDI: {
    extern void op_opt_movl_A0_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_EDI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EDI: {
    extern void op_opt_addl_A0_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_addl_A0_EDI_s1: {
    extern void op_opt_addl_A0_EDI_s1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDI_s1+0), 10);
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_addl_A0_EDI_s2: {
    extern void op_opt_addl_A0_EDI_s2();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDI_s2+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_addl_A0_EDI_s3: {
    extern void op_opt_addl_A0_EDI_s3();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_EDI_s3+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_T0_EDI: {
    extern void op_opt_movl_T0_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_EDI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_EDI: {
    extern void op_opt_movl_T1_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_EDI+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movh_T0_EDI: {
    extern void op_opt_movh_T0_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T0_EDI+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movh_T1_EDI: {
    extern void op_opt_movh_T1_EDI();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_T1_EDI+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_opt_movl_EDI_T0: {
    extern void op_opt_movl_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDI_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EDI_T1: {
    extern void op_opt_movl_EDI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDI_T1+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_EDI_A0: {
    extern void op_opt_movl_EDI_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_EDI_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_cmovw_EDI_T1_T0: {
    extern void op_opt_cmovw_EDI_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovw_EDI_T1_T0+0), 27);
    gen_code_ptr += 27;
}
break;

case INDEX_op_opt_cmovl_EDI_T1_T0: {
    extern void op_opt_cmovl_EDI_T1_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_cmovl_EDI_T1_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movw_EDI_T0: {
    extern void op_opt_movw_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDI_T0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EDI_T1: {
    extern void op_opt_movw_EDI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDI_T1+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movw_EDI_A0: {
    extern void op_opt_movw_EDI_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movw_EDI_A0+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_opt_movb_EDI_T0: {
    extern void op_opt_movb_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EDI_T0+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EDI_T0: {
    extern void op_opt_movh_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EDI_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_opt_movb_EDI_T1: {
    extern void op_opt_movb_EDI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movb_EDI_T1+0), 17);
    gen_code_ptr += 17;
}
break;

case INDEX_op_opt_movh_EDI_T1: {
    extern void op_opt_movh_EDI_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movh_EDI_T1+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_update2_cc: {
    extern void op_update2_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_update2_cc+0), 64);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 36) + -4;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 64;
}
break;

case INDEX_op_update1_cc: {
    extern void op_update1_cc();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_update1_cc+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_update_neg_cc: {
    extern void op_update_neg_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_update_neg_cc+0), 64);
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 36) + -4;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 64;
}
break;

case INDEX_op_cmpl_T0_T1_cc: {
    extern void op_cmpl_T0_T1_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpl_T0_T1_cc+0), 71);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 38) + -4;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 63) + -4;
    gen_code_ptr += 71;
}
break;

case INDEX_op_update_inc_cc: {
    extern void op_update_inc_cc();
extern char cc_table;
extern char taintcheck_reg_clean;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_update_inc_cc+0), 60);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 35) + -4;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 55) + -4;
    gen_code_ptr += 60;
}
break;

case INDEX_op_testl_T0_T1_cc: {
    extern void op_testl_T0_T1_cc();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_testl_T0_T1_cc+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_addl_T0_T1: {
    extern void op_addl_T0_T1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_T0_T1+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_orl_T0_T1: {
    extern void op_orl_T0_T1();
extern char taintcheck_logic_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_orl_T0_T1+0), 23);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_logic_T0_T1) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_andl_T0_T1: {
    extern void op_andl_T0_T1();
extern char taintcheck_logic_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_andl_T0_T1+0), 23);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_logic_T0_T1) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_subl_T0_T1: {
    extern void op_subl_T0_T1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_subl_T0_T1+0), 41);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_xorl_T0_T1: {
    extern void op_xorl_T0_T1();
extern char taintcheck_logic_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_xorl_T0_T1+0), 23);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_logic_T0_T1) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_negl_T0: {
    extern void op_negl_T0();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_negl_T0+0), 27);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_incl_T0: {
    extern void op_incl_T0();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_incl_T0+0), 28);
    *(uint32_t *)(gen_code_ptr + 20) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 20) + -4;
    gen_code_ptr += 28;
}
break;

case INDEX_op_decl_T0: {
    extern void op_decl_T0();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_decl_T0+0), 28);
    *(uint32_t *)(gen_code_ptr + 20) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 20) + -4;
    gen_code_ptr += 28;
}
break;

case INDEX_op_notl_T0: {
    extern void op_notl_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_notl_T0+0), 4);
    gen_code_ptr += 4;
}
break;

case INDEX_op_bswapl_T0: {
    extern void op_bswapl_T0();
extern char taintcheck_bswap;
    memcpy(gen_code_ptr, (void *)((char *)&op_bswapl_T0+0), 33);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&taintcheck_bswap) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 33;
}
break;

case INDEX_op_mulb_AL_T0: {
    extern void op_mulb_AL_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg_shift;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_mulb_AL_T0+0), 113);
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 71) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 71) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 105) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 105) + -4;
    gen_code_ptr += 113;
}
break;

case INDEX_op_imulb_AL_T0: {
    extern void op_imulb_AL_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg_shift;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_imulb_AL_T0+0), 123);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 98) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 98) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 123;
}
break;

case INDEX_op_mulw_AX_T0: {
    extern void op_mulw_AX_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_mulw_AX_T0+0), 129);
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 104) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 104) + -4;
    *(uint32_t *)(gen_code_ptr + 121) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 121) + -4;
    gen_code_ptr += 129;
}
break;

case INDEX_op_imulw_AX_T0: {
    extern void op_imulw_AX_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_imulw_AX_T0+0), 140);
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 98) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 98) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    *(uint32_t *)(gen_code_ptr + 132) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 132) + -4;
    gen_code_ptr += 140;
}
break;

case INDEX_op_mull_EAX_T0: {
    extern void op_mull_EAX_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_mull_EAX_T0+0), 111);
    *(uint32_t *)(gen_code_ptr + 52) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 52) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 103) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 103) + -4;
    gen_code_ptr += 111;
}
break;

case INDEX_op_imull_EAX_T0: {
    extern void op_imull_EAX_T0();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_imull_EAX_T0+0), 123);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 98) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 98) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 123;
}
break;

case INDEX_op_imulw_T0_T1: {
    extern void op_imulw_T0_T1();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg_shift;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_imulw_T0_T1+0), 129);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 101) + -4;
    *(uint32_t *)(gen_code_ptr + 121) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 121) + -4;
    gen_code_ptr += 129;
}
break;

case INDEX_op_imull_T0_T1: {
    extern void op_imull_T0_T1();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_imull_T0_T1+0), 109);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 101) + -4;
    gen_code_ptr += 109;
}
break;

case INDEX_op_divb_AL_T0: {
    extern void op_divb_AL_T0();
extern char raise_exception;
extern char raise_exception;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_divb_AL_T0+0), 142);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&raise_exception) - (long)(gen_code_ptr + 35) + -4;
    *(uint32_t *)(gen_code_ptr + 58) = (long)(&raise_exception) - (long)(gen_code_ptr + 58) + -4;
    *(uint32_t *)(gen_code_ptr + 103) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 103) + -4;
    *(uint32_t *)(gen_code_ptr + 120) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 120) + -4;
    gen_code_ptr += 142;
}
break;

case INDEX_op_idivb_AL_T0: {
    extern void op_idivb_AL_T0();
extern char raise_exception;
extern char raise_exception;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_idivb_AL_T0+0), 155);
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&raise_exception) - (long)(gen_code_ptr + 35) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&raise_exception) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 116) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 116) + -4;
    *(uint32_t *)(gen_code_ptr + 133) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 133) + -4;
    gen_code_ptr += 155;
}
break;

case INDEX_op_divw_AX_T0: {
    extern void op_divw_AX_T0();
extern char raise_exception;
extern char raise_exception;
extern char taintcheck_fn3regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_divw_AX_T0+0), 169);
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&raise_exception) - (long)(gen_code_ptr + 44) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&raise_exception) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 130) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 130) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 147) + -4;
    gen_code_ptr += 169;
}
break;

case INDEX_op_idivw_AX_T0: {
    extern void op_idivw_AX_T0();
extern char raise_exception;
extern char raise_exception;
extern char taintcheck_fn3regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_idivw_AX_T0+0), 180);
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&raise_exception) - (long)(gen_code_ptr + 44) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&raise_exception) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 141) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 141) + -4;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 158) + -4;
    gen_code_ptr += 180;
}
break;

case INDEX_op_divl_EAX_T0: {
    extern void op_divl_EAX_T0();
extern char helper_divl_EAX_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_divl_EAX_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_divl_EAX_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_idivl_EAX_T0: {
    extern void op_idivl_EAX_T0();
extern char helper_idivl_EAX_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_idivl_EAX_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_idivl_EAX_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_movl_T0_imu: {
    long param1;
    extern void op_movl_T0_imu();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_imu+0), 27);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_movl_T0_im: {
    long param1;
    extern void op_movl_T0_im();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_im+0), 27);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_addl_T0_im: {
    long param1;
    extern void op_addl_T0_im();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_T0_im+0), 33);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 33;
}
break;

case INDEX_op_andl_T0_ffff: {
    extern void op_andl_T0_ffff();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_andl_T0_ffff+0), 31);
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_andl_T0_im: {
    long param1;
    extern void op_andl_T0_im();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_andl_T0_im+0), 33);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 33;
}
break;

case INDEX_op_movl_T0_T1: {
    extern void op_movl_T0_T1();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_T1+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T1_imu: {
    long param1;
    extern void op_movl_T1_imu();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_imu+0), 27);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_movl_T1_im: {
    long param1;
    extern void op_movl_T1_im();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_im+0), 27);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_addl_T1_im: {
    long param1;
    extern void op_addl_T1_im();
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_T1_im+0), 33);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 33;
}
break;

case INDEX_op_movl_T1_A0: {
    extern void op_movl_T1_A0();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T1_A0+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_A0_im: {
    long param1;
    extern void op_movl_A0_im();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_im+0), 27);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_addl_A0_im: {
    long param1;
    extern void op_addl_A0_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_im+0), 10);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    gen_code_ptr += 10;
}
break;

case INDEX_op_movl_A0_seg: {
    long param1;
    extern void op_movl_A0_seg();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_A0_seg+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_addl_A0_seg: {
    long param1;
    extern void op_addl_A0_seg();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_seg+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_addl_A0_AL: {
    extern void op_addl_A0_AL();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_AL+0), 38);
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 30) + -4;
    gen_code_ptr += 38;
}
break;

case INDEX_op_andl_A0_ffff: {
    extern void op_andl_A0_ffff();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_andl_A0_ffff+0), 31);
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_ldub_raw_T0_A0: {
    extern void op_ldub_raw_T0_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldsb_raw_T0_A0: {
    extern void op_ldsb_raw_T0_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_lduw_raw_T0_A0: {
    extern void op_lduw_raw_T0_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldsw_raw_T0_A0: {
    extern void op_ldsw_raw_T0_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldl_raw_T0_A0: {
    extern void op_ldl_raw_T0_A0();
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_raw_T0_A0+0), 37);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_ldub_raw_T1_A0: {
    extern void op_ldub_raw_T1_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldsb_raw_T1_A0: {
    extern void op_ldsb_raw_T1_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_lduw_raw_T1_A0: {
    extern void op_lduw_raw_T1_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldsw_raw_T1_A0: {
    extern void op_ldsw_raw_T1_A0();
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 15) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldl_raw_T1_A0: {
    extern void op_ldl_raw_T1_A0();
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_raw_T1_A0+0), 37);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_stb_raw_T0_A0: {
    extern void op_stb_raw_T0_A0();
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stb_raw_T0_A0+0), 41);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_stw_raw_T0_A0: {
    extern void op_stw_raw_T0_A0();
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_raw_T0_A0+0), 42);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 42;
}
break;

case INDEX_op_stl_raw_T0_A0: {
    extern void op_stl_raw_T0_A0();
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_raw_T0_A0+0), 41);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_stw_raw_T1_A0: {
    extern void op_stw_raw_T1_A0();
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_raw_T1_A0+0), 42);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 42;
}
break;

case INDEX_op_stl_raw_T1_A0: {
    extern void op_stl_raw_T1_A0();
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_raw_T1_A0+0), 41);
    *(uint32_t *)(gen_code_ptr + 19) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 19) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_ldq_raw_env_A0: {
    long param1;
    extern void op_ldq_raw_env_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_ldq_raw_env_A0+0), 14);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_stq_raw_env_A0: {
    long param1;
    extern void op_stq_raw_env_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_stq_raw_env_A0+0), 14);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_ldo_raw_env_A0: {
    long param1;
    extern void op_ldo_raw_env_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_ldo_raw_env_A0+0), 31);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 8;
    gen_code_ptr += 31;
}
break;

case INDEX_op_sto_raw_env_A0: {
    long param1;
    extern void op_sto_raw_env_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_sto_raw_env_A0+0), 31);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 8;
    gen_code_ptr += 31;
}
break;

case INDEX_op_TD_ldub_raw_T0_A0: {
    extern void op_TD_ldub_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_raw_T0_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldsb_raw_T0_A0: {
    extern void op_TD_ldsb_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_raw_T0_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_lduw_raw_T0_A0: {
    extern void op_TD_lduw_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_raw_T0_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldsw_raw_T0_A0: {
    extern void op_TD_ldsw_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_raw_T0_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldl_raw_T0_A0: {
    extern void op_TD_ldl_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 53;
}
break;

case INDEX_op_TD_ldub_raw_T1_A0: {
    extern void op_TD_ldub_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_raw_T1_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldsb_raw_T1_A0: {
    extern void op_TD_ldsb_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_raw_T1_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_lduw_raw_T1_A0: {
    extern void op_TD_lduw_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_raw_T1_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldsw_raw_T1_A0: {
    extern void op_TD_ldsw_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_raw_T1_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_ldl_raw_T1_A0: {
    extern void op_TD_ldl_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 2) = (long)(&physaddr_index) - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&physaddr_index) - (long)(gen_code_ptr + 22) + -4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 53;
}
break;

case INDEX_op_TD_stb_raw_T0_A0: {
    extern void op_TD_stb_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stb_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 12) = (long)(&physaddr_index) - (long)(gen_code_ptr + 12) + -4;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&physaddr_index) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 53;
}
break;

case INDEX_op_TD_stw_raw_T0_A0: {
    extern void op_TD_stw_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_raw_T0_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 13) = (long)(&physaddr_index) - (long)(gen_code_ptr + 13) + -4;
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&physaddr_index) - (long)(gen_code_ptr + 33) + -4;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_stl_raw_T0_A0: {
    extern void op_TD_stl_raw_T0_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_raw_T0_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 12) = (long)(&physaddr_index) - (long)(gen_code_ptr + 12) + -4;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&physaddr_index) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 53;
}
break;

case INDEX_op_TD_stw_raw_T1_A0: {
    extern void op_TD_stw_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_raw_T1_A0+0), 54);
    *(uint32_t *)(gen_code_ptr + 13) = (long)(&physaddr_index) - (long)(gen_code_ptr + 13) + -4;
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&physaddr_index) - (long)(gen_code_ptr + 33) + -4;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_TD_stl_raw_T1_A0: {
    extern void op_TD_stl_raw_T1_A0();
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_raw_T1_A0+0), 53);
    *(uint32_t *)(gen_code_ptr + 12) = (long)(&physaddr_index) - (long)(gen_code_ptr + 12) + -4;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&physaddr_index) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ldub_kernel_T0_A0: {
    extern void op_ldub_kernel_T0_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_kernel_T0_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_ldsb_kernel_T0_A0: {
    extern void op_ldsb_kernel_T0_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_kernel_T0_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_lduw_kernel_T0_A0: {
    extern void op_lduw_kernel_T0_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_kernel_T0_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_ldsw_kernel_T0_A0: {
    extern void op_ldsw_kernel_T0_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_kernel_T0_A0+0), 131);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 106) + -4;
    gen_code_ptr += 131;
}
break;

case INDEX_op_ldl_kernel_T0_A0: {
    extern void op_ldl_kernel_T0_A0();
extern char __TC_ldl_mmu;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_kernel_T0_A0+0), 114);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldl_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 90) + -4;
    gen_code_ptr += 114;
}
break;

case INDEX_op_ldub_kernel_T1_A0: {
    extern void op_ldub_kernel_T1_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_kernel_T1_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_ldsb_kernel_T1_A0: {
    extern void op_ldsb_kernel_T1_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_kernel_T1_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_lduw_kernel_T1_A0: {
    extern void op_lduw_kernel_T1_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_kernel_T1_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_ldsw_kernel_T1_A0: {
    extern void op_ldsw_kernel_T1_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_kernel_T1_A0+0), 131);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 106) + -4;
    gen_code_ptr += 131;
}
break;

case INDEX_op_ldl_kernel_T1_A0: {
    extern void op_ldl_kernel_T1_A0();
extern char __TC_ldl_mmu;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_kernel_T1_A0+0), 114);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&__TC_ldl_mmu) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 90) + -4;
    gen_code_ptr += 114;
}
break;

case INDEX_op_stb_kernel_T0_A0: {
    extern void op_stb_kernel_T0_A0();
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stb_kernel_T0_A0+0), 120);
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 95) + -4;
    gen_code_ptr += 120;
}
break;

case INDEX_op_stw_kernel_T0_A0: {
    extern void op_stw_kernel_T0_A0();
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_kernel_T0_A0+0), 119);
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 119;
}
break;

case INDEX_op_stl_kernel_T0_A0: {
    extern void op_stl_kernel_T0_A0();
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_kernel_T0_A0+0), 118);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 93) + -4;
    gen_code_ptr += 118;
}
break;

case INDEX_op_stw_kernel_T1_A0: {
    extern void op_stw_kernel_T1_A0();
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_kernel_T1_A0+0), 119);
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 119;
}
break;

case INDEX_op_stl_kernel_T1_A0: {
    extern void op_stl_kernel_T1_A0();
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_kernel_T1_A0+0), 118);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 93) + -4;
    gen_code_ptr += 118;
}
break;

case INDEX_op_ldq_kernel_env_A0: {
    long param1;
    extern void op_ldq_kernel_env_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldq_kernel_env_A0+0), 68);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 63) = (int32_t)param1 + 0;
    gen_code_ptr += 68;
}
break;

case INDEX_op_stq_kernel_env_A0: {
    long param1;
    extern void op_stq_kernel_env_A0();
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_stq_kernel_env_A0+0), 75);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 50) + -4;
    gen_code_ptr += 75;
}
break;

case INDEX_op_ldo_kernel_env_A0: {
    long param1;
    extern void op_ldo_kernel_env_A0();
extern char __ldq_mmu;
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldo_kernel_env_A0+0), 148);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 121) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 121) + -4;
    gen_code_ptr += 148;
}
break;

case INDEX_op_sto_kernel_env_A0: {
    long param1;
    extern void op_sto_kernel_env_A0();
extern char __stq_mmu;
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_sto_kernel_env_A0+0), 139);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 117) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 117) + -4;
    gen_code_ptr += 139;
}
break;

case INDEX_op_TD_ldub_kernel_T0_A0: {
    extern void op_TD_ldub_kernel_T0_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_kernel_T0_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_ldsb_kernel_T0_A0: {
    extern void op_TD_ldsb_kernel_T0_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_kernel_T0_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_lduw_kernel_T0_A0: {
    extern void op_TD_lduw_kernel_T0_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_kernel_T0_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_ldsw_kernel_T0_A0: {
    extern void op_TD_ldsw_kernel_T0_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_kernel_T0_A0+0), 103);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 52) = (long)(&physaddr_index) - (long)(gen_code_ptr + 52) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&physaddr_index) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 92) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 103;
}
break;

case INDEX_op_TD_ldl_kernel_T0_A0: {
    extern void op_TD_ldl_kernel_T0_A0();
extern char __TD_ldl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_kernel_T0_A0+0), 101);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldl_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&physaddr_index) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&physaddr_index) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 101;
}
break;

case INDEX_op_TD_ldub_kernel_T1_A0: {
    extern void op_TD_ldub_kernel_T1_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_kernel_T1_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_ldsb_kernel_T1_A0: {
    extern void op_TD_ldsb_kernel_T1_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_kernel_T1_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_lduw_kernel_T1_A0: {
    extern void op_TD_lduw_kernel_T1_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_kernel_T1_A0+0), 105);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 105;
}
break;

case INDEX_op_TD_ldsw_kernel_T1_A0: {
    extern void op_TD_ldsw_kernel_T1_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_kernel_T1_A0+0), 103);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 52) = (long)(&physaddr_index) - (long)(gen_code_ptr + 52) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&physaddr_index) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 92) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 103;
}
break;

case INDEX_op_TD_ldl_kernel_T1_A0: {
    extern void op_TD_ldl_kernel_T1_A0();
extern char __TD_ldl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_kernel_T1_A0+0), 101);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&__TD_ldl_mmu) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&physaddr_index) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&physaddr_index) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 101;
}
break;

case INDEX_op_TD_stb_kernel_T0_A0: {
    extern void op_TD_stb_kernel_T0_A0();
extern char __TD_stb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stb_kernel_T0_A0+0), 114);
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&__TD_stb_mmu) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&physaddr_index) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 85) = (long)(&physaddr_index) - (long)(gen_code_ptr + 85) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 102) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 114;
}
break;

case INDEX_op_TD_stw_kernel_T0_A0: {
    extern void op_TD_stw_kernel_T0_A0();
extern char __TD_stw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_kernel_T0_A0+0), 113);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&__TD_stw_mmu) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&physaddr_index) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 84) = (long)(&physaddr_index) - (long)(gen_code_ptr + 84) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 101) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 113;
}
break;

case INDEX_op_TD_stl_kernel_T0_A0: {
    extern void op_TD_stl_kernel_T0_A0();
extern char __TD_stl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_kernel_T0_A0+0), 109);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&__TD_stl_mmu) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&physaddr_index) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 109;
}
break;

case INDEX_op_TD_stw_kernel_T1_A0: {
    extern void op_TD_stw_kernel_T1_A0();
extern char __TD_stw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_kernel_T1_A0+0), 113);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&__TD_stw_mmu) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&physaddr_index) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 84) = (long)(&physaddr_index) - (long)(gen_code_ptr + 84) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 101) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 113;
}
break;

case INDEX_op_TD_stl_kernel_T1_A0: {
    extern void op_TD_stl_kernel_T1_A0();
extern char __TD_stl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_kernel_T1_A0+0), 109);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&__TD_stl_mmu) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&physaddr_index) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 109;
}
break;

case INDEX_op_ldub_user_T0_A0: {
    extern void op_ldub_user_T0_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_user_T0_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_ldsb_user_T0_A0: {
    extern void op_ldsb_user_T0_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_user_T0_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_lduw_user_T0_A0: {
    extern void op_lduw_user_T0_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_user_T0_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_ldsw_user_T0_A0: {
    extern void op_ldsw_user_T0_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_user_T0_A0+0), 134);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 109) + -4;
    gen_code_ptr += 134;
}
break;

case INDEX_op_ldl_user_T0_A0: {
    extern void op_ldl_user_T0_A0();
extern char __TC_ldl_mmu;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_user_T0_A0+0), 117);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldl_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 93) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_ldub_user_T1_A0: {
    extern void op_ldub_user_T1_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldub_user_T1_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_ldsb_user_T1_A0: {
    extern void op_ldsb_user_T1_A0();
extern char __TC_ldb_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsb_user_T1_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldb_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_lduw_user_T1_A0: {
    extern void op_lduw_user_T1_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_lduw_user_T1_A0+0), 136);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 111) + -4;
    gen_code_ptr += 136;
}
break;

case INDEX_op_ldsw_user_T1_A0: {
    extern void op_ldsw_user_T1_A0();
extern char __TC_ldw_mmu;
extern char taintcheck_reg_clean2;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldsw_user_T1_A0+0), 134);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldw_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 109) + -4;
    gen_code_ptr += 134;
}
break;

case INDEX_op_ldl_user_T1_A0: {
    extern void op_ldl_user_T1_A0();
extern char __TC_ldl_mmu;
extern char taintcheck_mem2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldl_user_T1_A0+0), 117);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&__TC_ldl_mmu) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_mem2reg) - (long)(gen_code_ptr + 93) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_stb_user_T0_A0: {
    extern void op_stb_user_T0_A0();
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stb_user_T0_A0+0), 123);
    *(uint32_t *)(gen_code_ptr + 71) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 71) + -4;
    *(uint32_t *)(gen_code_ptr + 98) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 98) + -4;
    gen_code_ptr += 123;
}
break;

case INDEX_op_stw_user_T0_A0: {
    extern void op_stw_user_T0_A0();
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_user_T0_A0+0), 122);
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 97) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 97) + -4;
    gen_code_ptr += 122;
}
break;

case INDEX_op_stl_user_T0_A0: {
    extern void op_stl_user_T0_A0();
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_user_T0_A0+0), 121);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 96) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 96) + -4;
    gen_code_ptr += 121;
}
break;

case INDEX_op_stw_user_T1_A0: {
    extern void op_stw_user_T1_A0();
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stw_user_T1_A0+0), 122);
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 97) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 97) + -4;
    gen_code_ptr += 122;
}
break;

case INDEX_op_stl_user_T1_A0: {
    extern void op_stl_user_T1_A0();
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_stl_user_T1_A0+0), 121);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 96) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 96) + -4;
    gen_code_ptr += 121;
}
break;

case INDEX_op_ldq_user_env_A0: {
    long param1;
    extern void op_ldq_user_env_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldq_user_env_A0+0), 71);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)param1 + 0;
    gen_code_ptr += 71;
}
break;

case INDEX_op_stq_user_env_A0: {
    long param1;
    extern void op_stq_user_env_A0();
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_stq_user_env_A0+0), 78);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 53) + -4;
    gen_code_ptr += 78;
}
break;

case INDEX_op_ldo_user_env_A0: {
    long param1;
    extern void op_ldo_user_env_A0();
extern char __ldq_mmu;
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_ldo_user_env_A0+0), 154);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 58) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 58) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 127) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 127) + -4;
    gen_code_ptr += 154;
}
break;

case INDEX_op_sto_user_env_A0: {
    long param1;
    extern void op_sto_user_env_A0();
extern char __stq_mmu;
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_sto_user_env_A0+0), 145);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 123) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 123) + -4;
    gen_code_ptr += 145;
}
break;

case INDEX_op_TD_ldub_user_T0_A0: {
    extern void op_TD_ldub_user_T0_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_user_T0_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_ldsb_user_T0_A0: {
    extern void op_TD_ldsb_user_T0_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_user_T0_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_lduw_user_T0_A0: {
    extern void op_TD_lduw_user_T0_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_user_T0_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_ldsw_user_T0_A0: {
    extern void op_TD_ldsw_user_T0_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_user_T0_A0+0), 106);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&physaddr_index) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&physaddr_index) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 84) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 106;
}
break;

case INDEX_op_TD_ldl_user_T0_A0: {
    extern void op_TD_ldl_user_T0_A0();
extern char __TD_ldl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_user_T0_A0+0), 104);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldl_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 104;
}
break;

case INDEX_op_TD_ldub_user_T1_A0: {
    extern void op_TD_ldub_user_T1_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldub_user_T1_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_ldsb_user_T1_A0: {
    extern void op_TD_ldsb_user_T1_A0();
extern char __TD_ldb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsb_user_T1_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldb_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_lduw_user_T1_A0: {
    extern void op_TD_lduw_user_T1_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_lduw_user_T1_A0+0), 108);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&physaddr_index) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&physaddr_index) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 108;
}
break;

case INDEX_op_TD_ldsw_user_T1_A0: {
    extern void op_TD_ldsw_user_T1_A0();
extern char __TD_ldw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldsw_user_T1_A0+0), 106);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldw_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&physaddr_index) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&physaddr_index) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 84) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 106;
}
break;

case INDEX_op_TD_ldl_user_T1_A0: {
    extern void op_TD_ldl_user_T1_A0();
extern char __TD_ldl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_ldl_user_T1_A0+0), 104);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&__TD_ldl_mmu) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&physaddr_index) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&physaddr_index) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 104;
}
break;

case INDEX_op_TD_stb_user_T0_A0: {
    extern void op_TD_stb_user_T0_A0();
extern char __TD_stb_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stb_user_T0_A0+0), 117);
    *(uint32_t *)(gen_code_ptr + 54) = (long)(&__TD_stb_mmu) - (long)(gen_code_ptr + 54) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&physaddr_index) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&physaddr_index) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 105) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 117;
}
break;

case INDEX_op_TD_stw_user_T0_A0: {
    extern void op_TD_stw_user_T0_A0();
extern char __TD_stw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_user_T0_A0+0), 116);
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&__TD_stw_mmu) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 71) = (long)(&physaddr_index) - (long)(gen_code_ptr + 71) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&physaddr_index) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 116;
}
break;

case INDEX_op_TD_stl_user_T0_A0: {
    extern void op_TD_stl_user_T0_A0();
extern char __TD_stl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_user_T0_A0+0), 112);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&__TD_stl_mmu) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&physaddr_index) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (long)(&physaddr_index) - (long)(gen_code_ptr + 83) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 112;
}
break;

case INDEX_op_TD_stw_user_T1_A0: {
    extern void op_TD_stw_user_T1_A0();
extern char __TD_stw_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stw_user_T1_A0+0), 116);
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&__TD_stw_mmu) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 71) = (long)(&physaddr_index) - (long)(gen_code_ptr + 71) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&physaddr_index) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 93) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 116;
}
break;

case INDEX_op_TD_stl_user_T1_A0: {
    extern void op_TD_stl_user_T1_A0();
extern char __TD_stl_mmu;
extern char physaddr_index;
extern char physaddr_index;
extern char physaddr_info_list;
extern char physaddr_info_list;
    memcpy(gen_code_ptr, (void *)((char *)&op_TD_stl_user_T1_A0+0), 112);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&__TD_stl_mmu) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&physaddr_index) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 83) = (long)(&physaddr_index) - (long)(gen_code_ptr + 83) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (int32_t)(long)(&physaddr_info_list) + 0;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&physaddr_info_list) + 8;
    gen_code_ptr += 112;
}
break;

case INDEX_op_jmp_T0: {
    extern void op_jmp_T0();
extern char taintcheck_check_eip;
    memcpy(gen_code_ptr, (void *)((char *)&op_jmp_T0+0), 26);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&taintcheck_check_eip) - (long)(gen_code_ptr + 10) + -4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_movl_eip_im: {
    long param1;
    extern void op_movl_eip_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_eip_im+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_hlt: {
    extern void op_hlt();
extern char helper_hlt;
    memcpy(gen_code_ptr, (void *)((char *)&op_hlt+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_hlt) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_monitor: {
    extern void op_monitor();
extern char helper_monitor;
    memcpy(gen_code_ptr, (void *)((char *)&op_monitor+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_monitor) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_mwait: {
    extern void op_mwait();
extern char helper_mwait;
    memcpy(gen_code_ptr, (void *)((char *)&op_mwait+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_mwait) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_debug: {
    extern void op_debug();
extern char cpu_loop_exit;
    memcpy(gen_code_ptr, (void *)((char *)&op_debug+0), 24);
    *(uint32_t *)(gen_code_ptr + 16) = (long)(&cpu_loop_exit) - (long)(gen_code_ptr + 16) + -4;
    gen_code_ptr += 24;
}
break;

case INDEX_op_raise_interrupt: {
    long param1, param2;
    extern void op_raise_interrupt();
extern char raise_interrupt;
    memcpy(gen_code_ptr, (void *)((char *)&op_raise_interrupt+0), 32);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&raise_interrupt) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_raise_exception: {
    long param1;
    extern void op_raise_exception();
extern char raise_exception;
    memcpy(gen_code_ptr, (void *)((char *)&op_raise_exception+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&raise_exception) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_into: {
    long param1;
    extern void op_into();
extern char cc_table;
extern char raise_interrupt;
    memcpy(gen_code_ptr, (void *)((char *)&op_into+0), 54);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 25) = param1 - (long)(gen_code_ptr + 25) + -4;
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&raise_interrupt) - (long)(gen_code_ptr + 42) + -4;
    gen_code_ptr += 54;
}
break;

case INDEX_op_cli: {
    extern void op_cli();
    memcpy(gen_code_ptr, (void *)((char *)&op_cli+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_sti: {
    extern void op_sti();
    memcpy(gen_code_ptr, (void *)((char *)&op_sti+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_set_inhibit_irq: {
    extern void op_set_inhibit_irq();
    memcpy(gen_code_ptr, (void *)((char *)&op_set_inhibit_irq+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_reset_inhibit_irq: {
    extern void op_reset_inhibit_irq();
    memcpy(gen_code_ptr, (void *)((char *)&op_reset_inhibit_irq+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_rsm: {
    extern void op_rsm();
extern char helper_rsm;
    memcpy(gen_code_ptr, (void *)((char *)&op_rsm+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_rsm) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_boundw: {
    extern void op_boundw();
extern char __ldw_mmu;
extern char __ldw_mmu;
extern char raise_exception;
    memcpy(gen_code_ptr, (void *)((char *)&op_boundw+0), 219);
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&__ldw_mmu) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&__ldw_mmu) - (long)(gen_code_ptr + 169) + -4;
    *(uint32_t *)(gen_code_ptr + 210) = (long)(&raise_exception) - (long)(gen_code_ptr + 210) + -4;
    gen_code_ptr += 219;
}
break;

case INDEX_op_boundl: {
    extern void op_boundl();
extern char __ldl_mmu;
extern char __ldl_mmu;
extern char raise_exception;
    memcpy(gen_code_ptr, (void *)((char *)&op_boundl+0), 212);
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 167) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 167) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (long)(&raise_exception) - (long)(gen_code_ptr + 203) + -4;
    gen_code_ptr += 212;
}
break;

case INDEX_op_cmpxchg8b: {
    extern void op_cmpxchg8b();
extern char helper_cmpxchg8b;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchg8b+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_cmpxchg8b) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_single_step: {
    extern void op_single_step();
extern char helper_single_step;
    memcpy(gen_code_ptr, (void *)((char *)&op_single_step+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_single_step) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_movl_T0_0: {
    extern void op_movl_T0_0();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_0+0), 26);
    *(uint32_t *)(gen_code_ptr + 18) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 18) + -4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_exit_tb: {
    extern void op_exit_tb();
    memcpy(gen_code_ptr, (void *)((char *)&op_exit_tb+0), 1);
    *(uint8_t *)(gen_code_ptr + 0) = 0xc3;
    gen_code_ptr += 1;
}
break;

case INDEX_op_jb_subb: {
    long param1;
    extern void op_jb_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jb_subb+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_jz_subb: {
    long param1;
    extern void op_jz_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_subb+0), 12);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = gen_labels[param1] - (long)(gen_code_ptr + 8) + -4;
    *(uint8_t *)(gen_code_ptr + 7) = 0xe9;
    gen_code_ptr += 12;
}
break;

case INDEX_op_jnz_subb: {
    long param1;
    extern void op_jnz_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_subb+0), 12);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = gen_labels[param1] - (long)(gen_code_ptr + 8) + -4;
    *(uint8_t *)(gen_code_ptr + 7) = 0xe9;
    gen_code_ptr += 12;
}
break;

case INDEX_op_jbe_subb: {
    long param1;
    extern void op_jbe_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jbe_subb+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_js_subb: {
    long param1;
    extern void op_js_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_js_subb+0), 12);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = gen_labels[param1] - (long)(gen_code_ptr + 8) + -4;
    *(uint8_t *)(gen_code_ptr + 7) = 0xe9;
    gen_code_ptr += 12;
}
break;

case INDEX_op_jl_subb: {
    long param1;
    extern void op_jl_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jl_subb+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_jle_subb: {
    long param1;
    extern void op_jle_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_jle_subb+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_setb_T0_subb: {
    extern void op_setb_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_setb_T0_subb+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_setz_T0_subb: {
    extern void op_setz_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_setz_T0_subb+0), 14);
    gen_code_ptr += 14;
}
break;

case INDEX_op_setbe_T0_subb: {
    extern void op_setbe_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_setbe_T0_subb+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_sets_T0_subb: {
    extern void op_sets_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_sets_T0_subb+0), 14);
    gen_code_ptr += 14;
}
break;

case INDEX_op_setl_T0_subb: {
    extern void op_setl_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_setl_T0_subb+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_setle_T0_subb: {
    extern void op_setle_T0_subb();
    memcpy(gen_code_ptr, (void *)((char *)&op_setle_T0_subb+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_shlb_T0_T1: {
    extern void op_shlb_T0_T1();
extern char taintcheck_fn2regs;
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlb_T0_T1+0), 60);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    *(uint32_t *)(gen_code_ptr + 48) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 48) + -4;
    gen_code_ptr += 60;
}
break;

case INDEX_op_shrb_T0_T1: {
    extern void op_shrb_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrb_T0_T1+0), 82);
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 45) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 70) + -4;
    gen_code_ptr += 82;
}
break;

case INDEX_op_sarb_T0_T1: {
    extern void op_sarb_T0_T1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarb_T0_T1+0), 52);
    *(uint32_t *)(gen_code_ptr + 40) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 40) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_rolb_T0_T1_cc: {
    extern void op_rolb_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_T0_T1_cc+0), 173);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 173;
}
break;

case INDEX_op_rorb_T0_T1_cc: {
    extern void op_rorb_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_T0_T1_cc+0), 176);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 167) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 167) + -4;
    gen_code_ptr += 176;
}
break;

case INDEX_op_rolb_T0_T1: {
    extern void op_rolb_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_T0_T1+0), 87);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 87;
}
break;

case INDEX_op_rorb_T0_T1: {
    extern void op_rorb_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_T0_T1+0), 87);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 87;
}
break;

case INDEX_op_rclb_T0_T1_cc: {
    extern void op_rclb_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclb_T0_T1_cc+0), 238);
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 129) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 161) + -4;
    gen_code_ptr += 238;
}
break;

case INDEX_op_rcrb_T0_T1_cc: {
    extern void op_rcrb_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrb_T0_T1_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_shlb_T0_T1_cc: {
    extern void op_shlb_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlb_T0_T1_cc+0), 123);
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 44) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 114) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 114) + -4;
    gen_code_ptr += 123;
}
break;

case INDEX_op_shrb_T0_T1_cc: {
    extern void op_shrb_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrb_T0_T1_cc+0), 140);
    *(uint32_t *)(gen_code_ptr + 41) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 41) + -4;
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 111) + -4;
    *(uint32_t *)(gen_code_ptr + 131) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 131) + -4;
    gen_code_ptr += 140;
}
break;

case INDEX_op_sarb_T0_T1_cc: {
    extern void op_sarb_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarb_T0_T1_cc+0), 138);
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 109) + -4;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 129) + -4;
    gen_code_ptr += 138;
}
break;

case INDEX_op_adcb_T0_T1_cc: {
    extern void op_adcb_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcb_T0_T1_cc+0), 120);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 120;
}
break;

case INDEX_op_sbbb_T0_T1_cc: {
    extern void op_sbbb_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbb_T0_T1_cc+0), 124);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 99) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 99) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 119) + -4;
    gen_code_ptr += 124;
}
break;

case INDEX_op_cmpxchgb_T0_T1_EAX_cc: {
    extern void op_cmpxchgb_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgb_T0_T1_EAX_cc+0), 139);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 103) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 103) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 125) + -4;
    gen_code_ptr += 139;
}
break;

case INDEX_op_rolb_raw_T0_T1_cc: {
    extern void op_rolb_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_raw_T0_T1_cc+0), 198);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 101) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 189) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 189) + -4;
    gen_code_ptr += 198;
}
break;

case INDEX_op_rorb_raw_T0_T1_cc: {
    extern void op_rorb_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_raw_T0_T1_cc+0), 201);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 101) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 192) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 192) + -4;
    gen_code_ptr += 201;
}
break;

case INDEX_op_rolb_raw_T0_T1: {
    extern void op_rolb_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_raw_T0_T1+0), 116);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 116;
}
break;

case INDEX_op_rorb_raw_T0_T1: {
    extern void op_rorb_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_raw_T0_T1+0), 116);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 116;
}
break;

case INDEX_op_rclb_raw_T0_T1_cc: {
    extern void op_rclb_raw_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclb_raw_T0_T1_cc+0), 267);
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 129) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 180) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 180) + -4;
    gen_code_ptr += 267;
}
break;

case INDEX_op_rcrb_raw_T0_T1_cc: {
    extern void op_rcrb_raw_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrb_raw_T0_T1_cc+0), 191);
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 177) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 177) + -4;
    gen_code_ptr += 191;
}
break;

case INDEX_op_shlb_raw_T0_T1_cc: {
    extern void op_shlb_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlb_raw_T0_T1_cc+0), 156);
    *(uint32_t *)(gen_code_ptr + 48) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 48) + -4;
    *(uint32_t *)(gen_code_ptr + 73) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 73) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 92) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 147) + -4;
    gen_code_ptr += 156;
}
break;

case INDEX_op_shrb_raw_T0_T1_cc: {
    extern void op_shrb_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrb_raw_T0_T1_cc+0), 173);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 45) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 173;
}
break;

case INDEX_op_sarb_raw_T0_T1_cc: {
    extern void op_sarb_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarb_raw_T0_T1_cc+0), 171);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 142) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 142) + -4;
    *(uint32_t *)(gen_code_ptr + 162) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 162) + -4;
    gen_code_ptr += 171;
}
break;

case INDEX_op_adcb_raw_T0_T1_cc: {
    extern void op_adcb_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcb_raw_T0_T1_cc+0), 149);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 124) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 124) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 144) + -4;
    gen_code_ptr += 149;
}
break;

case INDEX_op_sbbb_raw_T0_T1_cc: {
    extern void op_sbbb_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbb_raw_T0_T1_cc+0), 153);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 148) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_cmpxchgb_raw_T0_T1_EAX_cc: {
    extern void op_cmpxchgb_raw_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgb_raw_T0_T1_EAX_cc+0), 168);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 104) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 104) + -4;
    *(uint32_t *)(gen_code_ptr + 132) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 132) + -4;
    *(uint32_t *)(gen_code_ptr + 154) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 154) + -4;
    gen_code_ptr += 168;
}
break;

case INDEX_op_rolb_kernel_T0_T1_cc: {
    extern void op_rolb_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_kernel_T0_T1_cc+0), 293);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 158) + -4;
    *(uint32_t *)(gen_code_ptr + 185) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 185) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 267) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 267) + -4;
    gen_code_ptr += 293;
}
break;

case INDEX_op_rorb_kernel_T0_T1_cc: {
    extern void op_rorb_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_kernel_T0_T1_cc+0), 296);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 158) + -4;
    *(uint32_t *)(gen_code_ptr + 185) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 185) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 270) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 270) + -4;
    gen_code_ptr += 296;
}
break;

case INDEX_op_rolb_kernel_T0_T1: {
    extern void op_rolb_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_kernel_T0_T1+0), 199);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 147) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 174) + -4;
    gen_code_ptr += 199;
}
break;

case INDEX_op_rorb_kernel_T0_T1: {
    extern void op_rorb_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_kernel_T0_T1+0), 199);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 147) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 174) + -4;
    gen_code_ptr += 199;
}
break;

case INDEX_op_rclb_kernel_T0_T1_cc: {
    extern void op_rclb_kernel_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclb_kernel_T0_T1_cc+0), 339);
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 134) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 134) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 159) + -4;
    *(uint32_t *)(gen_code_ptr + 220) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 220) + -4;
    *(uint32_t *)(gen_code_ptr + 247) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 247) + -4;
    gen_code_ptr += 339;
}
break;

case INDEX_op_rcrb_kernel_T0_T1_cc: {
    extern void op_rcrb_kernel_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char __stb_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrb_kernel_T0_T1_cc+0), 273);
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__stb_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 246) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 246) + -4;
    gen_code_ptr += 273;
}
break;

case INDEX_op_shlb_kernel_T0_T1_cc: {
    extern void op_shlb_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlb_kernel_T0_T1_cc+0), 251);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 225) + -4;
    gen_code_ptr += 251;
}
break;

case INDEX_op_shrb_kernel_T0_T1_cc: {
    extern void op_shrb_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrb_kernel_T0_T1_cc+0), 268);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 173) + -4;
    *(uint32_t *)(gen_code_ptr + 222) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 222) + -4;
    *(uint32_t *)(gen_code_ptr + 242) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 242) + -4;
    gen_code_ptr += 268;
}
break;

case INDEX_op_sarb_kernel_T0_T1_cc: {
    extern void op_sarb_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarb_kernel_T0_T1_cc+0), 266);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 171) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 171) + -4;
    *(uint32_t *)(gen_code_ptr + 220) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 220) + -4;
    *(uint32_t *)(gen_code_ptr + 240) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 240) + -4;
    gen_code_ptr += 266;
}
break;

case INDEX_op_adcb_kernel_T0_T1_cc: {
    extern void op_adcb_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcb_kernel_T0_T1_cc+0), 215);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 109) + -4;
    *(uint32_t *)(gen_code_ptr + 136) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 136) + -4;
    *(uint32_t *)(gen_code_ptr + 187) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 187) + -4;
    *(uint32_t *)(gen_code_ptr + 207) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 207) + -4;
    gen_code_ptr += 215;
}
break;

case INDEX_op_sbbb_kernel_T0_T1_cc: {
    extern void op_sbbb_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbb_kernel_T0_T1_cc+0), 219);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 113) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 113) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 140) + -4;
    *(uint32_t *)(gen_code_ptr + 191) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 191) + -4;
    *(uint32_t *)(gen_code_ptr + 211) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 211) + -4;
    gen_code_ptr += 219;
}
break;

case INDEX_op_cmpxchgb_kernel_T0_T1_EAX_cc: {
    extern void op_cmpxchgb_kernel_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgb_kernel_T0_T1_EAX_cc+0), 267);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 125) + -4;
    *(uint32_t *)(gen_code_ptr + 152) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 152) + -4;
    *(uint32_t *)(gen_code_ptr + 185) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 185) + -4;
    *(uint32_t *)(gen_code_ptr + 213) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 213) + -4;
    *(uint32_t *)(gen_code_ptr + 235) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 235) + -4;
    gen_code_ptr += 267;
}
break;

case INDEX_op_rolb_user_T0_T1_cc: {
    extern void op_rolb_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_user_T0_T1_cc+0), 296);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 206) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 270) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 270) + -4;
    gen_code_ptr += 296;
}
break;

case INDEX_op_rorb_user_T0_T1_cc: {
    extern void op_rorb_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_user_T0_T1_cc+0), 299);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 206) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 273) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 273) + -4;
    gen_code_ptr += 299;
}
break;

case INDEX_op_rolb_user_T0_T1: {
    extern void op_rolb_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolb_user_T0_T1+0), 202);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 150) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 150) + -4;
    *(uint32_t *)(gen_code_ptr + 177) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 177) + -4;
    gen_code_ptr += 202;
}
break;

case INDEX_op_rorb_user_T0_T1: {
    extern void op_rorb_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorb_user_T0_T1+0), 202);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 150) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 150) + -4;
    *(uint32_t *)(gen_code_ptr + 177) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 177) + -4;
    gen_code_ptr += 202;
}
break;

case INDEX_op_rclb_user_T0_T1_cc: {
    extern void op_rclb_user_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclb_user_T0_T1_cc+0), 342);
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 134) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 134) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 159) + -4;
    *(uint32_t *)(gen_code_ptr + 223) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 223) + -4;
    *(uint32_t *)(gen_code_ptr + 250) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 250) + -4;
    gen_code_ptr += 342;
}
break;

case INDEX_op_rcrb_user_T0_T1_cc: {
    extern void op_rcrb_user_T0_T1_cc();
extern char rclb_table;
extern char cc_table;
extern char __stb_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrb_user_T0_T1_cc+0), 276);
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)(long)(&rclb_table) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&__stb_mmu) - (long)(gen_code_ptr + 164) + -4;
    *(uint32_t *)(gen_code_ptr + 249) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 249) + -4;
    gen_code_ptr += 276;
}
break;

case INDEX_op_shlb_user_T0_T1_cc: {
    extern void op_shlb_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlb_user_T0_T1_cc+0), 254);
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 152) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 152) + -4;
    *(uint32_t *)(gen_code_ptr + 179) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 179) + -4;
    *(uint32_t *)(gen_code_ptr + 228) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 228) + -4;
    gen_code_ptr += 254;
}
break;

case INDEX_op_shrb_user_T0_T1_cc: {
    extern void op_shrb_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrb_user_T0_T1_cc+0), 271);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 225) + -4;
    *(uint32_t *)(gen_code_ptr + 245) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 245) + -4;
    gen_code_ptr += 271;
}
break;

case INDEX_op_sarb_user_T0_T1_cc: {
    extern void op_sarb_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarb_user_T0_T1_cc+0), 269);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 147) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 174) + -4;
    *(uint32_t *)(gen_code_ptr + 223) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 223) + -4;
    *(uint32_t *)(gen_code_ptr + 243) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 243) + -4;
    gen_code_ptr += 269;
}
break;

case INDEX_op_adcb_user_T0_T1_cc: {
    extern void op_adcb_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcb_user_T0_T1_cc+0), 218);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 139) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 139) + -4;
    *(uint32_t *)(gen_code_ptr + 190) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 190) + -4;
    *(uint32_t *)(gen_code_ptr + 210) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 210) + -4;
    gen_code_ptr += 218;
}
break;

case INDEX_op_sbbb_user_T0_T1_cc: {
    extern void op_sbbb_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbb_user_T0_T1_cc+0), 222);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 116) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 116) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 194) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 194) + -4;
    *(uint32_t *)(gen_code_ptr + 214) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 214) + -4;
    gen_code_ptr += 222;
}
break;

case INDEX_op_cmpxchgb_user_T0_T1_EAX_cc: {
    extern void op_cmpxchgb_user_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stb_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgb_user_T0_T1_EAX_cc+0), 270);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&__TC_stb_mmu) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 155) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 155) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 216) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 216) + -4;
    *(uint32_t *)(gen_code_ptr + 238) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 238) + -4;
    gen_code_ptr += 270;
}
break;

case INDEX_op_movl_T0_Dshiftb: {
    extern void op_movl_T0_Dshiftb();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_Dshiftb+0), 26);
    *(uint32_t *)(gen_code_ptr + 18) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 18) + -4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_outb_T0_T1: {
    extern void op_outb_T0_T1();
extern char cpu_outb;
    memcpy(gen_code_ptr, (void *)((char *)&op_outb_T0_T1+0), 41);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&cpu_outb) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_inb_T0_T1: {
    extern void op_inb_T0_T1();
extern char taintcheck_reg_clean;
extern char cpu_inb;
    memcpy(gen_code_ptr, (void *)((char *)&op_inb_T0_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&cpu_inb) - (long)(gen_code_ptr + 30) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_inb_DX_T0: {
    extern void op_inb_DX_T0();
extern char taintcheck_reg_clean;
extern char cpu_inb;
    memcpy(gen_code_ptr, (void *)((char *)&op_inb_DX_T0+0), 47);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 31) = (long)(&cpu_inb) - (long)(gen_code_ptr + 31) + -4;
    gen_code_ptr += 47;
}
break;

case INDEX_op_outb_DX_T0: {
    extern void op_outb_DX_T0();
extern char cpu_outb;
    memcpy(gen_code_ptr, (void *)((char *)&op_outb_DX_T0+0), 41);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&cpu_outb) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_check_iob_T0: {
    extern void op_check_iob_T0();
extern char check_iob_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iob_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iob_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_check_iob_DX: {
    extern void op_check_iob_DX();
extern char check_iob_DX;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iob_DX+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iob_DX) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jb_subw: {
    long param1;
    extern void op_jb_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jb_subw+0), 20);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = gen_labels[param1] - (long)(gen_code_ptr + 16) + -4;
    *(uint8_t *)(gen_code_ptr + 15) = 0xe9;
    gen_code_ptr += 20;
}
break;

case INDEX_op_jz_subw: {
    long param1;
    extern void op_jz_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_subw+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jnz_subw: {
    long param1;
    extern void op_jnz_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_subw+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jbe_subw: {
    long param1;
    extern void op_jbe_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jbe_subw+0), 20);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = gen_labels[param1] - (long)(gen_code_ptr + 16) + -4;
    *(uint8_t *)(gen_code_ptr + 15) = 0xe9;
    gen_code_ptr += 20;
}
break;

case INDEX_op_js_subw: {
    long param1;
    extern void op_js_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_js_subw+0), 12);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = gen_labels[param1] - (long)(gen_code_ptr + 8) + -4;
    *(uint8_t *)(gen_code_ptr + 7) = 0xe9;
    gen_code_ptr += 12;
}
break;

case INDEX_op_jl_subw: {
    long param1;
    extern void op_jl_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jl_subw+0), 20);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = gen_labels[param1] - (long)(gen_code_ptr + 16) + -4;
    *(uint8_t *)(gen_code_ptr + 15) = 0xe9;
    gen_code_ptr += 20;
}
break;

case INDEX_op_jle_subw: {
    long param1;
    extern void op_jle_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jle_subw+0), 20);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = gen_labels[param1] - (long)(gen_code_ptr + 16) + -4;
    *(uint8_t *)(gen_code_ptr + 15) = 0xe9;
    gen_code_ptr += 20;
}
break;

case INDEX_op_loopnzw: {
    long param1;
    extern void op_loopnzw();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_loopnzw+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 24) + -4;
    *(uint32_t *)(gen_code_ptr + 35) = gen_labels[param1] - (long)(gen_code_ptr + 35) + -4;
    *(uint8_t *)(gen_code_ptr + 34) = 0xe9;
    gen_code_ptr += 39;
}
break;

case INDEX_op_loopzw: {
    long param1;
    extern void op_loopzw();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_loopzw+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 24) + -4;
    *(uint32_t *)(gen_code_ptr + 35) = gen_labels[param1] - (long)(gen_code_ptr + 35) + -4;
    *(uint8_t *)(gen_code_ptr + 34) = 0xe9;
    gen_code_ptr += 39;
}
break;

case INDEX_op_jz_ecxw: {
    long param1;
    extern void op_jz_ecxw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_ecxw+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jnz_ecxw: {
    long param1;
    extern void op_jnz_ecxw();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_ecxw+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_setb_T0_subw: {
    extern void op_setb_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_setb_T0_subw+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_setz_T0_subw: {
    extern void op_setz_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_setz_T0_subw+0), 15);
    gen_code_ptr += 15;
}
break;

case INDEX_op_setbe_T0_subw: {
    extern void op_setbe_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_setbe_T0_subw+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_sets_T0_subw: {
    extern void op_sets_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_sets_T0_subw+0), 14);
    gen_code_ptr += 14;
}
break;

case INDEX_op_setl_T0_subw: {
    extern void op_setl_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_setl_T0_subw+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_setle_T0_subw: {
    extern void op_setle_T0_subw();
    memcpy(gen_code_ptr, (void *)((char *)&op_setle_T0_subw+0), 23);
    gen_code_ptr += 23;
}
break;

case INDEX_op_shlw_T0_T1: {
    extern void op_shlw_T0_T1();
extern char taintcheck_fn2regs;
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlw_T0_T1+0), 60);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    *(uint32_t *)(gen_code_ptr + 48) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 48) + -4;
    gen_code_ptr += 60;
}
break;

case INDEX_op_shrw_T0_T1: {
    extern void op_shrw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrw_T0_T1+0), 82);
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 45) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 70) + -4;
    gen_code_ptr += 82;
}
break;

case INDEX_op_sarw_T0_T1: {
    extern void op_sarw_T0_T1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarw_T0_T1+0), 52);
    *(uint32_t *)(gen_code_ptr + 40) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 40) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_rolw_T0_T1_cc: {
    extern void op_rolw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_T0_T1_cc+0), 173);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 173;
}
break;

case INDEX_op_rorw_T0_T1_cc: {
    extern void op_rorw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_T0_T1_cc+0), 176);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 167) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 167) + -4;
    gen_code_ptr += 176;
}
break;

case INDEX_op_rolw_T0_T1: {
    extern void op_rolw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_T0_T1+0), 87);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 87;
}
break;

case INDEX_op_rorw_T0_T1: {
    extern void op_rorw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_T0_T1+0), 87);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 87;
}
break;

case INDEX_op_rclw_T0_T1_cc: {
    extern void op_rclw_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclw_T0_T1_cc+0), 238);
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 129) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 161) + -4;
    gen_code_ptr += 238;
}
break;

case INDEX_op_rcrw_T0_T1_cc: {
    extern void op_rcrw_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrw_T0_T1_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_shlw_T0_T1_cc: {
    extern void op_shlw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlw_T0_T1_cc+0), 122);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 113) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 113) + -4;
    gen_code_ptr += 122;
}
break;

case INDEX_op_shrw_T0_T1_cc: {
    extern void op_shrw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrw_T0_T1_cc+0), 140);
    *(uint32_t *)(gen_code_ptr + 41) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 41) + -4;
    *(uint32_t *)(gen_code_ptr + 66) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 66) + -4;
    *(uint32_t *)(gen_code_ptr + 111) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 111) + -4;
    *(uint32_t *)(gen_code_ptr + 131) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 131) + -4;
    gen_code_ptr += 140;
}
break;

case INDEX_op_sarw_T0_T1_cc: {
    extern void op_sarw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarw_T0_T1_cc+0), 138);
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 109) + -4;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 129) + -4;
    gen_code_ptr += 138;
}
break;

case INDEX_op_shldw_T0_T1_im_cc: {
    long param1;
    extern void op_shldw_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_T0_T1_im_cc+0), 174);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 169) + -4;
    gen_code_ptr += 174;
}
break;

case INDEX_op_shldw_T0_T1_ECX_cc: {
    extern void op_shldw_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_T0_T1_ECX_cc+0), 144);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 144;
}
break;

case INDEX_op_shrdw_T0_T1_im_cc: {
    long param1;
    extern void op_shrdw_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_T0_T1_im_cc+0), 169);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = param1 - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 107) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 107) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 164) + -4;
    gen_code_ptr += 169;
}
break;

case INDEX_op_shrdw_T0_T1_ECX_cc: {
    extern void op_shrdw_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_T0_T1_ECX_cc+0), 188);
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 114) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 114) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 159) + -4;
    *(uint32_t *)(gen_code_ptr + 179) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 179) + -4;
    gen_code_ptr += 188;
}
break;

case INDEX_op_adcw_T0_T1_cc: {
    extern void op_adcw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcw_T0_T1_cc+0), 120);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 120;
}
break;

case INDEX_op_sbbw_T0_T1_cc: {
    extern void op_sbbw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbw_T0_T1_cc+0), 124);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 99) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 99) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 119) + -4;
    gen_code_ptr += 124;
}
break;

case INDEX_op_cmpxchgw_T0_T1_EAX_cc: {
    extern void op_cmpxchgw_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgw_T0_T1_EAX_cc+0), 140);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 76) + -4;
    *(uint32_t *)(gen_code_ptr + 104) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 104) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 126) + -4;
    gen_code_ptr += 140;
}
break;

case INDEX_op_rolw_raw_T0_T1_cc: {
    extern void op_rolw_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_raw_T0_T1_cc+0), 199);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 101) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 190) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 190) + -4;
    gen_code_ptr += 199;
}
break;

case INDEX_op_rorw_raw_T0_T1_cc: {
    extern void op_rorw_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_raw_T0_T1_cc+0), 202);
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 57) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 101) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 193) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 193) + -4;
    gen_code_ptr += 202;
}
break;

case INDEX_op_rolw_raw_T0_T1: {
    extern void op_rolw_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_raw_T0_T1+0), 117);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_rorw_raw_T0_T1: {
    extern void op_rorw_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_raw_T0_T1+0), 117);
    *(uint32_t *)(gen_code_ptr + 50) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 50) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_rclw_raw_T0_T1_cc: {
    extern void op_rclw_raw_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclw_raw_T0_T1_cc+0), 268);
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 129) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 180) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 180) + -4;
    gen_code_ptr += 268;
}
break;

case INDEX_op_rcrw_raw_T0_T1_cc: {
    extern void op_rcrw_raw_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrw_raw_T0_T1_cc+0), 192);
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 178) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 178) + -4;
    gen_code_ptr += 192;
}
break;

case INDEX_op_shlw_raw_T0_T1_cc: {
    extern void op_shlw_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlw_raw_T0_T1_cc+0), 156);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 147) + -4;
    gen_code_ptr += 156;
}
break;

case INDEX_op_shrw_raw_T0_T1_cc: {
    extern void op_shrw_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrw_raw_T0_T1_cc+0), 174);
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 45) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 145) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 145) + -4;
    *(uint32_t *)(gen_code_ptr + 165) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 165) + -4;
    gen_code_ptr += 174;
}
break;

case INDEX_op_sarw_raw_T0_T1_cc: {
    extern void op_sarw_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarw_raw_T0_T1_cc+0), 172);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 68) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 163) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 163) + -4;
    gen_code_ptr += 172;
}
break;

case INDEX_op_shldw_raw_T0_T1_im_cc: {
    long param1;
    extern void op_shldw_raw_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_raw_T0_T1_im_cc+0), 204);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 131) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 131) + -4;
    *(uint32_t *)(gen_code_ptr + 179) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 179) + -4;
    *(uint32_t *)(gen_code_ptr + 199) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 199) + -4;
    gen_code_ptr += 204;
}
break;

case INDEX_op_shldw_raw_T0_T1_ECX_cc: {
    extern void op_shldw_raw_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_raw_T0_T1_ECX_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 79) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 79) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 94) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 119) + -4;
    *(uint32_t *)(gen_code_ptr + 138) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 138) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_shrdw_raw_T0_T1_im_cc: {
    long param1;
    extern void op_shrdw_raw_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_raw_T0_T1_im_cc+0), 199);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = param1 - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 107) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 107) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 126) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 174) + -4;
    *(uint32_t *)(gen_code_ptr + 194) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 194) + -4;
    gen_code_ptr += 199;
}
break;

case INDEX_op_shrdw_raw_T0_T1_ECX_cc: {
    extern void op_shrdw_raw_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_raw_T0_T1_ECX_cc+0), 218);
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 114) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 114) + -4;
    *(uint32_t *)(gen_code_ptr + 133) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 133) + -4;
    *(uint32_t *)(gen_code_ptr + 189) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 189) + -4;
    *(uint32_t *)(gen_code_ptr + 209) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 209) + -4;
    gen_code_ptr += 218;
}
break;

case INDEX_op_adcw_raw_T0_T1_cc: {
    extern void op_adcw_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcw_raw_T0_T1_cc+0), 150);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 125) + -4;
    *(uint32_t *)(gen_code_ptr + 145) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 145) + -4;
    gen_code_ptr += 150;
}
break;

case INDEX_op_sbbw_raw_T0_T1_cc: {
    extern void op_sbbw_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbw_raw_T0_T1_cc+0), 154);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 129) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 149) + -4;
    gen_code_ptr += 154;
}
break;

case INDEX_op_cmpxchgw_raw_T0_T1_EAX_cc: {
    extern void op_cmpxchgw_raw_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgw_raw_T0_T1_EAX_cc+0), 170);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 106) + -4;
    *(uint32_t *)(gen_code_ptr + 134) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 134) + -4;
    *(uint32_t *)(gen_code_ptr + 156) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 156) + -4;
    gen_code_ptr += 170;
}
break;

case INDEX_op_rolw_kernel_T0_T1_cc: {
    extern void op_rolw_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_kernel_T0_T1_cc+0), 294);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 158) + -4;
    *(uint32_t *)(gen_code_ptr + 185) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 185) + -4;
    *(uint32_t *)(gen_code_ptr + 204) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 268) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 268) + -4;
    gen_code_ptr += 294;
}
break;

case INDEX_op_rorw_kernel_T0_T1_cc: {
    extern void op_rorw_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_kernel_T0_T1_cc+0), 297);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 158) + -4;
    *(uint32_t *)(gen_code_ptr + 185) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 185) + -4;
    *(uint32_t *)(gen_code_ptr + 204) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 271) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 271) + -4;
    gen_code_ptr += 297;
}
break;

case INDEX_op_rolw_kernel_T0_T1: {
    extern void op_rolw_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_kernel_T0_T1+0), 198);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 173) + -4;
    gen_code_ptr += 198;
}
break;

case INDEX_op_rorw_kernel_T0_T1: {
    extern void op_rorw_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_kernel_T0_T1+0), 198);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 173) + -4;
    gen_code_ptr += 198;
}
break;

case INDEX_op_rclw_kernel_T0_T1_cc: {
    extern void op_rclw_kernel_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclw_kernel_T0_T1_cc+0), 340);
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 134) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 134) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 159) + -4;
    *(uint32_t *)(gen_code_ptr + 220) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 220) + -4;
    *(uint32_t *)(gen_code_ptr + 247) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 247) + -4;
    gen_code_ptr += 340;
}
break;

case INDEX_op_rcrw_kernel_T0_T1_cc: {
    extern void op_rcrw_kernel_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char __stw_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrw_kernel_T0_T1_cc+0), 274);
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 247) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 247) + -4;
    gen_code_ptr += 274;
}
break;

case INDEX_op_shlw_kernel_T0_T1_cc: {
    extern void op_shlw_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlw_kernel_T0_T1_cc+0), 251);
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 148) + -4;
    *(uint32_t *)(gen_code_ptr + 175) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 175) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 225) + -4;
    gen_code_ptr += 251;
}
break;

case INDEX_op_shrw_kernel_T0_T1_cc: {
    extern void op_shrw_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrw_kernel_T0_T1_cc+0), 269);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 173) + -4;
    *(uint32_t *)(gen_code_ptr + 223) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 223) + -4;
    *(uint32_t *)(gen_code_ptr + 243) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 243) + -4;
    gen_code_ptr += 269;
}
break;

case INDEX_op_sarw_kernel_T0_T1_cc: {
    extern void op_sarw_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarw_kernel_T0_T1_cc+0), 267);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 171) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 171) + -4;
    *(uint32_t *)(gen_code_ptr + 221) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 221) + -4;
    *(uint32_t *)(gen_code_ptr + 241) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 241) + -4;
    gen_code_ptr += 267;
}
break;

case INDEX_op_shldw_kernel_T0_T1_im_cc: {
    long param1;
    extern void op_shldw_kernel_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_kernel_T0_T1_im_cc+0), 270);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 115) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 173) + -4;
    *(uint32_t *)(gen_code_ptr + 200) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 200) + -4;
    *(uint32_t *)(gen_code_ptr + 242) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 242) + -4;
    *(uint32_t *)(gen_code_ptr + 262) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 262) + -4;
    gen_code_ptr += 270;
}
break;

case INDEX_op_shldw_kernel_T0_T1_ECX_cc: {
    extern void op_shldw_kernel_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_kernel_T0_T1_ECX_cc+0), 273);
    *(uint32_t *)(gen_code_ptr + 97) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 97) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 137) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 137) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 222) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 222) + -4;
    gen_code_ptr += 273;
}
break;

case INDEX_op_shrdw_kernel_T0_T1_im_cc: {
    long param1;
    extern void op_shrdw_kernel_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_kernel_T0_T1_im_cc+0), 265);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 85) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 85) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 110) + -4;
    *(uint32_t *)(gen_code_ptr + 168) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 168) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 237) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 237) + -4;
    *(uint32_t *)(gen_code_ptr + 257) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 257) + -4;
    gen_code_ptr += 265;
}
break;

case INDEX_op_shrdw_kernel_T0_T1_ECX_cc: {
    extern void op_shrdw_kernel_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_kernel_T0_T1_ECX_cc+0), 313);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 92) + -4;
    *(uint32_t *)(gen_code_ptr + 107) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 107) + -4;
    *(uint32_t *)(gen_code_ptr + 132) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 132) + -4;
    *(uint32_t *)(gen_code_ptr + 190) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 190) + -4;
    *(uint32_t *)(gen_code_ptr + 217) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 217) + -4;
    *(uint32_t *)(gen_code_ptr + 267) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 267) + -4;
    *(uint32_t *)(gen_code_ptr + 287) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 287) + -4;
    gen_code_ptr += 313;
}
break;

case INDEX_op_adcw_kernel_T0_T1_cc: {
    extern void op_adcw_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcw_kernel_T0_T1_cc+0), 216);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 109) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 109) + -4;
    *(uint32_t *)(gen_code_ptr + 136) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 136) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 208) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 208) + -4;
    gen_code_ptr += 216;
}
break;

case INDEX_op_sbbw_kernel_T0_T1_cc: {
    extern void op_sbbw_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbw_kernel_T0_T1_cc+0), 220);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 113) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 113) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 140) + -4;
    *(uint32_t *)(gen_code_ptr + 192) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 192) + -4;
    *(uint32_t *)(gen_code_ptr + 212) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 212) + -4;
    gen_code_ptr += 220;
}
break;

case INDEX_op_cmpxchgw_kernel_T0_T1_EAX_cc: {
    extern void op_cmpxchgw_kernel_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgw_kernel_T0_T1_EAX_cc+0), 269);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 125) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 125) + -4;
    *(uint32_t *)(gen_code_ptr + 152) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 152) + -4;
    *(uint32_t *)(gen_code_ptr + 187) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 187) + -4;
    *(uint32_t *)(gen_code_ptr + 215) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 215) + -4;
    *(uint32_t *)(gen_code_ptr + 237) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 237) + -4;
    gen_code_ptr += 269;
}
break;

case INDEX_op_rolw_user_T0_T1_cc: {
    extern void op_rolw_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_user_T0_T1_cc+0), 297);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 207) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 271) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 271) + -4;
    gen_code_ptr += 297;
}
break;

case INDEX_op_rorw_user_T0_T1_cc: {
    extern void op_rorw_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_user_T0_T1_cc+0), 300);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 100) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 100) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 161) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 207) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 274) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 274) + -4;
    gen_code_ptr += 300;
}
break;

case INDEX_op_rolw_user_T0_T1: {
    extern void op_rolw_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rolw_user_T0_T1+0), 201);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    gen_code_ptr += 201;
}
break;

case INDEX_op_rorw_user_T0_T1: {
    extern void op_rorw_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorw_user_T0_T1+0), 201);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    gen_code_ptr += 201;
}
break;

case INDEX_op_rclw_user_T0_T1_cc: {
    extern void op_rclw_user_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rclw_user_T0_T1_cc+0), 343);
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 134) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 134) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 159) + -4;
    *(uint32_t *)(gen_code_ptr + 223) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 223) + -4;
    *(uint32_t *)(gen_code_ptr + 250) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 250) + -4;
    gen_code_ptr += 343;
}
break;

case INDEX_op_rcrw_user_T0_T1_cc: {
    extern void op_rcrw_user_T0_T1_cc();
extern char rclw_table;
extern char cc_table;
extern char __stw_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrw_user_T0_T1_cc+0), 277);
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)(long)(&rclw_table) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 164) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 164) + -4;
    *(uint32_t *)(gen_code_ptr + 250) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 250) + -4;
    gen_code_ptr += 277;
}
break;

case INDEX_op_shlw_user_T0_T1_cc: {
    extern void op_shlw_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shlw_user_T0_T1_cc+0), 254);
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 151) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 151) + -4;
    *(uint32_t *)(gen_code_ptr + 178) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 178) + -4;
    *(uint32_t *)(gen_code_ptr + 228) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 228) + -4;
    gen_code_ptr += 254;
}
break;

case INDEX_op_shrw_user_T0_T1_cc: {
    extern void op_shrw_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrw_user_T0_T1_cc+0), 272);
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    *(uint32_t *)(gen_code_ptr + 226) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 226) + -4;
    *(uint32_t *)(gen_code_ptr + 246) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 246) + -4;
    gen_code_ptr += 272;
}
break;

case INDEX_op_sarw_user_T0_T1_cc: {
    extern void op_sarw_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarw_user_T0_T1_cc+0), 270);
    *(uint32_t *)(gen_code_ptr + 61) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 61) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 147) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 174) + -4;
    *(uint32_t *)(gen_code_ptr + 224) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 224) + -4;
    *(uint32_t *)(gen_code_ptr + 244) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 244) + -4;
    gen_code_ptr += 270;
}
break;

case INDEX_op_shldw_user_T0_T1_im_cc: {
    long param1;
    extern void op_shldw_user_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_user_T0_T1_im_cc+0), 273);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 115) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 176) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 203) + -4;
    *(uint32_t *)(gen_code_ptr + 245) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 245) + -4;
    *(uint32_t *)(gen_code_ptr + 265) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 265) + -4;
    gen_code_ptr += 273;
}
break;

case INDEX_op_shldw_user_T0_T1_ECX_cc: {
    extern void op_shldw_user_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldw_user_T0_T1_ECX_cc+0), 276);
    *(uint32_t *)(gen_code_ptr + 97) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 97) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 137) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 137) + -4;
    *(uint32_t *)(gen_code_ptr + 198) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 198) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 225) + -4;
    gen_code_ptr += 276;
}
break;

case INDEX_op_shrdw_user_T0_T1_im_cc: {
    long param1;
    extern void op_shrdw_user_T0_T1_im_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_user_T0_T1_im_cc+0), 268);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 70) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 70) + -4;
    *(uint32_t *)(gen_code_ptr + 85) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 85) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 110) + -4;
    *(uint32_t *)(gen_code_ptr + 171) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 171) + -4;
    *(uint32_t *)(gen_code_ptr + 198) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 198) + -4;
    *(uint32_t *)(gen_code_ptr + 240) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 240) + -4;
    *(uint32_t *)(gen_code_ptr + 260) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 260) + -4;
    gen_code_ptr += 268;
}
break;

case INDEX_op_shrdw_user_T0_T1_ECX_cc: {
    extern void op_shrdw_user_T0_T1_ECX_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdw_user_T0_T1_ECX_cc+0), 316);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 92) + -4;
    *(uint32_t *)(gen_code_ptr + 107) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 107) + -4;
    *(uint32_t *)(gen_code_ptr + 132) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 132) + -4;
    *(uint32_t *)(gen_code_ptr + 193) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 193) + -4;
    *(uint32_t *)(gen_code_ptr + 220) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 220) + -4;
    *(uint32_t *)(gen_code_ptr + 270) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 270) + -4;
    *(uint32_t *)(gen_code_ptr + 290) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 290) + -4;
    gen_code_ptr += 316;
}
break;

case INDEX_op_adcw_user_T0_T1_cc: {
    extern void op_adcw_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcw_user_T0_T1_cc+0), 219);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 112) + -4;
    *(uint32_t *)(gen_code_ptr + 139) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 139) + -4;
    *(uint32_t *)(gen_code_ptr + 191) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 191) + -4;
    *(uint32_t *)(gen_code_ptr + 211) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 211) + -4;
    gen_code_ptr += 219;
}
break;

case INDEX_op_sbbw_user_T0_T1_cc: {
    extern void op_sbbw_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbw_user_T0_T1_cc+0), 223);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 116) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 116) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 215) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 215) + -4;
    gen_code_ptr += 223;
}
break;

case INDEX_op_cmpxchgw_user_T0_T1_EAX_cc: {
    extern void op_cmpxchgw_user_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stw_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgw_user_T0_T1_EAX_cc+0), 272);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&__TC_stw_mmu) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 155) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 155) + -4;
    *(uint32_t *)(gen_code_ptr + 190) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 190) + -4;
    *(uint32_t *)(gen_code_ptr + 218) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 218) + -4;
    *(uint32_t *)(gen_code_ptr + 240) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 240) + -4;
    gen_code_ptr += 272;
}
break;

case INDEX_op_btw_T0_T1_cc: {
    extern void op_btw_T0_T1_cc();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btw_T0_T1_cc+0), 45);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_btsw_T0_T1_cc: {
    extern void op_btsw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btsw_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_btrw_T0_T1_cc: {
    extern void op_btrw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btrw_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_btcw_T0_T1_cc: {
    extern void op_btcw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btcw_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_add_bitw_A0_T1: {
    extern void op_add_bitw_A0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_add_bitw_A0_T1+0), 65);
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 57) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 57) + -4;
    gen_code_ptr += 65;
}
break;

case INDEX_op_bsfw_T0_cc: {
    extern void op_bsfw_T0_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg2reg;
extern char taintcheck_fn1reg;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_bsfw_T0_cc+0), 118);
    *(uint32_t *)(gen_code_ptr + 43) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 43) + -4;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 106) + -4;
    gen_code_ptr += 118;
}
break;

case INDEX_op_bsrw_T0_cc: {
    extern void op_bsrw_T0_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg2reg;
extern char taintcheck_fn1reg;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_bsrw_T0_cc+0), 122);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 82) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 110) + -4;
    gen_code_ptr += 122;
}
break;

case INDEX_op_movl_T0_Dshiftw: {
    extern void op_movl_T0_Dshiftw();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_Dshiftw+0), 28);
    *(uint32_t *)(gen_code_ptr + 20) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 20) + -4;
    gen_code_ptr += 28;
}
break;

case INDEX_op_outw_T0_T1: {
    extern void op_outw_T0_T1();
extern char cpu_outw;
    memcpy(gen_code_ptr, (void *)((char *)&op_outw_T0_T1+0), 41);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&cpu_outw) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_inw_T0_T1: {
    extern void op_inw_T0_T1();
extern char taintcheck_reg_clean;
extern char cpu_inw;
    memcpy(gen_code_ptr, (void *)((char *)&op_inw_T0_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&cpu_inw) - (long)(gen_code_ptr + 30) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_inw_DX_T0: {
    extern void op_inw_DX_T0();
extern char taintcheck_reg_clean;
extern char cpu_inw;
    memcpy(gen_code_ptr, (void *)((char *)&op_inw_DX_T0+0), 47);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 31) = (long)(&cpu_inw) - (long)(gen_code_ptr + 31) + -4;
    gen_code_ptr += 47;
}
break;

case INDEX_op_outw_DX_T0: {
    extern void op_outw_DX_T0();
extern char cpu_outw;
    memcpy(gen_code_ptr, (void *)((char *)&op_outw_DX_T0+0), 41);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&cpu_outw) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_check_iow_T0: {
    extern void op_check_iow_T0();
extern char check_iow_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iow_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iow_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_check_iow_DX: {
    extern void op_check_iow_DX();
extern char check_iow_DX;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iow_DX+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iow_DX) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jb_subl: {
    long param1;
    extern void op_jb_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jb_subl+0), 15);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 11) = gen_labels[param1] - (long)(gen_code_ptr + 11) + -4;
    *(uint8_t *)(gen_code_ptr + 10) = 0xe9;
    gen_code_ptr += 15;
}
break;

case INDEX_op_jz_subl: {
    long param1;
    extern void op_jz_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_subl+0), 14);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = gen_labels[param1] - (long)(gen_code_ptr + 10) + -4;
    *(uint8_t *)(gen_code_ptr + 9) = 0xe9;
    gen_code_ptr += 14;
}
break;

case INDEX_op_jnz_subl: {
    long param1;
    extern void op_jnz_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_subl+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jbe_subl: {
    long param1;
    extern void op_jbe_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jbe_subl+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_js_subl: {
    long param1;
    extern void op_js_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_js_subl+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jl_subl: {
    long param1;
    extern void op_jl_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jl_subl+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_jle_subl: {
    long param1;
    extern void op_jle_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jle_subl+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = gen_labels[param1] - (long)(gen_code_ptr + 15) + -4;
    *(uint8_t *)(gen_code_ptr + 14) = 0xe9;
    gen_code_ptr += 19;
}
break;

case INDEX_op_loopnzl: {
    long param1;
    extern void op_loopnzl();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_loopnzl+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 18) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 18) + -4;
    *(uint32_t *)(gen_code_ptr + 35) = gen_labels[param1] - (long)(gen_code_ptr + 35) + -4;
    *(uint8_t *)(gen_code_ptr + 34) = 0xe9;
    gen_code_ptr += 39;
}
break;

case INDEX_op_loopzl: {
    long param1;
    extern void op_loopzl();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_loopzl+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 18) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 18) + -4;
    *(uint32_t *)(gen_code_ptr + 35) = gen_labels[param1] - (long)(gen_code_ptr + 35) + -4;
    *(uint8_t *)(gen_code_ptr + 34) = 0xe9;
    gen_code_ptr += 39;
}
break;

case INDEX_op_jz_ecxl: {
    long param1;
    extern void op_jz_ecxl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_ecxl+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jnz_ecxl: {
    long param1;
    extern void op_jnz_ecxl();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_ecxl+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_setb_T0_subl: {
    extern void op_setb_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_setb_T0_subl+0), 18);
    gen_code_ptr += 18;
}
break;

case INDEX_op_setz_T0_subl: {
    extern void op_setz_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_setz_T0_subl+0), 15);
    gen_code_ptr += 15;
}
break;

case INDEX_op_setbe_T0_subl: {
    extern void op_setbe_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_setbe_T0_subl+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_sets_T0_subl: {
    extern void op_sets_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_sets_T0_subl+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_setl_T0_subl: {
    extern void op_setl_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_setl_T0_subl+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_setle_T0_subl: {
    extern void op_setle_T0_subl();
    memcpy(gen_code_ptr, (void *)((char *)&op_setle_T0_subl+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_shll_T0_T1: {
    extern void op_shll_T0_T1();
extern char taintcheck_fn2regs;
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shll_T0_T1+0), 60);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    *(uint32_t *)(gen_code_ptr + 48) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 48) + -4;
    gen_code_ptr += 60;
}
break;

case INDEX_op_shrl_T0_T1: {
    extern void op_shrl_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrl_T0_T1+0), 72);
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 23) + -4;
    *(uint32_t *)(gen_code_ptr + 35) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 35) + -4;
    *(uint32_t *)(gen_code_ptr + 60) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 60) + -4;
    gen_code_ptr += 72;
}
break;

case INDEX_op_sarl_T0_T1: {
    extern void op_sarl_T0_T1();
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarl_T0_T1+0), 45);
    *(uint32_t *)(gen_code_ptr + 33) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 33) + -4;
    gen_code_ptr += 45;
}
break;

case INDEX_op_roll_T0_T1_cc: {
    extern void op_roll_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_T0_T1_cc+0), 153);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 144) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_rorl_T0_T1_cc: {
    extern void op_rorl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_T0_T1_cc+0), 153);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 144) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_roll_T0_T1: {
    extern void op_roll_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_T0_T1+0), 65);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 28) + -4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 53) + -4;
    gen_code_ptr += 65;
}
break;

case INDEX_op_rorl_T0_T1: {
    extern void op_rorl_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_T0_T1+0), 65);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 28) + -4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 53) + -4;
    gen_code_ptr += 65;
}
break;

case INDEX_op_rcll_T0_T1_cc: {
    extern void op_rcll_T0_T1_cc();
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcll_T0_T1_cc+0), 211);
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 108) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 140) + -4;
    gen_code_ptr += 211;
}
break;

case INDEX_op_rcrl_T0_T1_cc: {
    extern void op_rcrl_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrl_T0_T1_cc+0), 154);
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 145) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 145) + -4;
    gen_code_ptr += 154;
}
break;

case INDEX_op_shll_T0_T1_cc: {
    extern void op_shll_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shll_T0_T1_cc+0), 121);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 112) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 112) + -4;
    gen_code_ptr += 121;
}
break;

case INDEX_op_shrl_T0_T1_cc: {
    extern void op_shrl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrl_T0_T1_cc+0), 139);
    *(uint32_t *)(gen_code_ptr + 40) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 40) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 110) + -4;
    *(uint32_t *)(gen_code_ptr + 130) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 130) + -4;
    gen_code_ptr += 139;
}
break;

case INDEX_op_sarl_T0_T1_cc: {
    extern void op_sarl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarl_T0_T1_cc+0), 137);
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 38) + -4;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 108) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 128) + -4;
    gen_code_ptr += 137;
}
break;

case INDEX_op_shldl_T0_T1_im_cc: {
    long param1;
    extern void op_shldl_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_T0_T1_im_cc+0), 124);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = param1 - (long)(gen_code_ptr + 3) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 99) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 99) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 119) + -4;
    gen_code_ptr += 124;
}
break;

case INDEX_op_shldl_T0_T1_ECX_cc: {
    extern void op_shldl_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_T0_T1_ECX_cc+0), 149);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 120) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 120) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 140) + -4;
    gen_code_ptr += 149;
}
break;

case INDEX_op_shrdl_T0_T1_im_cc: {
    long param1;
    extern void op_shrdl_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_T0_T1_im_cc+0), 124);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = param1 - (long)(gen_code_ptr + 3) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 99) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 99) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 119) + -4;
    gen_code_ptr += 124;
}
break;

case INDEX_op_shrdl_T0_T1_ECX_cc: {
    extern void op_shrdl_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_T0_T1_ECX_cc+0), 149);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 120) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 120) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 140) + -4;
    gen_code_ptr += 149;
}
break;

case INDEX_op_adcl_T0_T1_cc: {
    extern void op_adcl_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcl_T0_T1_cc+0), 120);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 115) + -4;
    gen_code_ptr += 120;
}
break;

case INDEX_op_sbbl_T0_T1_cc: {
    extern void op_sbbl_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbl_T0_T1_cc+0), 124);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 99) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 99) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 119) + -4;
    gen_code_ptr += 124;
}
break;

case INDEX_op_cmpxchgl_T0_T1_EAX_cc: {
    extern void op_cmpxchgl_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgl_T0_T1_EAX_cc+0), 127);
    *(uint32_t *)(gen_code_ptr + 41) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 41) + -4;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 113) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 113) + -4;
    gen_code_ptr += 127;
}
break;

case INDEX_op_roll_raw_T0_T1_cc: {
    extern void op_roll_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_raw_T0_T1_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 105) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 169) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_rorl_raw_T0_T1_cc: {
    extern void op_rorl_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_raw_T0_T1_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 105) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 169) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_roll_raw_T0_T1: {
    extern void op_roll_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_raw_T0_T1+0), 94);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 28) + -4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 72) + -4;
    gen_code_ptr += 94;
}
break;

case INDEX_op_rorl_raw_T0_T1: {
    extern void op_rorl_raw_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_raw_T0_T1+0), 94);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 28) + -4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 72) + -4;
    gen_code_ptr += 94;
}
break;

case INDEX_op_rcll_raw_T0_T1_cc: {
    extern void op_rcll_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcll_raw_T0_T1_cc+0), 240);
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 108) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 140) + -4;
    *(uint32_t *)(gen_code_ptr + 159) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 159) + -4;
    gen_code_ptr += 240;
}
break;

case INDEX_op_rcrl_raw_T0_T1_cc: {
    extern void op_rcrl_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrl_raw_T0_T1_cc+0), 167);
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 158) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 158) + -4;
    gen_code_ptr += 167;
}
break;

case INDEX_op_shll_raw_T0_T1_cc: {
    extern void op_shll_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shll_raw_T0_T1_cc+0), 154);
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 46) + -4;
    *(uint32_t *)(gen_code_ptr + 71) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 71) + -4;
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 90) + -4;
    *(uint32_t *)(gen_code_ptr + 145) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 145) + -4;
    gen_code_ptr += 154;
}
break;

case INDEX_op_shrl_raw_T0_T1_cc: {
    extern void op_shrl_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrl_raw_T0_T1_cc+0), 172);
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 44) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 88) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 163) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 163) + -4;
    gen_code_ptr += 172;
}
break;

case INDEX_op_sarl_raw_T0_T1_cc: {
    extern void op_sarl_raw_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarl_raw_T0_T1_cc+0), 170);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 86) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 86) + -4;
    *(uint32_t *)(gen_code_ptr + 141) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 141) + -4;
    *(uint32_t *)(gen_code_ptr + 161) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 161) + -4;
    gen_code_ptr += 170;
}
break;

case INDEX_op_shldl_raw_T0_T1_im_cc: {
    long param1;
    extern void op_shldl_raw_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_raw_T0_T1_im_cc+0), 153);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = param1 - (long)(gen_code_ptr + 3) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 148) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_shldl_raw_T0_T1_ECX_cc: {
    extern void op_shldl_raw_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_raw_T0_T1_ECX_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 169) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_shrdl_raw_T0_T1_im_cc: {
    long param1;
    extern void op_shrdl_raw_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_raw_T0_T1_im_cc+0), 153);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = param1 - (long)(gen_code_ptr + 3) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 81) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 148) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_shrdl_raw_T0_T1_ECX_cc: {
    extern void op_shrdl_raw_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_raw_T0_T1_ECX_cc+0), 178);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 94) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 94) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 169) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_adcl_raw_T0_T1_cc: {
    extern void op_adcl_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcl_raw_T0_T1_cc+0), 149);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 124) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 124) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 144) + -4;
    gen_code_ptr += 149;
}
break;

case INDEX_op_sbbl_raw_T0_T1_cc: {
    extern void op_sbbl_raw_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbl_raw_T0_T1_cc+0), 153);
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 78) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 128) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 148) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_cmpxchgl_raw_T0_T1_EAX_cc: {
    extern void op_cmpxchgl_raw_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgl_raw_T0_T1_EAX_cc+0), 156);
    *(uint32_t *)(gen_code_ptr + 41) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 41) + -4;
    *(uint32_t *)(gen_code_ptr + 60) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 60) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    *(uint32_t *)(gen_code_ptr + 120) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 120) + -4;
    *(uint32_t *)(gen_code_ptr + 142) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 142) + -4;
    gen_code_ptr += 156;
}
break;

case INDEX_op_roll_kernel_T0_T1_cc: {
    extern void op_roll_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_kernel_T0_T1_cc+0), 274);
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 139) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 139) + -4;
    *(uint32_t *)(gen_code_ptr + 166) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 166) + -4;
    *(uint32_t *)(gen_code_ptr + 184) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 248) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 248) + -4;
    gen_code_ptr += 274;
}
break;

case INDEX_op_rorl_kernel_T0_T1_cc: {
    extern void op_rorl_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_kernel_T0_T1_cc+0), 274);
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 139) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 139) + -4;
    *(uint32_t *)(gen_code_ptr + 166) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 166) + -4;
    *(uint32_t *)(gen_code_ptr + 184) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 248) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 248) + -4;
    gen_code_ptr += 274;
}
break;

case INDEX_op_roll_kernel_T0_T1: {
    extern void op_roll_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_kernel_T0_T1+0), 175);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 123) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 123) + -4;
    *(uint32_t *)(gen_code_ptr + 150) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 150) + -4;
    gen_code_ptr += 175;
}
break;

case INDEX_op_rorl_kernel_T0_T1: {
    extern void op_rorl_kernel_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_kernel_T0_T1+0), 175);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 123) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 123) + -4;
    *(uint32_t *)(gen_code_ptr + 150) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 150) + -4;
    gen_code_ptr += 175;
}
break;

case INDEX_op_rcll_kernel_T0_T1_cc: {
    extern void op_rcll_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcll_kernel_T0_T1_cc+0), 321);
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 118) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 118) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 203) + -4;
    *(uint32_t *)(gen_code_ptr + 230) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 230) + -4;
    gen_code_ptr += 321;
}
break;

case INDEX_op_rcrl_kernel_T0_T1_cc: {
    extern void op_rcrl_kernel_T0_T1_cc();
extern char cc_table;
extern char __stl_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrl_kernel_T0_T1_cc+0), 232);
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 133) = (long)(&__stl_mmu) - (long)(gen_code_ptr + 133) + -4;
    *(uint32_t *)(gen_code_ptr + 218) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 218) + -4;
    gen_code_ptr += 232;
}
break;

case INDEX_op_shll_kernel_T0_T1_cc: {
    extern void op_shll_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shll_kernel_T0_T1_cc+0), 250);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 148) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 148) + -4;
    *(uint32_t *)(gen_code_ptr + 175) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 175) + -4;
    *(uint32_t *)(gen_code_ptr + 224) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 224) + -4;
    gen_code_ptr += 250;
}
break;

case INDEX_op_shrl_kernel_T0_T1_cc: {
    extern void op_shrl_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrl_kernel_T0_T1_cc+0), 268);
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 173) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 173) + -4;
    *(uint32_t *)(gen_code_ptr + 222) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 222) + -4;
    *(uint32_t *)(gen_code_ptr + 242) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 242) + -4;
    gen_code_ptr += 268;
}
break;

case INDEX_op_sarl_kernel_T0_T1_cc: {
    extern void op_sarl_kernel_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarl_kernel_T0_T1_cc+0), 266);
    *(uint32_t *)(gen_code_ptr + 60) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 60) + -4;
    *(uint32_t *)(gen_code_ptr + 85) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 85) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 171) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 171) + -4;
    *(uint32_t *)(gen_code_ptr + 220) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 220) + -4;
    *(uint32_t *)(gen_code_ptr + 240) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 240) + -4;
    gen_code_ptr += 266;
}
break;

case INDEX_op_shldl_kernel_T0_T1_im_cc: {
    long param1;
    extern void op_shldl_kernel_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_kernel_T0_T1_im_cc+0), 220);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 124) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 124) + -4;
    *(uint32_t *)(gen_code_ptr + 151) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 151) + -4;
    *(uint32_t *)(gen_code_ptr + 192) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 192) + -4;
    *(uint32_t *)(gen_code_ptr + 212) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 212) + -4;
    gen_code_ptr += 220;
}
break;

case INDEX_op_shldl_kernel_T0_T1_ECX_cc: {
    extern void op_shldl_kernel_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_kernel_T0_T1_ECX_cc+0), 274);
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 152) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 152) + -4;
    *(uint32_t *)(gen_code_ptr + 179) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 179) + -4;
    *(uint32_t *)(gen_code_ptr + 228) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 228) + -4;
    *(uint32_t *)(gen_code_ptr + 248) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 248) + -4;
    gen_code_ptr += 274;
}
break;

case INDEX_op_shrdl_kernel_T0_T1_im_cc: {
    long param1;
    extern void op_shrdl_kernel_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_kernel_T0_T1_im_cc+0), 220);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 124) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 124) + -4;
    *(uint32_t *)(gen_code_ptr + 151) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 151) + -4;
    *(uint32_t *)(gen_code_ptr + 192) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 192) + -4;
    *(uint32_t *)(gen_code_ptr + 212) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 212) + -4;
    gen_code_ptr += 220;
}
break;

case INDEX_op_shrdl_kernel_T0_T1_ECX_cc: {
    extern void op_shrdl_kernel_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_kernel_T0_T1_ECX_cc+0), 274);
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 152) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 152) + -4;
    *(uint32_t *)(gen_code_ptr + 179) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 179) + -4;
    *(uint32_t *)(gen_code_ptr + 228) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 228) + -4;
    *(uint32_t *)(gen_code_ptr + 248) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 248) + -4;
    gen_code_ptr += 274;
}
break;

case INDEX_op_adcl_kernel_T0_T1_cc: {
    extern void op_adcl_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcl_kernel_T0_T1_cc+0), 216);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 110) + -4;
    *(uint32_t *)(gen_code_ptr + 137) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 137) + -4;
    *(uint32_t *)(gen_code_ptr + 188) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 188) + -4;
    *(uint32_t *)(gen_code_ptr + 208) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 208) + -4;
    gen_code_ptr += 216;
}
break;

case INDEX_op_sbbl_kernel_T0_T1_cc: {
    extern void op_sbbl_kernel_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbl_kernel_T0_T1_cc+0), 220);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 114) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 114) + -4;
    *(uint32_t *)(gen_code_ptr + 141) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 141) + -4;
    *(uint32_t *)(gen_code_ptr + 192) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 192) + -4;
    *(uint32_t *)(gen_code_ptr + 212) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 212) + -4;
    gen_code_ptr += 220;
}
break;

case INDEX_op_cmpxchgl_kernel_T0_T1_EAX_cc: {
    extern void op_cmpxchgl_kernel_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgl_kernel_T0_T1_EAX_cc+0), 254);
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 119) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 119) + -4;
    *(uint32_t *)(gen_code_ptr + 146) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 146) + -4;
    *(uint32_t *)(gen_code_ptr + 172) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 172) + -4;
    *(uint32_t *)(gen_code_ptr + 200) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 200) + -4;
    *(uint32_t *)(gen_code_ptr + 222) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 222) + -4;
    gen_code_ptr += 254;
}
break;

case INDEX_op_roll_user_T0_T1_cc: {
    extern void op_roll_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_user_T0_T1_cc+0), 277);
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 142) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 142) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 169) + -4;
    *(uint32_t *)(gen_code_ptr + 187) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 251) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 251) + -4;
    gen_code_ptr += 277;
}
break;

case INDEX_op_rorl_user_T0_T1_cc: {
    extern void op_rorl_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char cc_table;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_user_T0_T1_cc+0), 277);
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 80) + -4;
    *(uint32_t *)(gen_code_ptr + 142) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 142) + -4;
    *(uint32_t *)(gen_code_ptr + 169) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 169) + -4;
    *(uint32_t *)(gen_code_ptr + 187) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 251) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 251) + -4;
    gen_code_ptr += 277;
}
break;

case INDEX_op_roll_user_T0_T1: {
    extern void op_roll_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_roll_user_T0_T1+0), 178);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 126) + -4;
    *(uint32_t *)(gen_code_ptr + 153) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 153) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_rorl_user_T0_T1: {
    extern void op_rorl_user_T0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rorl_user_T0_T1+0), 178);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 126) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 126) + -4;
    *(uint32_t *)(gen_code_ptr + 153) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 153) + -4;
    gen_code_ptr += 178;
}
break;

case INDEX_op_rcll_user_T0_T1_cc: {
    extern void op_rcll_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcll_user_T0_T1_cc+0), 324);
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 118) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 118) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 143) + -4;
    *(uint32_t *)(gen_code_ptr + 206) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 206) + -4;
    *(uint32_t *)(gen_code_ptr + 233) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 233) + -4;
    gen_code_ptr += 324;
}
break;

case INDEX_op_rcrl_user_T0_T1_cc: {
    extern void op_rcrl_user_T0_T1_cc();
extern char cc_table;
extern char __stl_mmu;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcrl_user_T0_T1_cc+0), 235);
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 136) = (long)(&__stl_mmu) - (long)(gen_code_ptr + 136) + -4;
    *(uint32_t *)(gen_code_ptr + 221) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 221) + -4;
    gen_code_ptr += 235;
}
break;

case INDEX_op_shll_user_T0_T1_cc: {
    extern void op_shll_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_shll_user_T0_T1_cc+0), 253);
    *(uint32_t *)(gen_code_ptr + 64) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 64) + -4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 151) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 151) + -4;
    *(uint32_t *)(gen_code_ptr + 178) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 178) + -4;
    *(uint32_t *)(gen_code_ptr + 227) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 227) + -4;
    gen_code_ptr += 253;
}
break;

case INDEX_op_shrl_user_T0_T1_cc: {
    extern void op_shrl_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrl_user_T0_T1_cc+0), 271);
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 87) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 87) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 176) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 176) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 225) + -4;
    *(uint32_t *)(gen_code_ptr + 245) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 245) + -4;
    gen_code_ptr += 271;
}
break;

case INDEX_op_sarl_user_T0_T1_cc: {
    extern void op_sarl_user_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sarl_user_T0_T1_cc+0), 269);
    *(uint32_t *)(gen_code_ptr + 60) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 60) + -4;
    *(uint32_t *)(gen_code_ptr + 85) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 85) + -4;
    *(uint32_t *)(gen_code_ptr + 147) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 147) + -4;
    *(uint32_t *)(gen_code_ptr + 174) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 174) + -4;
    *(uint32_t *)(gen_code_ptr + 223) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 223) + -4;
    *(uint32_t *)(gen_code_ptr + 243) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 243) + -4;
    gen_code_ptr += 269;
}
break;

case INDEX_op_shldl_user_T0_T1_im_cc: {
    long param1;
    extern void op_shldl_user_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_user_T0_T1_im_cc+0), 223);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 127) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 127) + -4;
    *(uint32_t *)(gen_code_ptr + 154) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 154) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 215) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 215) + -4;
    gen_code_ptr += 223;
}
break;

case INDEX_op_shldl_user_T0_T1_ECX_cc: {
    extern void op_shldl_user_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shldl_user_T0_T1_ECX_cc+0), 277);
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 155) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 155) + -4;
    *(uint32_t *)(gen_code_ptr + 182) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 182) + -4;
    *(uint32_t *)(gen_code_ptr + 231) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 231) + -4;
    *(uint32_t *)(gen_code_ptr + 251) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 251) + -4;
    gen_code_ptr += 277;
}
break;

case INDEX_op_shrdl_user_T0_T1_im_cc: {
    long param1;
    extern void op_shrdl_user_T0_T1_im_cc();
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_user_T0_T1_im_cc+0), 223);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = param1 - (long)(gen_code_ptr + 4) + -4;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 127) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 127) + -4;
    *(uint32_t *)(gen_code_ptr + 154) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 154) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 215) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 215) + -4;
    gen_code_ptr += 223;
}
break;

case INDEX_op_shrdl_user_T0_T1_ECX_cc: {
    extern void op_shrdl_user_T0_T1_ECX_cc();
extern char taintcheck_fn3regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_shrdl_user_T0_T1_ECX_cc+0), 277);
    *(uint32_t *)(gen_code_ptr + 93) = (long)(&taintcheck_fn3regs) - (long)(gen_code_ptr + 93) + -4;
    *(uint32_t *)(gen_code_ptr + 155) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 155) + -4;
    *(uint32_t *)(gen_code_ptr + 182) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 182) + -4;
    *(uint32_t *)(gen_code_ptr + 231) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 231) + -4;
    *(uint32_t *)(gen_code_ptr + 251) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 251) + -4;
    gen_code_ptr += 277;
}
break;

case INDEX_op_adcl_user_T0_T1_cc: {
    extern void op_adcl_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_adcl_user_T0_T1_cc+0), 219);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    *(uint32_t *)(gen_code_ptr + 113) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 113) + -4;
    *(uint32_t *)(gen_code_ptr + 140) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 140) + -4;
    *(uint32_t *)(gen_code_ptr + 191) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 191) + -4;
    *(uint32_t *)(gen_code_ptr + 211) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 211) + -4;
    gen_code_ptr += 219;
}
break;

case INDEX_op_sbbl_user_T0_T1_cc: {
    extern void op_sbbl_user_T0_T1_cc();
extern char cc_table;
extern char taintcheck_fn2regs;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sbbl_user_T0_T1_cc+0), 223);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 55) + -4;
    *(uint32_t *)(gen_code_ptr + 117) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 117) + -4;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 144) + -4;
    *(uint32_t *)(gen_code_ptr + 195) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 195) + -4;
    *(uint32_t *)(gen_code_ptr + 215) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 215) + -4;
    gen_code_ptr += 223;
}
break;

case INDEX_op_cmpxchgl_user_T0_T1_EAX_cc: {
    extern void op_cmpxchgl_user_T0_T1_EAX_cc();
extern char taintcheck_reg2reg;
extern char __TC_stl_mmu;
extern char taintcheck_reg2mem;
extern char taintcheck_reg2reg;
extern char taintcheck_reg2reg;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpxchgl_user_T0_T1_EAX_cc+0), 257);
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 122) = (long)(&__TC_stl_mmu) - (long)(gen_code_ptr + 122) + -4;
    *(uint32_t *)(gen_code_ptr + 149) = (long)(&taintcheck_reg2mem) - (long)(gen_code_ptr + 149) + -4;
    *(uint32_t *)(gen_code_ptr + 175) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 175) + -4;
    *(uint32_t *)(gen_code_ptr + 203) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 203) + -4;
    *(uint32_t *)(gen_code_ptr + 225) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 225) + -4;
    gen_code_ptr += 257;
}
break;

case INDEX_op_btl_T0_T1_cc: {
    extern void op_btl_T0_T1_cc();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btl_T0_T1_cc+0), 42);
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 42;
}
break;

case INDEX_op_btsl_T0_T1_cc: {
    extern void op_btsl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btsl_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_btrl_T0_T1_cc: {
    extern void op_btrl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btrl_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_btcl_T0_T1_cc: {
    extern void op_btcl_T0_T1_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_btcl_T0_T1_cc+0), 100);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 100;
}
break;

case INDEX_op_add_bitl_A0_T1: {
    extern void op_add_bitl_A0_T1();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn2regs;
    memcpy(gen_code_ptr, (void *)((char *)&op_add_bitl_A0_T1+0), 59);
    *(uint32_t *)(gen_code_ptr + 26) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 26) + -4;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 51) + -4;
    gen_code_ptr += 59;
}
break;

case INDEX_op_bsfl_T0_cc: {
    extern void op_bsfl_T0_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg2reg;
extern char taintcheck_fn1reg;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_bsfl_T0_cc+0), 114);
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 59) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 59) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 102) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 102) + -4;
    gen_code_ptr += 114;
}
break;

case INDEX_op_bsrl_T0_cc: {
    extern void op_bsrl_T0_cc();
extern char taintcheck_reg_clean2;
extern char taintcheck_reg2reg;
extern char taintcheck_fn1reg;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_bsrl_T0_cc+0), 117);
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 77) + -4;
    *(uint32_t *)(gen_code_ptr + 105) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 105) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_update_bt_cc: {
    extern void op_update_bt_cc();
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_update_bt_cc+0), 36);
    *(uint32_t *)(gen_code_ptr + 28) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 28) + -4;
    gen_code_ptr += 36;
}
break;

case INDEX_op_movl_T0_Dshiftl: {
    extern void op_movl_T0_Dshiftl();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_Dshiftl+0), 29);
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_outl_T0_T1: {
    extern void op_outl_T0_T1();
extern char cpu_outl;
    memcpy(gen_code_ptr, (void *)((char *)&op_outl_T0_T1+0), 40);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&cpu_outl) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_inl_T0_T1: {
    extern void op_inl_T0_T1();
extern char taintcheck_reg_clean;
extern char cpu_inl;
    memcpy(gen_code_ptr, (void *)((char *)&op_inl_T0_T1+0), 46);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&cpu_inl) - (long)(gen_code_ptr + 30) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_inl_DX_T0: {
    extern void op_inl_DX_T0();
extern char taintcheck_reg_clean;
extern char cpu_inl;
    memcpy(gen_code_ptr, (void *)((char *)&op_inl_DX_T0+0), 47);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 31) = (long)(&cpu_inl) - (long)(gen_code_ptr + 31) + -4;
    gen_code_ptr += 47;
}
break;

case INDEX_op_outl_DX_T0: {
    extern void op_outl_DX_T0();
extern char cpu_outl;
    memcpy(gen_code_ptr, (void *)((char *)&op_outl_DX_T0+0), 41);
    *(uint32_t *)(gen_code_ptr + 25) = (long)(&cpu_outl) - (long)(gen_code_ptr + 25) + -4;
    gen_code_ptr += 41;
}
break;

case INDEX_op_check_iol_T0: {
    extern void op_check_iol_T0();
extern char check_iol_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iol_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iol_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_check_iol_DX: {
    extern void op_check_iol_DX();
extern char check_iol_DX;
    memcpy(gen_code_ptr, (void *)((char *)&op_check_iol_DX+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&check_iol_DX) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_movsbl_T0_T0: {
    extern void op_movsbl_T0_T0();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_movsbl_T0_T0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movzbl_T0_T0: {
    extern void op_movzbl_T0_T0();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_movzbl_T0_T0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movswl_T0_T0: {
    extern void op_movswl_T0_T0();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_movswl_T0_T0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movzwl_T0_T0: {
    extern void op_movzwl_T0_T0();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_movzwl_T0_T0+0), 32);
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 32;
}
break;

case INDEX_op_movswl_EAX_AX: {
    extern void op_movswl_EAX_AX();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_movswl_EAX_AX+0), 30);
    *(uint32_t *)(gen_code_ptr + 22) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 22) + -4;
    gen_code_ptr += 30;
}
break;

case INDEX_op_movsbw_AX_AL: {
    extern void op_movsbw_AX_AL();
extern char taintcheck_reg_clean2;
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movsbw_AX_AL+0), 54);
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 34) + -4;
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 46) + -4;
    gen_code_ptr += 54;
}
break;

case INDEX_op_movslq_EDX_EAX: {
    extern void op_movslq_EDX_EAX();
extern char taintcheck_reg_clean;
extern char taintcheck_reg2reg_shift;
extern char taintcheck_fn1reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movslq_EDX_EAX+0), 63);
    *(uint32_t *)(gen_code_ptr + 20) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 20) + -4;
    *(uint32_t *)(gen_code_ptr + 40) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 40) + -4;
    *(uint32_t *)(gen_code_ptr + 55) = (long)(&taintcheck_fn1reg) - (long)(gen_code_ptr + 55) + -4;
    gen_code_ptr += 63;
}
break;

case INDEX_op_movswl_DX_AX: {
    extern void op_movswl_DX_AX();
extern char taintcheck_reg2reg_shift;
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_movswl_DX_AX+0), 77);
    *(uint32_t *)(gen_code_ptr + 49) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 49) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 69) + -4;
    gen_code_ptr += 77;
}
break;

case INDEX_op_addl_ESI_T0: {
    extern void op_addl_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_ESI_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_addw_ESI_T0: {
    extern void op_addw_ESI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_ESI_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_addl_EDI_T0: {
    extern void op_addl_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_EDI_T0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_addw_EDI_T0: {
    extern void op_addw_EDI_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_EDI_T0+0), 25);
    gen_code_ptr += 25;
}
break;

case INDEX_op_decl_ECX: {
    extern void op_decl_ECX();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_decl_ECX+0), 31);
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_decw_ECX: {
    extern void op_decw_ECX();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_decw_ECX+0), 49);
    *(uint32_t *)(gen_code_ptr + 41) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 41) + -4;
    gen_code_ptr += 49;
}
break;

case INDEX_op_addl_A0_SS: {
    extern void op_addl_A0_SS();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_A0_SS+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_subl_A0_2: {
    extern void op_subl_A0_2();
    memcpy(gen_code_ptr, (void *)((char *)&op_subl_A0_2+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_subl_A0_4: {
    extern void op_subl_A0_4();
    memcpy(gen_code_ptr, (void *)((char *)&op_subl_A0_4+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_addl_ESP_4: {
    extern void op_addl_ESP_4();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_ESP_4+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_addl_ESP_2: {
    extern void op_addl_ESP_2();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_ESP_2+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_addw_ESP_4: {
    extern void op_addw_ESP_4();
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_ESP_4+0), 21);
    gen_code_ptr += 21;
}
break;

case INDEX_op_addw_ESP_2: {
    extern void op_addw_ESP_2();
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_ESP_2+0), 21);
    gen_code_ptr += 21;
}
break;

case INDEX_op_addl_ESP_im: {
    long param1;
    extern void op_addl_ESP_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_addl_ESP_im+0), 10);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    gen_code_ptr += 10;
}
break;

case INDEX_op_addw_ESP_im: {
    long param1;
    extern void op_addw_ESP_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_addw_ESP_im+0), 26);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_rdtsc: {
    extern void op_rdtsc();
extern char helper_rdtsc;
    memcpy(gen_code_ptr, (void *)((char *)&op_rdtsc+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_rdtsc) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_rdpmc: {
    extern void op_rdpmc();
extern char helper_rdpmc;
    memcpy(gen_code_ptr, (void *)((char *)&op_rdpmc+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_rdpmc) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_cpuid: {
    extern void op_cpuid();
extern char helper_cpuid;
    memcpy(gen_code_ptr, (void *)((char *)&op_cpuid+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_cpuid) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_enter_level: {
    long param1, param2;
    extern void op_enter_level();
extern char helper_enter_level;
    memcpy(gen_code_ptr, (void *)((char *)&op_enter_level+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&helper_enter_level) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_sysenter: {
    extern void op_sysenter();
extern char helper_sysenter;
    memcpy(gen_code_ptr, (void *)((char *)&op_sysenter+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_sysenter) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_sysexit: {
    extern void op_sysexit();
extern char helper_sysexit;
    memcpy(gen_code_ptr, (void *)((char *)&op_sysexit+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_sysexit) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_rdmsr: {
    extern void op_rdmsr();
extern char helper_rdmsr;
    memcpy(gen_code_ptr, (void *)((char *)&op_rdmsr+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_rdmsr) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_wrmsr: {
    extern void op_wrmsr();
extern char helper_wrmsr;
    memcpy(gen_code_ptr, (void *)((char *)&op_wrmsr+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_wrmsr) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_aam: {
    long param1;
    extern void op_aam();
    memcpy(gen_code_ptr, (void *)((char *)&op_aam+0), 37);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = param1 - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_aad: {
    long param1;
    extern void op_aad();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_aad+0), 49);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 40) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 40) + -4;
    gen_code_ptr += 49;
}
break;

case INDEX_op_aaa: {
    extern void op_aaa();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_aaa+0), 124);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 124;
}
break;

case INDEX_op_aas: {
    extern void op_aas();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_aas+0), 122);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 122;
}
break;

case INDEX_op_daa: {
    extern void op_daa();
extern char cc_table;
extern char parity_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_daa+0), 140);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 108) = (int32_t)(long)(&parity_table) + 0;
    gen_code_ptr += 140;
}
break;

case INDEX_op_das: {
    extern void op_das();
extern char cc_table;
extern char parity_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_das+0), 164);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 132) = (int32_t)(long)(&parity_table) + 0;
    gen_code_ptr += 164;
}
break;

case INDEX_op_movl_seg_T0: {
    long param1;
    extern void op_movl_seg_T0();
extern char load_seg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_seg_T0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&load_seg) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_movl_seg_T0_vm: {
    long param1;
    extern void op_movl_seg_T0_vm();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_seg_T0_vm+0), 22);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 4;
    gen_code_ptr += 22;
}
break;

case INDEX_op_movl_T0_seg: {
    long param1;
    extern void op_movl_T0_seg();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_seg+0), 35);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 27) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 27) + -4;
    gen_code_ptr += 35;
}
break;

case INDEX_op_lsl: {
    extern void op_lsl();
extern char helper_lsl;
    memcpy(gen_code_ptr, (void *)((char *)&op_lsl+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_lsl) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_lar: {
    extern void op_lar();
extern char helper_lar;
    memcpy(gen_code_ptr, (void *)((char *)&op_lar+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_lar) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_verr: {
    extern void op_verr();
extern char helper_verr;
    memcpy(gen_code_ptr, (void *)((char *)&op_verr+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_verr) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_verw: {
    extern void op_verw();
extern char helper_verw;
    memcpy(gen_code_ptr, (void *)((char *)&op_verw+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_verw) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_arpl: {
    extern void op_arpl();
extern char taintcheck_fn2regs;
extern char taintcheck_reg_clean;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_arpl+0), 104);
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_fn2regs) - (long)(gen_code_ptr + 62) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 72) + -4;
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 104;
}
break;

case INDEX_op_arpl_update: {
    extern void op_arpl_update();
extern char cc_table;
extern char taintcheck_reg2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_arpl_update+0), 53);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg2reg) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_ljmp_protected_T0_T1: {
    long param1;
    extern void op_ljmp_protected_T0_T1();
extern char helper_ljmp_protected_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_ljmp_protected_T0_T1+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&helper_ljmp_protected_T0_T1) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_lcall_real_T0_T1: {
    long param1, param2;
    extern void op_lcall_real_T0_T1();
extern char helper_lcall_real_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_lcall_real_T0_T1+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&helper_lcall_real_T0_T1) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_lcall_protected_T0_T1: {
    long param1, param2;
    extern void op_lcall_protected_T0_T1();
extern char helper_lcall_protected_T0_T1;
    memcpy(gen_code_ptr, (void *)((char *)&op_lcall_protected_T0_T1+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&helper_lcall_protected_T0_T1) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_iret_real: {
    long param1;
    extern void op_iret_real();
extern char helper_iret_real;
    memcpy(gen_code_ptr, (void *)((char *)&op_iret_real+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&helper_iret_real) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_iret_protected: {
    long param1, param2;
    extern void op_iret_protected();
extern char helper_iret_protected;
    memcpy(gen_code_ptr, (void *)((char *)&op_iret_protected+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&helper_iret_protected) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_lret_protected: {
    long param1, param2;
    extern void op_lret_protected();
extern char helper_lret_protected;
    memcpy(gen_code_ptr, (void *)((char *)&op_lret_protected+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&helper_lret_protected) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_lldt_T0: {
    extern void op_lldt_T0();
extern char helper_lldt_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_lldt_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_lldt_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_ltr_T0: {
    extern void op_ltr_T0();
extern char helper_ltr_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_ltr_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_ltr_T0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_movl_crN_T0: {
    long param1;
    extern void op_movl_crN_T0();
extern char helper_movl_crN_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_crN_T0+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&helper_movl_crN_T0) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_svm_check_intercept: {
    long param1, param2;
    extern void op_svm_check_intercept();
extern char svm_check_intercept_param;
    memcpy(gen_code_ptr, (void *)((char *)&op_svm_check_intercept+0), 50);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 6) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = param1 - (long)(gen_code_ptr + 12) + -4;
    *(uint32_t *)(gen_code_ptr + 30) = param2 - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 42) = (long)(&svm_check_intercept_param) - (long)(gen_code_ptr + 42) + -4;
    gen_code_ptr += 50;
}
break;

case INDEX_op_svm_check_intercept_param: {
    long param1, param2;
    extern void op_svm_check_intercept_param();
extern char svm_check_intercept_param;
    memcpy(gen_code_ptr, (void *)((char *)&op_svm_check_intercept_param+0), 52);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (uint32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = param2 - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 26) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&svm_check_intercept_param) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_svm_vmexit: {
    long param1, param2;
    extern void op_svm_vmexit();
extern char vmexit;
    memcpy(gen_code_ptr, (void *)((char *)&op_svm_vmexit+0), 52);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = param1 - (long)(gen_code_ptr + 6) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (uint32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = param2 - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 26) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&vmexit) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_geneflags: {
    extern void op_geneflags();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_geneflags+0), 22);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 22;
}
break;

case INDEX_op_svm_check_intercept_io: {
    long param1, param2;
    extern void op_svm_check_intercept_io();
extern char stq_phys;
extern char svm_check_intercept_param;
    memcpy(gen_code_ptr, (void *)((char *)&op_svm_check_intercept_io+0), 89);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (uint32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (uint32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (long)(&stq_phys) - (long)(gen_code_ptr + 36) + -4;
    *(uint32_t *)(gen_code_ptr + 42) = param1 - (long)(gen_code_ptr + 42) + -4;
    *(uint32_t *)(gen_code_ptr + 48) = param2 - (long)(gen_code_ptr + 48) + -4;
    *(uint32_t *)(gen_code_ptr + 81) = (long)(&svm_check_intercept_param) - (long)(gen_code_ptr + 81) + -4;
    gen_code_ptr += 89;
}
break;

case INDEX_op_movtl_T0_cr8: {
    extern void op_movtl_T0_cr8();
extern char cpu_get_apic_tpr;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movtl_T0_cr8+0), 29);
    *(uint32_t *)(gen_code_ptr + 8) = (long)(&cpu_get_apic_tpr) - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 24) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 24) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_movl_drN_T0: {
    long param1;
    extern void op_movl_drN_T0();
extern char helper_movl_drN_T0;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_drN_T0+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&helper_movl_drN_T0) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_lmsw_T0: {
    extern void op_lmsw_T0();
extern char helper_movl_crN_T0;
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_lmsw_T0+0), 53);
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&helper_movl_crN_T0) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 45) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 45) + -4;
    gen_code_ptr += 53;
}
break;

case INDEX_op_invlpg_A0: {
    extern void op_invlpg_A0();
extern char helper_invlpg;
    memcpy(gen_code_ptr, (void *)((char *)&op_invlpg_A0+0), 17);
    *(uint32_t *)(gen_code_ptr + 9) = (long)(&helper_invlpg) - (long)(gen_code_ptr + 9) + -4;
    gen_code_ptr += 17;
}
break;

case INDEX_op_movl_T0_env: {
    long param1;
    extern void op_movl_T0_env();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_env+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_movl_env_T0: {
    long param1;
    extern void op_movl_env_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_env_T0+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_movl_env_T1: {
    long param1;
    extern void op_movl_env_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_env_T1+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_movtl_T0_env: {
    long param1;
    extern void op_movtl_T0_env();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movtl_T0_env+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_movtl_env_T0: {
    long param1;
    extern void op_movtl_env_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_movtl_env_T0+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_movtl_T1_env: {
    long param1;
    extern void op_movtl_T1_env();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movtl_T1_env+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_movtl_env_T1: {
    long param1;
    extern void op_movtl_env_T1();
    memcpy(gen_code_ptr, (void *)((char *)&op_movtl_env_T1+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_clts: {
    extern void op_clts();
    memcpy(gen_code_ptr, (void *)((char *)&op_clts+0), 16);
    gen_code_ptr += 16;
}
break;

case INDEX_op_goto_tb0: {
    long param1;
    extern void op_goto_tb0();
    memcpy(gen_code_ptr, (void *)((char *)&op_goto_tb0+0), 8);
    label_offsets[0] = 8 + (gen_code_ptr - gen_code_buf);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + 64;
    gen_code_ptr += 8;
}
break;

case INDEX_op_goto_tb1: {
    long param1;
    extern void op_goto_tb1();
    memcpy(gen_code_ptr, (void *)((char *)&op_goto_tb1+0), 8);
    label_offsets[1] = 8 + (gen_code_ptr - gen_code_buf);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + 68;
    gen_code_ptr += 8;
}
break;

case INDEX_op_jmp_label: {
    long param1;
    extern void op_jmp_label();
    memcpy(gen_code_ptr, (void *)((char *)&op_jmp_label+0), 5);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = gen_labels[param1] - (long)(gen_code_ptr + 1) + -4;
    *(uint8_t *)(gen_code_ptr + 0) = 0xe9;
    gen_code_ptr += 5;
}
break;

case INDEX_op_jnz_T0_label: {
    long param1;
    extern void op_jnz_T0_label();
    memcpy(gen_code_ptr, (void *)((char *)&op_jnz_T0_label+0), 13);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = gen_labels[param1] - (long)(gen_code_ptr + 9) + -4;
    *(uint8_t *)(gen_code_ptr + 8) = 0xe9;
    gen_code_ptr += 13;
}
break;

case INDEX_op_jz_T0_label: {
    long param1;
    extern void op_jz_T0_label();
    memcpy(gen_code_ptr, (void *)((char *)&op_jz_T0_label+0), 14);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = gen_labels[param1] - (long)(gen_code_ptr + 10) + -4;
    *(uint8_t *)(gen_code_ptr + 9) = 0xe9;
    gen_code_ptr += 14;
}
break;

case INDEX_op_seto_T0_cc: {
    extern void op_seto_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_seto_T0_cc+0), 52);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_setb_T0_cc: {
    extern void op_setb_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setb_T0_cc+0), 42);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 42;
}
break;

case INDEX_op_setz_T0_cc: {
    extern void op_setz_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setz_T0_cc+0), 52);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_setbe_T0_cc: {
    extern void op_setbe_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setbe_T0_cc+0), 54);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 46) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 46) + -4;
    gen_code_ptr += 54;
}
break;

case INDEX_op_sets_T0_cc: {
    extern void op_sets_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_sets_T0_cc+0), 52);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_setp_T0_cc: {
    extern void op_setp_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setp_T0_cc+0), 52);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 44) + -4;
    gen_code_ptr += 52;
}
break;

case INDEX_op_setl_T0_cc: {
    extern void op_setl_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setl_T0_cc+0), 59);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 51) + -4;
    gen_code_ptr += 59;
}
break;

case INDEX_op_setle_T0_cc: {
    extern void op_setle_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_setle_T0_cc+0), 75);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 67) + -4;
    gen_code_ptr += 75;
}
break;

case INDEX_op_xor_T0_1: {
    extern void op_xor_T0_1();
    memcpy(gen_code_ptr, (void *)((char *)&op_xor_T0_1+0), 5);
    gen_code_ptr += 5;
}
break;

case INDEX_op_set_cc_op: {
    long param1;
    extern void op_set_cc_op();
    memcpy(gen_code_ptr, (void *)((char *)&op_set_cc_op+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_mov_T0_cc: {
    extern void op_mov_T0_cc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_mov_T0_cc+0), 42);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 37) + -4;
    gen_code_ptr += 42;
}
break;

case INDEX_op_movl_eflags_T0: {
    extern void op_movl_eflags_T0();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_eflags_T0+0), 88);
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 80) + -4;
    gen_code_ptr += 88;
}
break;

case INDEX_op_movw_eflags_T0: {
    extern void op_movw_eflags_T0();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_eflags_T0+0), 85);
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 77) + -4;
    gen_code_ptr += 85;
}
break;

case INDEX_op_movl_eflags_T0_io: {
    extern void op_movl_eflags_T0_io();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_eflags_T0_io+0), 88);
    *(uint32_t *)(gen_code_ptr + 80) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 80) + -4;
    gen_code_ptr += 88;
}
break;

case INDEX_op_movw_eflags_T0_io: {
    extern void op_movw_eflags_T0_io();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_eflags_T0_io+0), 83);
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 83;
}
break;

case INDEX_op_movl_eflags_T0_cpl0: {
    extern void op_movl_eflags_T0_cpl0();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_eflags_T0_cpl0+0), 86);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 86;
}
break;

case INDEX_op_movw_eflags_T0_cpl0: {
    extern void op_movw_eflags_T0_cpl0();
extern char taintcheck_reg2flag;
    memcpy(gen_code_ptr, (void *)((char *)&op_movw_eflags_T0_cpl0+0), 85);
    *(uint32_t *)(gen_code_ptr + 77) = (long)(&taintcheck_reg2flag) - (long)(gen_code_ptr + 77) + -4;
    gen_code_ptr += 85;
}
break;

case INDEX_op_movb_eflags_T0: {
    extern void op_movb_eflags_T0();
extern char cc_table;
extern char TEMU_eflags;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movb_eflags_T0+0), 81);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 73) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 73) + -4;
    gen_code_ptr += 81;
}
break;

case INDEX_op_movl_T0_eflags: {
    extern void op_movl_T0_eflags();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_eflags+0), 70);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 62) + -4;
    gen_code_ptr += 70;
}
break;

case INDEX_op_cld: {
    extern void op_cld();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_cld+0), 18);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 10) + -8;
    gen_code_ptr += 18;
}
break;

case INDEX_op_std: {
    extern void op_std();
extern char TEMU_eflags;
    memcpy(gen_code_ptr, (void *)((char *)&op_std+0), 18);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&TEMU_eflags) - (long)(gen_code_ptr + 10) + -8;
    gen_code_ptr += 18;
}
break;

case INDEX_op_clc: {
    extern void op_clc();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_clc+0), 29);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 29;
}
break;

case INDEX_op_stc: {
    extern void op_stc();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_stc+0), 29);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 29;
}
break;

case INDEX_op_cmc: {
    extern void op_cmc();
extern char cc_table;
    memcpy(gen_code_ptr, (void *)((char *)&op_cmc+0), 29);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 0;
    gen_code_ptr += 29;
}
break;

case INDEX_op_salc: {
    extern void op_salc();
extern char cc_table;
extern char taintcheck_flag2reg;
    memcpy(gen_code_ptr, (void *)((char *)&op_salc+0), 56);
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)(long)(&cc_table) + 8;
    *(uint32_t *)(gen_code_ptr + 48) = (long)(&taintcheck_flag2reg) - (long)(gen_code_ptr + 48) + -4;
    gen_code_ptr += 56;
}
break;

case INDEX_op_flds_FT0_A0: {
    extern void op_flds_FT0_A0();
extern char __ldl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_flds_FT0_A0+0), 117);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 117;
}
break;

case INDEX_op_fldl_FT0_A0: {
    extern void op_fldl_FT0_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldl_FT0_A0+0), 120);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 120;
}
break;

case INDEX_op_fild_FT0_A0: {
    extern void op_fild_FT0_A0();
extern char __ldw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fild_FT0_A0+0), 115);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&__ldw_mmu) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 115;
}
break;

case INDEX_op_fildl_FT0_A0: {
    extern void op_fildl_FT0_A0();
extern char __ldl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fildl_FT0_A0+0), 113);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 113;
}
break;

case INDEX_op_fildll_FT0_A0: {
    extern void op_fildll_FT0_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fildll_FT0_A0+0), 115);
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 115;
}
break;

case INDEX_op_flds_ST0_A0: {
    extern void op_flds_ST0_A0();
extern char __ldl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_flds_ST0_A0+0), 160);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 160;
}
break;

case INDEX_op_fldl_ST0_A0: {
    extern void op_fldl_ST0_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldl_ST0_A0+0), 163);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 163;
}
break;

case INDEX_op_fldt_ST0_A0: {
    extern void op_fldt_ST0_A0();
extern char helper_fldt_ST0_A0;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldt_ST0_A0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fldt_ST0_A0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fild_ST0_A0: {
    extern void op_fild_ST0_A0();
extern char __ldw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fild_ST0_A0+0), 160);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&__ldw_mmu) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 160;
}
break;

case INDEX_op_fildl_ST0_A0: {
    extern void op_fildl_ST0_A0();
extern char __ldl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fildl_ST0_A0+0), 156);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&__ldl_mmu) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 156;
}
break;

case INDEX_op_fildll_ST0_A0: {
    extern void op_fildll_ST0_A0();
extern char __ldq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fildll_ST0_A0+0), 158);
    *(uint32_t *)(gen_code_ptr + 92) = (long)(&__ldq_mmu) - (long)(gen_code_ptr + 92) + -4;
    gen_code_ptr += 158;
}
break;

case INDEX_op_fsts_ST0_A0: {
    extern void op_fsts_ST0_A0();
extern char __stl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fsts_ST0_A0+0), 131);
    *(uint32_t *)(gen_code_ptr + 107) = (long)(&__stl_mmu) - (long)(gen_code_ptr + 107) + -4;
    gen_code_ptr += 131;
}
break;

case INDEX_op_fstl_ST0_A0: {
    extern void op_fstl_ST0_A0();
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fstl_ST0_A0+0), 131);
    *(uint32_t *)(gen_code_ptr + 106) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 106) + -4;
    gen_code_ptr += 131;
}
break;

case INDEX_op_fstt_ST0_A0: {
    extern void op_fstt_ST0_A0();
extern char helper_fstt_ST0_A0;
    memcpy(gen_code_ptr, (void *)((char *)&op_fstt_ST0_A0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fstt_ST0_A0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fist_ST0_A0: {
    extern void op_fist_ST0_A0();
extern char floatx80_to_int32;
extern char __stw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fist_ST0_A0+0), 168);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int32) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 143) + -4;
    gen_code_ptr += 168;
}
break;

case INDEX_op_fistl_ST0_A0: {
    extern void op_fistl_ST0_A0();
extern char floatx80_to_int32;
extern char __stl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fistl_ST0_A0+0), 153);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int32) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&__stl_mmu) - (long)(gen_code_ptr + 129) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_fistll_ST0_A0: {
    extern void op_fistll_ST0_A0();
extern char floatx80_to_int64;
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fistll_ST0_A0+0), 155);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int64) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 130) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 130) + -4;
    gen_code_ptr += 155;
}
break;

case INDEX_op_fistt_ST0_A0: {
    extern void op_fistt_ST0_A0();
extern char floatx80_to_int32_round_to_zero;
extern char __stw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fistt_ST0_A0+0), 168);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int32_round_to_zero) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 143) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 143) + -4;
    gen_code_ptr += 168;
}
break;

case INDEX_op_fisttl_ST0_A0: {
    extern void op_fisttl_ST0_A0();
extern char floatx80_to_int32_round_to_zero;
extern char __stl_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fisttl_ST0_A0+0), 153);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int32_round_to_zero) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 129) = (long)(&__stl_mmu) - (long)(gen_code_ptr + 129) + -4;
    gen_code_ptr += 153;
}
break;

case INDEX_op_fisttll_ST0_A0: {
    extern void op_fisttll_ST0_A0();
extern char floatx80_to_int64_round_to_zero;
extern char __stq_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fisttll_ST0_A0+0), 155);
    *(uint32_t *)(gen_code_ptr + 47) = (long)(&floatx80_to_int64_round_to_zero) - (long)(gen_code_ptr + 47) + -4;
    *(uint32_t *)(gen_code_ptr + 130) = (long)(&__stq_mmu) - (long)(gen_code_ptr + 130) + -4;
    gen_code_ptr += 155;
}
break;

case INDEX_op_fbld_ST0_A0: {
    extern void op_fbld_ST0_A0();
extern char helper_fbld_ST0_A0;
    memcpy(gen_code_ptr, (void *)((char *)&op_fbld_ST0_A0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fbld_ST0_A0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fbst_ST0_A0: {
    extern void op_fbst_ST0_A0();
extern char helper_fbst_ST0_A0;
    memcpy(gen_code_ptr, (void *)((char *)&op_fbst_ST0_A0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fbst_ST0_A0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fpush: {
    extern void op_fpush();
    memcpy(gen_code_ptr, (void *)((char *)&op_fpush+0), 29);
    gen_code_ptr += 29;
}
break;

case INDEX_op_fpop: {
    extern void op_fpop();
    memcpy(gen_code_ptr, (void *)((char *)&op_fpop+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fdecstp: {
    extern void op_fdecstp();
    memcpy(gen_code_ptr, (void *)((char *)&op_fdecstp+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fincstp: {
    extern void op_fincstp();
    memcpy(gen_code_ptr, (void *)((char *)&op_fincstp+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_ffree_STN: {
    long param1;
    extern void op_ffree_STN();
    memcpy(gen_code_ptr, (void *)((char *)&op_ffree_STN+0), 25);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param1 + 0;
    gen_code_ptr += 25;
}
break;

case INDEX_op_fmov_ST0_FT0: {
    extern void op_fmov_ST0_FT0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmov_ST0_FT0+0), 40);
    gen_code_ptr += 40;
}
break;

case INDEX_op_fmov_FT0_STN: {
    long param1;
    extern void op_fmov_FT0_STN();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmov_FT0_STN+0), 50);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    gen_code_ptr += 50;
}
break;

case INDEX_op_fmov_ST0_STN: {
    long param1;
    extern void op_fmov_ST0_STN();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmov_ST0_STN+0), 53);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    gen_code_ptr += 53;
}
break;

case INDEX_op_fmov_STN_ST0: {
    long param1;
    extern void op_fmov_STN_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmov_STN_ST0+0), 52);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    gen_code_ptr += 52;
}
break;

case INDEX_op_fxchg_ST0_STN: {
    long param1;
    extern void op_fxchg_ST0_STN();
    memcpy(gen_code_ptr, (void *)((char *)&op_fxchg_ST0_STN+0), 65);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 65;
}
break;

case INDEX_op_fcom_ST0_FT0: {
    extern void op_fcom_ST0_FT0();
extern char floatx80_compare;
extern char fcom_ccval;
    memcpy(gen_code_ptr, (void *)((char *)&op_fcom_ST0_FT0+0), 111);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&floatx80_compare) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&fcom_ccval) + 0;
    gen_code_ptr += 111;
}
break;

case INDEX_op_fucom_ST0_FT0: {
    extern void op_fucom_ST0_FT0();
extern char floatx80_compare_quiet;
extern char fcom_ccval;
    memcpy(gen_code_ptr, (void *)((char *)&op_fucom_ST0_FT0+0), 111);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&floatx80_compare_quiet) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&fcom_ccval) + 0;
    gen_code_ptr += 111;
}
break;

case INDEX_op_fcomi_ST0_FT0: {
    extern void op_fcomi_ST0_FT0();
extern char floatx80_compare;
extern char cc_table;
extern char fcomi_ccval;
    memcpy(gen_code_ptr, (void *)((char *)&op_fcomi_ST0_FT0+0), 118);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&floatx80_compare) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 101) = (int32_t)(long)(&fcomi_ccval) + 0;
    gen_code_ptr += 118;
}
break;

case INDEX_op_fucomi_ST0_FT0: {
    extern void op_fucomi_ST0_FT0();
extern char floatx80_compare_quiet;
extern char cc_table;
extern char fcomi_ccval;
    memcpy(gen_code_ptr, (void *)((char *)&op_fucomi_ST0_FT0+0), 118);
    *(uint32_t *)(gen_code_ptr + 69) = (long)(&floatx80_compare_quiet) - (long)(gen_code_ptr + 69) + -4;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)(long)(&cc_table) + 0;
    *(uint32_t *)(gen_code_ptr + 101) = (int32_t)(long)(&fcomi_ccval) + 0;
    gen_code_ptr += 118;
}
break;

case INDEX_op_fcmov_ST0_STN_T0: {
    long param1;
    extern void op_fcmov_ST0_STN_T0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fcmov_ST0_STN_T0+0), 66);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    gen_code_ptr += 66;
}
break;

case INDEX_op_fadd_ST0_FT0: {
    extern void op_fadd_ST0_FT0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fadd_ST0_FT0+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fmul_ST0_FT0: {
    extern void op_fmul_ST0_FT0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmul_ST0_FT0+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fsub_ST0_FT0: {
    extern void op_fsub_ST0_FT0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fsub_ST0_FT0+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fsubr_ST0_FT0: {
    extern void op_fsubr_ST0_FT0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fsubr_ST0_FT0+0), 31);
    gen_code_ptr += 31;
}
break;

case INDEX_op_fdiv_ST0_FT0: {
    extern void op_fdiv_ST0_FT0();
extern char helper_fdiv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fdiv_ST0_FT0+0), 73);
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&helper_fdiv) - (long)(gen_code_ptr + 62) + -4;
    gen_code_ptr += 73;
}
break;

case INDEX_op_fdivr_ST0_FT0: {
    extern void op_fdivr_ST0_FT0();
extern char helper_fdiv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fdivr_ST0_FT0+0), 73);
    *(uint32_t *)(gen_code_ptr + 62) = (long)(&helper_fdiv) - (long)(gen_code_ptr + 62) + -4;
    gen_code_ptr += 73;
}
break;

case INDEX_op_fadd_STN_ST0: {
    long param1;
    extern void op_fadd_STN_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fadd_STN_ST0+0), 46);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 46;
}
break;

case INDEX_op_fmul_STN_ST0: {
    long param1;
    extern void op_fmul_STN_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fmul_STN_ST0+0), 46);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 46;
}
break;

case INDEX_op_fsub_STN_ST0: {
    long param1;
    extern void op_fsub_STN_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fsub_STN_ST0+0), 46);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 46;
}
break;

case INDEX_op_fsubr_STN_ST0: {
    long param1;
    extern void op_fsubr_STN_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fsubr_STN_ST0+0), 46);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 46;
}
break;

case INDEX_op_fdiv_STN_ST0: {
    long param1;
    extern void op_fdiv_STN_ST0();
extern char helper_fdiv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fdiv_STN_ST0+0), 86);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&helper_fdiv) - (long)(gen_code_ptr + 75) + -4;
    gen_code_ptr += 86;
}
break;

case INDEX_op_fdivr_STN_ST0: {
    long param1;
    extern void op_fdivr_STN_ST0();
extern char helper_fdiv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fdivr_STN_ST0+0), 89);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 78) = (long)(&helper_fdiv) - (long)(gen_code_ptr + 78) + -4;
    gen_code_ptr += 89;
}
break;

case INDEX_op_fchs_ST0: {
    extern void op_fchs_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fchs_ST0+0), 24);
    gen_code_ptr += 24;
}
break;

case INDEX_op_fabs_ST0: {
    extern void op_fabs_ST0();
    memcpy(gen_code_ptr, (void *)((char *)&op_fabs_ST0+0), 24);
    gen_code_ptr += 24;
}
break;

case INDEX_op_fxam_ST0: {
    extern void op_fxam_ST0();
extern char helper_fxam_ST0;
    memcpy(gen_code_ptr, (void *)((char *)&op_fxam_ST0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fxam_ST0) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fld1_ST0: {
    extern void op_fld1_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fld1_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 20;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 12;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldl2t_ST0: {
    extern void op_fldl2t_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldl2t_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 100;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 92;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldl2e_ST0: {
    extern void op_fldl2e_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldl2e_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 84;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 76;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldpi_ST0: {
    extern void op_fldpi_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldpi_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 36;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 28;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldlg2_ST0: {
    extern void op_fldlg2_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldlg2_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 52;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 44;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldln2_ST0: {
    extern void op_fldln2_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldln2_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 68;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + 60;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldz_ST0: {
    extern void op_fldz_ST0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldz_ST0+0), 39);
    *(uint32_t *)(gen_code_ptr + 10) = (long)(&f15rk) - (long)(gen_code_ptr + 10) + 4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&f15rk) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_fldz_FT0: {
    extern void op_fldz_FT0();
extern char f15rk;
extern char f15rk;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldz_FT0+0), 27);
    *(uint32_t *)(gen_code_ptr + 3) = (long)(&f15rk) - (long)(gen_code_ptr + 3) + -4;
    *(uint32_t *)(gen_code_ptr + 9) = (long)(&f15rk) - (long)(gen_code_ptr + 9) + 4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_f2xm1: {
    extern void op_f2xm1();
extern char helper_f2xm1;
    memcpy(gen_code_ptr, (void *)((char *)&op_f2xm1+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_f2xm1) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fyl2x: {
    extern void op_fyl2x();
extern char helper_fyl2x;
    memcpy(gen_code_ptr, (void *)((char *)&op_fyl2x+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fyl2x) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fptan: {
    extern void op_fptan();
extern char helper_fptan;
    memcpy(gen_code_ptr, (void *)((char *)&op_fptan+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fptan) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fpatan: {
    extern void op_fpatan();
extern char helper_fpatan;
    memcpy(gen_code_ptr, (void *)((char *)&op_fpatan+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fpatan) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fxtract: {
    extern void op_fxtract();
extern char helper_fxtract;
    memcpy(gen_code_ptr, (void *)((char *)&op_fxtract+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fxtract) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fprem1: {
    extern void op_fprem1();
extern char helper_fprem1;
    memcpy(gen_code_ptr, (void *)((char *)&op_fprem1+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fprem1) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fprem: {
    extern void op_fprem();
extern char helper_fprem;
    memcpy(gen_code_ptr, (void *)((char *)&op_fprem+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fprem) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fyl2xp1: {
    extern void op_fyl2xp1();
extern char helper_fyl2xp1;
    memcpy(gen_code_ptr, (void *)((char *)&op_fyl2xp1+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fyl2xp1) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fsqrt: {
    extern void op_fsqrt();
extern char helper_fsqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_fsqrt+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fsqrt) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fsincos: {
    extern void op_fsincos();
extern char helper_fsincos;
    memcpy(gen_code_ptr, (void *)((char *)&op_fsincos+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fsincos) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_frndint: {
    extern void op_frndint();
extern char helper_frndint;
    memcpy(gen_code_ptr, (void *)((char *)&op_frndint+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_frndint) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fscale: {
    extern void op_fscale();
extern char helper_fscale;
    memcpy(gen_code_ptr, (void *)((char *)&op_fscale+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fscale) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fsin: {
    extern void op_fsin();
extern char helper_fsin;
    memcpy(gen_code_ptr, (void *)((char *)&op_fsin+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fsin) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fcos: {
    extern void op_fcos();
extern char helper_fcos;
    memcpy(gen_code_ptr, (void *)((char *)&op_fcos+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_fcos) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_fnstsw_A0: {
    extern void op_fnstsw_A0();
extern char __stw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fnstsw_A0+0), 133);
    *(uint32_t *)(gen_code_ptr + 108) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 108) + -4;
    gen_code_ptr += 133;
}
break;

case INDEX_op_fnstsw_EAX: {
    extern void op_fnstsw_EAX();
    memcpy(gen_code_ptr, (void *)((char *)&op_fnstsw_EAX+0), 36);
    gen_code_ptr += 36;
}
break;

case INDEX_op_fnstcw_A0: {
    extern void op_fnstcw_A0();
extern char __stw_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_fnstcw_A0+0), 115);
    *(uint32_t *)(gen_code_ptr + 90) = (long)(&__stw_mmu) - (long)(gen_code_ptr + 90) + -4;
    gen_code_ptr += 115;
}
break;

case INDEX_op_fldcw_A0: {
    extern void op_fldcw_A0();
extern char __ldw_mmu;
extern char update_fp_status;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldcw_A0+0), 106);
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&__ldw_mmu) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 101) = (long)(&update_fp_status) - (long)(gen_code_ptr + 101) + -4;
    gen_code_ptr += 106;
}
break;

case INDEX_op_fclex: {
    extern void op_fclex();
    memcpy(gen_code_ptr, (void *)((char *)&op_fclex+0), 11);
    gen_code_ptr += 11;
}
break;

case INDEX_op_fwait: {
    extern void op_fwait();
extern char fpu_raise_exception;
    memcpy(gen_code_ptr, (void *)((char *)&op_fwait+0), 27);
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&fpu_raise_exception) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 27;
}
break;

case INDEX_op_fninit: {
    extern void op_fninit();
    memcpy(gen_code_ptr, (void *)((char *)&op_fninit+0), 97);
    gen_code_ptr += 97;
}
break;

case INDEX_op_fnstenv_A0: {
    long param1;
    extern void op_fnstenv_A0();
extern char helper_fstenv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fnstenv_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_fstenv) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_fldenv_A0: {
    long param1;
    extern void op_fldenv_A0();
extern char helper_fldenv;
    memcpy(gen_code_ptr, (void *)((char *)&op_fldenv_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_fldenv) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_fnsave_A0: {
    long param1;
    extern void op_fnsave_A0();
extern char helper_fsave;
    memcpy(gen_code_ptr, (void *)((char *)&op_fnsave_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_fsave) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_frstor_A0: {
    long param1;
    extern void op_frstor_A0();
extern char helper_frstor;
    memcpy(gen_code_ptr, (void *)((char *)&op_frstor_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_frstor) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_lock: {
    extern void op_lock();
extern char cpu_lock;
    memcpy(gen_code_ptr, (void *)((char *)&op_lock+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&cpu_lock) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_unlock: {
    extern void op_unlock();
extern char cpu_unlock;
    memcpy(gen_code_ptr, (void *)((char *)&op_unlock+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&cpu_unlock) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_movo: {
    long param1, param2;
    extern void op_movo();
    memcpy(gen_code_ptr, (void *)((char *)&op_movo+0), 50);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    gen_code_ptr += 50;
}
break;

case INDEX_op_movq: {
    long param1, param2;
    extern void op_movq();
    memcpy(gen_code_ptr, (void *)((char *)&op_movq+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_movl: {
    long param1, param2;
    extern void op_movl();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_movq_env_0: {
    long param1;
    extern void op_movq_env_0();
    memcpy(gen_code_ptr, (void *)((char *)&op_movq_env_0+0), 11);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    gen_code_ptr += 11;
}
break;

case INDEX_op_fxsave_A0: {
    long param1;
    extern void op_fxsave_A0();
extern char helper_fxsave;
    memcpy(gen_code_ptr, (void *)((char *)&op_fxsave_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_fxsave) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_fxrstor_A0: {
    long param1;
    extern void op_fxrstor_A0();
extern char helper_fxrstor;
    memcpy(gen_code_ptr, (void *)((char *)&op_fxrstor_A0+0), 23);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 10) = param1 - (long)(gen_code_ptr + 10) + -4;
    *(uint32_t *)(gen_code_ptr + 15) = (long)(&helper_fxrstor) - (long)(gen_code_ptr + 15) + -4;
    gen_code_ptr += 23;
}
break;

case INDEX_op_enter_mmx: {
    extern void op_enter_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_enter_mmx+0), 33);
    gen_code_ptr += 33;
}
break;

case INDEX_op_emms: {
    extern void op_emms();
    memcpy(gen_code_ptr, (void *)((char *)&op_emms+0), 22);
    gen_code_ptr += 22;
}
break;

case INDEX_op_insn_end: {
    extern void op_insn_end();
extern char TEMU_insn_end;
    memcpy(gen_code_ptr, (void *)((char *)&op_insn_end+0), 15);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&TEMU_insn_end) - (long)(gen_code_ptr + 7) + -4;
    gen_code_ptr += 15;
}
break;

case INDEX_op_insn_begin: {
    long param1;
    extern void op_insn_begin();
extern char TEMU_insn_begin;
    memcpy(gen_code_ptr, (void *)((char *)&op_insn_begin+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&TEMU_insn_begin) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_block_begin: {
    extern void op_block_begin();
extern char TEMU_block_begin;
    memcpy(gen_code_ptr, (void *)((char *)&op_block_begin+0), 20);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&TEMU_block_begin) - (long)(gen_code_ptr + 7) + -4;
    *(uint8_t *)(gen_code_ptr + 15) = 0xc3;
    gen_code_ptr += 20;
}
break;

case INDEX_op_taint_reg_clean: {
    long param1;
    extern void op_taint_reg_clean();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_taint_reg_clean+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_taint_patch: {
    extern void op_taint_patch();
extern char taintcheck_patch;
    memcpy(gen_code_ptr, (void *)((char *)&op_taint_patch+0), 15);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_patch) - (long)(gen_code_ptr + 7) + -4;
    gen_code_ptr += 15;
}
break;

case INDEX_op_taintcheck_jnz_T0_label: {
    long param1;
    extern void op_taintcheck_jnz_T0_label();
extern char taintcheck_jnz_T0_label;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_jnz_T0_label+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_jnz_T0_label) - (long)(gen_code_ptr + 7) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = gen_labels[param1] - (long)(gen_code_ptr + 17) + -4;
    *(uint8_t *)(gen_code_ptr + 16) = 0xe9;
    gen_code_ptr += 29;
}
break;

case INDEX_op_taintcheck_mov_i2m: {
    extern void op_taintcheck_mov_i2m();
extern char taintcheck_mov_i2m;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_mov_i2m+0), 15);
    *(uint32_t *)(gen_code_ptr + 7) = (long)(&taintcheck_mov_i2m) - (long)(gen_code_ptr + 7) + -4;
    gen_code_ptr += 15;
}
break;

case INDEX_op_taintcheck_mov_i2r: {
    long param1, param2;
    extern void op_taintcheck_mov_i2r();
extern char taintcheck_reg_clean2;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_mov_i2r+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param1 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 17) = (long)(&taintcheck_reg_clean2) - (long)(gen_code_ptr + 17) + -4;
    gen_code_ptr += 25;
}
break;

case INDEX_op_taintcheck_mov_r2r: {
    long param1, param2, param3;
    extern void op_taintcheck_mov_r2r();
extern char taintcheck_reg2reg_shift;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_mov_r2r+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param2 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 14) = param1 - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_reg2reg_shift) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_taintcheck_mov_m2r: {
    long param1, param2, param3;
    extern void op_taintcheck_mov_m2r();
extern char taintcheck_mov_m2r;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_mov_m2r+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param2 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 14) = param1 - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_mov_m2r) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_taintcheck_mov_r2m: {
    long param1, param2, param3;
    extern void op_taintcheck_mov_r2m();
extern char taintcheck_mov_r2m;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_mov_r2m+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param2 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 14) = param1 - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_mov_r2m) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_taintcheck_sidt_T0: {
    extern void op_taintcheck_sidt_T0();
extern char taintcheck_sidt;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_sidt_T0+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&taintcheck_sidt) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_taintcheck_code2TN: {
    long param1, param2, param3;
    extern void op_taintcheck_code2TN();
extern char taintcheck_code2TN;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_code2TN+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 8) = param2 - (long)(gen_code_ptr + 8) + -4;
    *(uint32_t *)(gen_code_ptr + 14) = param1 - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (long)(&taintcheck_code2TN) - (long)(gen_code_ptr + 23) + -4;
    gen_code_ptr += 31;
}
break;

case INDEX_op_taintcheck_check_eip: {
    long param1;
    extern void op_taintcheck_check_eip();
extern char taintcheck_check_eip;
    memcpy(gen_code_ptr, (void *)((char *)&op_taintcheck_check_eip+0), 19);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 11) = (long)(&taintcheck_check_eip) - (long)(gen_code_ptr + 11) + -4;
    gen_code_ptr += 19;
}
break;

case INDEX_op_opt_movl_A0_im: {
    long param1;
    extern void op_opt_movl_A0_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_A0_im+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_opt_addl_A0_im: {
    long param1;
    extern void op_opt_addl_A0_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_addl_A0_im+0), 10);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param1 - (long)(gen_code_ptr + 2) + -4;
    gen_code_ptr += 10;
}
break;

case INDEX_op_opt_andl_A0_ffff: {
    extern void op_opt_andl_A0_ffff();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_andl_A0_ffff+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T0_imu: {
    long param1;
    extern void op_opt_movl_T0_imu();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_imu+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_opt_movl_T0_im: {
    long param1;
    extern void op_opt_movl_T0_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T0_im+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_opt_movl_T1_A0: {
    extern void op_opt_movl_T1_A0();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_A0+0), 8);
    gen_code_ptr += 8;
}
break;

case INDEX_op_opt_movl_T1_im: {
    long param1;
    extern void op_opt_movl_T1_im();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_im+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_opt_movl_T1_imu: {
    long param1;
    extern void op_opt_movl_T1_imu();
    memcpy(gen_code_ptr, (void *)((char *)&op_opt_movl_T1_imu+0), 9);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 1) = (uint32_t)param1 + 0;
    gen_code_ptr += 9;
}
break;

case INDEX_op_psrlw_mmx: {
    long param1, param2;
    extern void op_psrlw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrlw_mmx+0), 86);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 0;
    gen_code_ptr += 86;
}
break;

case INDEX_op_psraw_mmx: {
    long param1, param2;
    extern void op_psraw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psraw_mmx+0), 79);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 45) = (int32_t)param1 + 0;
    gen_code_ptr += 79;
}
break;

case INDEX_op_psllw_mmx: {
    long param1, param2;
    extern void op_psllw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psllw_mmx+0), 86);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 0;
    gen_code_ptr += 86;
}
break;

case INDEX_op_psrld_mmx: {
    long param1, param2;
    extern void op_psrld_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrld_mmx+0), 43);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    gen_code_ptr += 43;
}
break;

case INDEX_op_psrad_mmx: {
    long param1, param2;
    extern void op_psrad_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrad_mmx+0), 35);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param2 + 0;
    gen_code_ptr += 35;
}
break;

case INDEX_op_pslld_mmx: {
    long param1, param2;
    extern void op_pslld_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pslld_mmx+0), 43);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    gen_code_ptr += 43;
}
break;

case INDEX_op_psrlq_mmx: {
    long param1, param2;
    extern void op_psrlq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrlq_mmx+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_psllq_mmx: {
    long param1, param2;
    extern void op_psllq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psllq_mmx+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_paddb_mmx: {
    long param1, param2;
    extern void op_paddb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddb_mmx+0), 73);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 73;
}
break;

case INDEX_op_paddw_mmx: {
    long param1, param2;
    extern void op_paddw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddw_mmx+0), 49);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 49;
}
break;

case INDEX_op_paddl_mmx: {
    long param1, param2;
    extern void op_paddl_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddl_mmx+0), 26);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_paddq_mmx: {
    long param1, param2;
    extern void op_paddq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddq_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_psubb_mmx: {
    long param1, param2;
    extern void op_psubb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubb_mmx+0), 73);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 73;
}
break;

case INDEX_op_psubw_mmx: {
    long param1, param2;
    extern void op_psubw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubw_mmx+0), 49);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 49;
}
break;

case INDEX_op_psubl_mmx: {
    long param1, param2;
    extern void op_psubl_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubl_mmx+0), 26);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 4;
    gen_code_ptr += 26;
}
break;

case INDEX_op_psubq_mmx: {
    long param1, param2;
    extern void op_psubq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubq_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_paddusb_mmx: {
    long param1, param2;
    extern void op_paddusb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddusb_mmx+0), 221);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 57) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (int32_t)param1 + 1;
    gen_code_ptr += 221;
}
break;

case INDEX_op_paddsb_mmx: {
    long param1, param2;
    extern void op_paddsb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddsb_mmx+0), 258);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 1;
    gen_code_ptr += 258;
}
break;

case INDEX_op_psubusb_mmx: {
    long param1, param2;
    extern void op_psubusb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubusb_mmx+0), 172);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    gen_code_ptr += 172;
}
break;

case INDEX_op_psubsb_mmx: {
    long param1, param2;
    extern void op_psubsb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubsb_mmx+0), 256);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 70) = (int32_t)param1 + 0;
    gen_code_ptr += 256;
}
break;

case INDEX_op_paddusw_mmx: {
    long param1, param2;
    extern void op_paddusw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddusw_mmx+0), 131);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)param1 + 2;
    gen_code_ptr += 131;
}
break;

case INDEX_op_paddsw_mmx: {
    long param1, param2;
    extern void op_paddsw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddsw_mmx+0), 166);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 73) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 81) = (int32_t)param1 + 2;
    gen_code_ptr += 166;
}
break;

case INDEX_op_psubusw_mmx: {
    long param1, param2;
    extern void op_psubusw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubusw_mmx+0), 106);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 0;
    gen_code_ptr += 106;
}
break;

case INDEX_op_psubsw_mmx: {
    long param1, param2;
    extern void op_psubsw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubsw_mmx+0), 162);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 74) = (int32_t)param1 + 0;
    gen_code_ptr += 162;
}
break;

case INDEX_op_pminub_mmx: {
    long param1, param2;
    extern void op_pminub_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pminub_mmx+0), 165);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 165;
}
break;

case INDEX_op_pmaxub_mmx: {
    long param1, param2;
    extern void op_pmaxub_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaxub_mmx+0), 165);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 165;
}
break;

case INDEX_op_pminsw_mmx: {
    long param1, param2;
    extern void op_pminsw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pminsw_mmx+0), 102);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 0;
    gen_code_ptr += 102;
}
break;

case INDEX_op_pmaxsw_mmx: {
    long param1, param2;
    extern void op_pmaxsw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaxsw_mmx+0), 102);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 0;
    gen_code_ptr += 102;
}
break;

case INDEX_op_pand_mmx: {
    long param1, param2;
    extern void op_pand_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pand_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_pandn_mmx: {
    long param1, param2;
    extern void op_pandn_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pandn_mmx+0), 24);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    gen_code_ptr += 24;
}
break;

case INDEX_op_por_mmx: {
    long param1, param2;
    extern void op_por_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_por_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_pxor_mmx: {
    long param1, param2;
    extern void op_pxor_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pxor_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 14;
}
break;

case INDEX_op_pcmpgtb_mmx: {
    long param1, param2;
    extern void op_pcmpgtb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtb_mmx+0), 161);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 161;
}
break;

case INDEX_op_pcmpgtw_mmx: {
    long param1, param2;
    extern void op_pcmpgtw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtw_mmx+0), 115);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 0;
    gen_code_ptr += 115;
}
break;

case INDEX_op_pcmpgtl_mmx: {
    long param1, param2;
    extern void op_pcmpgtl_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtl_mmx+0), 63);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 33) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 4;
    gen_code_ptr += 63;
}
break;

case INDEX_op_pcmpeqb_mmx: {
    long param1, param2;
    extern void op_pcmpeqb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeqb_mmx+0), 161);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 161;
}
break;

case INDEX_op_pcmpeqw_mmx: {
    long param1, param2;
    extern void op_pcmpeqw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeqw_mmx+0), 115);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 0;
    gen_code_ptr += 115;
}
break;

case INDEX_op_pcmpeql_mmx: {
    long param1, param2;
    extern void op_pcmpeql_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeql_mmx+0), 63);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 33) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 4;
    gen_code_ptr += 63;
}
break;

case INDEX_op_pmullw_mmx: {
    long param1, param2;
    extern void op_pmullw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmullw_mmx+0), 82);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    gen_code_ptr += 82;
}
break;

case INDEX_op_pmulhuw_mmx: {
    long param1, param2;
    extern void op_pmulhuw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmulhuw_mmx+0), 102);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 102;
}
break;

case INDEX_op_pmulhw_mmx: {
    long param1, param2;
    extern void op_pmulhw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmulhw_mmx+0), 102);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 102;
}
break;

case INDEX_op_pavgb_mmx: {
    long param1, param2;
    extern void op_pavgb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pavgb_mmx+0), 170);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 1;
    gen_code_ptr += 170;
}
break;

case INDEX_op_pavgw_mmx: {
    long param1, param2;
    extern void op_pavgw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pavgw_mmx+0), 106);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)param1 + 2;
    gen_code_ptr += 106;
}
break;

case INDEX_op_pmuludq_mmx: {
    long param1, param2;
    extern void op_pmuludq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmuludq_mmx+0), 25);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 0;
    gen_code_ptr += 25;
}
break;

case INDEX_op_pmaddwd_mmx: {
    long param1, param2;
    extern void op_pmaddwd_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaddwd_mmx+0), 97);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 74) = (int32_t)param2 + 4;
    gen_code_ptr += 97;
}
break;

case INDEX_op_psadbw_mmx: {
    long param1, param2;
    extern void op_psadbw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_psadbw_mmx+0), 269);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param1 + 7;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 7;
    *(uint32_t *)(gen_code_ptr + 46) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 93) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 117) = (int32_t)param2 + 3;
    *(uint32_t *)(gen_code_ptr + 127) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 151) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 161) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 185) = (int32_t)param2 + 5;
    *(uint32_t *)(gen_code_ptr + 195) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 223) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 231) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 265) = (int32_t)param1 + 0;
    gen_code_ptr += 269;
}
break;

case INDEX_op_maskmov_mmx: {
    long param1, param2;
    extern void op_maskmov_mmx();
extern char __stb_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_maskmov_mmx+0), 156);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 121) = (long)(&__stb_mmu) - (long)(gen_code_ptr + 121) + -4;
    gen_code_ptr += 156;
}
break;

case INDEX_op_movl_mm_T0_mmx: {
    long param1;
    extern void op_movl_mm_T0_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_mm_T0_mmx+0), 22);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 0;
    gen_code_ptr += 22;
}
break;

case INDEX_op_movl_T0_mm_mmx: {
    long param1;
    extern void op_movl_T0_mm_mmx();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_mm_mmx+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_pshufw_mmx: {
    long param1, param2, param3;
    extern void op_pshufw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pshufw_mmx+0), 88);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 84) = (int32_t)param1 + 6;
    gen_code_ptr += 88;
}
break;

case INDEX_op_pmovmskb_mmx: {
    long param1;
    extern void op_pmovmskb_mmx();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_pmovmskb_mmx+0), 152);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 7;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 57) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 74) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 91) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 108) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 125) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 144) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 144) + -4;
    gen_code_ptr += 152;
}
break;

case INDEX_op_pinsrw_mmx: {
    long param1, param2;
    extern void op_pinsrw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_pinsrw_mmx+0), 22);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 0;
    gen_code_ptr += 22;
}
break;

case INDEX_op_pextrw_mmx: {
    long param1, param2;
    extern void op_pextrw_mmx();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_pextrw_mmx+0), 40);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_packsswb_mmx: {
    long param1, param2;
    extern void op_packsswb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_packsswb_mmx+0), 238);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 70) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 148) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 162) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 176) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 190) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 203) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 215) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 225) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 233) = (int32_t)param1 + 7;
    gen_code_ptr += 238;
}
break;

case INDEX_op_packuswb_mmx: {
    long param1, param2;
    extern void op_packuswb_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_packuswb_mmx+0), 259);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 65) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 73) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 169) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 183) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 197) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 211) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 224) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 236) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 246) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 254) = (int32_t)param1 + 7;
    gen_code_ptr += 259;
}
break;

case INDEX_op_packssdw_mmx: {
    long param1, param2;
    extern void op_packssdw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_packssdw_mmx+0), 134);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 98) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 111) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 122) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 130) = (int32_t)param1 + 6;
    gen_code_ptr += 134;
}
break;

case INDEX_op_punpcklbw_mmx: {
    long param1, param2;
    extern void op_punpcklbw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpcklbw_mmx+0), 92);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 3;
    gen_code_ptr += 92;
}
break;

case INDEX_op_punpcklwd_mmx: {
    long param1, param2;
    extern void op_punpcklwd_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpcklwd_mmx+0), 43);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    gen_code_ptr += 43;
}
break;

case INDEX_op_punpckldq_mmx: {
    long param1, param2;
    extern void op_punpckldq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckldq_mmx+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 4;
    gen_code_ptr += 14;
}
break;

case INDEX_op_punpckhbw_mmx: {
    long param1, param2;
    extern void op_punpckhbw_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhbw_mmx+0), 122);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 7;
    *(uint32_t *)(gen_code_ptr + 37) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 45) = (int32_t)param2 + 5;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)param2 + 7;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 75) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 89) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 96) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 103) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 110) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 117) = (int32_t)param1 + 7;
    gen_code_ptr += 122;
}
break;

case INDEX_op_punpckhwd_mmx: {
    long param1, param2;
    extern void op_punpckhwd_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhwd_mmx+0), 64);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 6;
    gen_code_ptr += 64;
}
break;

case INDEX_op_punpckhdq_mmx: {
    long param1, param2;
    extern void op_punpckhdq_mmx();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhdq_mmx+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 4;
    gen_code_ptr += 28;
}
break;

case INDEX_op_psrlw_xmm: {
    long param1, param2;
    extern void op_psrlw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrlw_xmm+0), 134);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    gen_code_ptr += 134;
}
break;

case INDEX_op_psraw_xmm: {
    long param1, param2;
    extern void op_psraw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psraw_xmm+0), 119);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 45) = (int32_t)param1 + 0;
    gen_code_ptr += 119;
}
break;

case INDEX_op_psllw_xmm: {
    long param1, param2;
    extern void op_psllw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psllw_xmm+0), 134);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    gen_code_ptr += 134;
}
break;

case INDEX_op_psrld_xmm: {
    long param1, param2;
    extern void op_psrld_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrld_xmm+0), 57);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    gen_code_ptr += 57;
}
break;

case INDEX_op_psrad_xmm: {
    long param1, param2;
    extern void op_psrad_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrad_xmm+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param2 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_pslld_xmm: {
    long param1, param2;
    extern void op_pslld_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pslld_xmm+0), 57);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    gen_code_ptr += 57;
}
break;

case INDEX_op_psrlq_xmm: {
    long param1, param2;
    extern void op_psrlq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrlq_xmm+0), 53);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    gen_code_ptr += 53;
}
break;

case INDEX_op_psllq_xmm: {
    long param1, param2;
    extern void op_psllq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psllq_xmm+0), 53);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    gen_code_ptr += 53;
}
break;

case INDEX_op_psrldq_xmm: {
    long param1, param2;
    extern void op_psrldq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psrldq_xmm+0), 70);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    gen_code_ptr += 70;
}
break;

case INDEX_op_pslldq_xmm: {
    long param1, param2;
    extern void op_pslldq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pslldq_xmm+0), 77);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    gen_code_ptr += 77;
}
break;

case INDEX_op_paddb_xmm: {
    long param1, param2;
    extern void op_paddb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddb_xmm+0), 129);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 129;
}
break;

case INDEX_op_paddw_xmm: {
    long param1, param2;
    extern void op_paddw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddw_xmm+0), 81);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 81;
}
break;

case INDEX_op_paddl_xmm: {
    long param1, param2;
    extern void op_paddl_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddl_xmm+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_paddq_xmm: {
    long param1, param2;
    extern void op_paddq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddq_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_psubb_xmm: {
    long param1, param2;
    extern void op_psubb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubb_xmm+0), 129);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 129;
}
break;

case INDEX_op_psubw_xmm: {
    long param1, param2;
    extern void op_psubw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubw_xmm+0), 81);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    gen_code_ptr += 81;
}
break;

case INDEX_op_psubl_xmm: {
    long param1, param2;
    extern void op_psubl_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubl_xmm+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_psubq_xmm: {
    long param1, param2;
    extern void op_psubq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubq_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_paddusb_xmm: {
    long param1, param2;
    extern void op_paddusb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddusb_xmm+0), 401);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 57) = (int32_t)param1 + 0;
    gen_code_ptr += 401;
}
break;

case INDEX_op_paddsb_xmm: {
    long param1, param2;
    extern void op_paddsb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddsb_xmm+0), 471);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param1 + 0;
    gen_code_ptr += 471;
}
break;

case INDEX_op_psubusb_xmm: {
    long param1, param2;
    extern void op_psubusb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubusb_xmm+0), 304);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 0;
    gen_code_ptr += 304;
}
break;

case INDEX_op_psubsb_xmm: {
    long param1, param2;
    extern void op_psubsb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubsb_xmm+0), 468);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param1 + 0;
    gen_code_ptr += 468;
}
break;

case INDEX_op_paddusw_xmm: {
    long param1, param2;
    extern void op_paddusw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddusw_xmm+0), 223);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 66) = (int32_t)param1 + 2;
    gen_code_ptr += 223;
}
break;

case INDEX_op_paddsw_xmm: {
    long param1, param2;
    extern void op_paddsw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_paddsw_xmm+0), 284);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 73) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 81) = (int32_t)param1 + 2;
    gen_code_ptr += 284;
}
break;

case INDEX_op_psubusw_xmm: {
    long param1, param2;
    extern void op_psubusw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubusw_xmm+0), 174);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 0;
    gen_code_ptr += 174;
}
break;

case INDEX_op_psubsw_xmm: {
    long param1, param2;
    extern void op_psubsw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psubsw_xmm+0), 282);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 74) = (int32_t)param1 + 0;
    gen_code_ptr += 282;
}
break;

case INDEX_op_pminub_xmm: {
    long param1, param2;
    extern void op_pminub_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pminub_xmm+0), 301);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 301;
}
break;

case INDEX_op_pmaxub_xmm: {
    long param1, param2;
    extern void op_pmaxub_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaxub_xmm+0), 301);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 301;
}
break;

case INDEX_op_pminsw_xmm: {
    long param1, param2;
    extern void op_pminsw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pminsw_xmm+0), 170);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 0;
    gen_code_ptr += 170;
}
break;

case INDEX_op_pmaxsw_xmm: {
    long param1, param2;
    extern void op_pmaxsw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaxsw_xmm+0), 170);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 0;
    gen_code_ptr += 170;
}
break;

case INDEX_op_pand_xmm: {
    long param1, param2;
    extern void op_pand_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pand_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_pandn_xmm: {
    long param1, param2;
    extern void op_pandn_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pandn_xmm+0), 48);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 37) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param1 + 8;
    gen_code_ptr += 48;
}
break;

case INDEX_op_por_xmm: {
    long param1, param2;
    extern void op_por_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_por_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_pxor_xmm: {
    long param1, param2;
    extern void op_pxor_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pxor_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param2 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_pcmpgtb_xmm: {
    long param1, param2;
    extern void op_pcmpgtb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtb_xmm+0), 289);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 289;
}
break;

case INDEX_op_pcmpgtw_xmm: {
    long param1, param2;
    extern void op_pcmpgtw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtw_xmm+0), 196);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 0;
    gen_code_ptr += 196;
}
break;

case INDEX_op_pcmpgtl_xmm: {
    long param1, param2;
    extern void op_pcmpgtl_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpgtl_xmm+0), 103);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)param1 + 0;
    gen_code_ptr += 103;
}
break;

case INDEX_op_pcmpeqb_xmm: {
    long param1, param2;
    extern void op_pcmpeqb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeqb_xmm+0), 289);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 289;
}
break;

case INDEX_op_pcmpeqw_xmm: {
    long param1, param2;
    extern void op_pcmpeqw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeqw_xmm+0), 196);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 0;
    gen_code_ptr += 196;
}
break;

case INDEX_op_pcmpeql_xmm: {
    long param1, param2;
    extern void op_pcmpeql_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pcmpeql_xmm+0), 103);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)param1 + 0;
    gen_code_ptr += 103;
}
break;

case INDEX_op_pmullw_xmm: {
    long param1, param2;
    extern void op_pmullw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmullw_xmm+0), 134);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param1 + 0;
    gen_code_ptr += 134;
}
break;

case INDEX_op_pmulhuw_xmm: {
    long param1, param2;
    extern void op_pmulhuw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmulhuw_xmm+0), 174);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 174;
}
break;

case INDEX_op_pmulhw_xmm: {
    long param1, param2;
    extern void op_pmulhw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmulhw_xmm+0), 174);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    gen_code_ptr += 174;
}
break;

case INDEX_op_pavgb_xmm: {
    long param1, param2;
    extern void op_pavgb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pavgb_xmm+0), 302);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 302;
}
break;

case INDEX_op_pavgw_xmm: {
    long param1, param2;
    extern void op_pavgw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pavgw_xmm+0), 178);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (int32_t)param1 + 2;
    gen_code_ptr += 178;
}
break;

case INDEX_op_pmuludq_xmm: {
    long param1, param2;
    extern void op_pmuludq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmuludq_xmm+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_pmaddwd_xmm: {
    long param1, param2;
    extern void op_pmaddwd_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pmaddwd_xmm+0), 60);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param2 + 0;
    gen_code_ptr += 60;
}
break;

case INDEX_op_psadbw_xmm: {
    long param1, param2;
    extern void op_psadbw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_psadbw_xmm+0), 464);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 89) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 99) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 123) = (int32_t)param2 + 3;
    *(uint32_t *)(gen_code_ptr + 133) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 157) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 167) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 191) = (int32_t)param2 + 5;
    *(uint32_t *)(gen_code_ptr + 201) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 229) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 237) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 256) = (int32_t)param2 + 7;
    *(uint32_t *)(gen_code_ptr + 267) = (int32_t)param1 + 7;
    *(uint32_t *)(gen_code_ptr + 288) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 296) = (int32_t)param1 + 8;
    gen_code_ptr += 464;
}
break;

case INDEX_op_maskmov_xmm: {
    long param1, param2;
    extern void op_maskmov_xmm();
extern char __stb_mmu;
    memcpy(gen_code_ptr, (void *)((char *)&op_maskmov_xmm+0), 155);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 120) = (long)(&__stb_mmu) - (long)(gen_code_ptr + 120) + -4;
    gen_code_ptr += 155;
}
break;

case INDEX_op_movl_mm_T0_xmm: {
    long param1;
    extern void op_movl_mm_T0_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_mm_T0_xmm+0), 33);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    gen_code_ptr += 33;
}
break;

case INDEX_op_movl_T0_mm_xmm: {
    long param1;
    extern void op_movl_T0_mm_xmm();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movl_T0_mm_xmm+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 21) + -4;
    gen_code_ptr += 29;
}
break;

case INDEX_op_shufps: {
    long param1, param2, param3;
    extern void op_shufps();
    memcpy(gen_code_ptr, (void *)((char *)&op_shufps+0), 63);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 0;
    gen_code_ptr += 63;
}
break;

case INDEX_op_shufpd: {
    long param1, param2;
    extern void op_shufpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_shufpd+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 8;
    gen_code_ptr += 14;
}
break;

case INDEX_op_pshufd_xmm: {
    long param1, param2, param3;
    extern void op_pshufd_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pshufd_xmm+0), 80);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 12;
    gen_code_ptr += 80;
}
break;

case INDEX_op_pshuflw_xmm: {
    long param1, param2, param3;
    extern void op_pshuflw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pshuflw_xmm+0), 102);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 67) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 75) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 98) = (int32_t)param1 + 4;
    gen_code_ptr += 102;
}
break;

case INDEX_op_pshufhw_xmm: {
    long param1, param2, param3;
    extern void op_pshufhw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pshufhw_xmm+0), 109);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    param3 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param3 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 72) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 81) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 89) = (int32_t)param1 + 10;
    *(uint32_t *)(gen_code_ptr + 97) = (int32_t)param1 + 14;
    *(uint32_t *)(gen_code_ptr + 105) = (int32_t)param1 + 12;
    gen_code_ptr += 109;
}
break;

case INDEX_op_addps: {
    long param1, param2;
    extern void op_addps();
    memcpy(gen_code_ptr, (void *)((char *)&op_addps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_addss: {
    long param1, param2;
    extern void op_addss();
    memcpy(gen_code_ptr, (void *)((char *)&op_addss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_addpd: {
    long param1, param2;
    extern void op_addpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_addpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_addsd: {
    long param1, param2;
    extern void op_addsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_addsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_subps: {
    long param1, param2;
    extern void op_subps();
    memcpy(gen_code_ptr, (void *)((char *)&op_subps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_subss: {
    long param1, param2;
    extern void op_subss();
    memcpy(gen_code_ptr, (void *)((char *)&op_subss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_subpd: {
    long param1, param2;
    extern void op_subpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_subpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_subsd: {
    long param1, param2;
    extern void op_subsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_subsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_mulps: {
    long param1, param2;
    extern void op_mulps();
    memcpy(gen_code_ptr, (void *)((char *)&op_mulps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_mulss: {
    long param1, param2;
    extern void op_mulss();
    memcpy(gen_code_ptr, (void *)((char *)&op_mulss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_mulpd: {
    long param1, param2;
    extern void op_mulpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_mulpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_mulsd: {
    long param1, param2;
    extern void op_mulsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_mulsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_divps: {
    long param1, param2;
    extern void op_divps();
    memcpy(gen_code_ptr, (void *)((char *)&op_divps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_divss: {
    long param1, param2;
    extern void op_divss();
    memcpy(gen_code_ptr, (void *)((char *)&op_divss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_divpd: {
    long param1, param2;
    extern void op_divpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_divpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_divsd: {
    long param1, param2;
    extern void op_divsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_divsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_minps: {
    long param1, param2;
    extern void op_minps();
    memcpy(gen_code_ptr, (void *)((char *)&op_minps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_minss: {
    long param1, param2;
    extern void op_minss();
    memcpy(gen_code_ptr, (void *)((char *)&op_minss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_minpd: {
    long param1, param2;
    extern void op_minpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_minpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_minsd: {
    long param1, param2;
    extern void op_minsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_minsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_maxps: {
    long param1, param2;
    extern void op_maxps();
    memcpy(gen_code_ptr, (void *)((char *)&op_maxps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_maxss: {
    long param1, param2;
    extern void op_maxss();
    memcpy(gen_code_ptr, (void *)((char *)&op_maxss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_maxpd: {
    long param1, param2;
    extern void op_maxpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_maxpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_maxsd: {
    long param1, param2;
    extern void op_maxsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_maxsd+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_sqrtps: {
    long param1, param2;
    extern void op_sqrtps();
extern char float32_sqrt;
extern char float32_sqrt;
extern char float32_sqrt;
extern char float32_sqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_sqrtps+0), 153);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float32_sqrt) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&float32_sqrt) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&float32_sqrt) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 110) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 118) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 123) = (long)(&float32_sqrt) - (long)(gen_code_ptr + 123) + -4;
    *(uint32_t *)(gen_code_ptr + 136) = (int32_t)param1 + 12;
    gen_code_ptr += 153;
}
break;

case INDEX_op_sqrtss: {
    long param1, param2;
    extern void op_sqrtss();
extern char float32_sqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_sqrtss+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float32_sqrt) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_sqrtpd: {
    long param1, param2;
    extern void op_sqrtpd();
extern char float64_sqrt;
extern char float64_sqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_sqrtpd+0), 97);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_sqrt) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&float64_sqrt) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)param1 + 8;
    gen_code_ptr += 97;
}
break;

case INDEX_op_sqrtsd: {
    long param1, param2;
    extern void op_sqrtsd();
extern char float64_sqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_sqrtsd+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float64_sqrt) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_cvtps2pd: {
    long param1, param2;
    extern void op_cvtps2pd();
extern char float32_to_float64;
extern char float32_to_float64;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtps2pd+0), 101);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 49) = (long)(&float32_to_float64) - (long)(gen_code_ptr + 49) + -4;
    *(uint32_t *)(gen_code_ptr + 64) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 75) = (long)(&float32_to_float64) - (long)(gen_code_ptr + 75) + -4;
    *(uint32_t *)(gen_code_ptr + 88) = (int32_t)param1 + 8;
    gen_code_ptr += 101;
}
break;

case INDEX_op_cvtpd2ps: {
    long param1, param2;
    extern void op_cvtpd2ps();
extern char float64_to_float32;
extern char float64_to_float32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtpd2ps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_to_float32) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&float64_to_float32) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 74) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 4;
    gen_code_ptr += 108;
}
break;

case INDEX_op_cvtss2sd: {
    long param1, param2;
    extern void op_cvtss2sd();
extern char float32_to_float64;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtss2sd+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float32_to_float64) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_cvtsd2ss: {
    long param1, param2;
    extern void op_cvtsd2ss();
extern char float64_to_float32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtsd2ss+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float64_to_float32) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_cvtdq2ps: {
    long param1, param2;
    extern void op_cvtdq2ps();
extern char int32_to_float32;
extern char int32_to_float32;
extern char int32_to_float32;
extern char int32_to_float32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtdq2ps+0), 145);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 84) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 89) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 89) + -4;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 110) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 115) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 115) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (int32_t)param1 + 12;
    gen_code_ptr += 145;
}
break;

case INDEX_op_cvtdq2pd: {
    long param1, param2;
    extern void op_cvtdq2pd();
extern char int32_to_float64;
extern char int32_to_float64;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtdq2pd+0), 97);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 44) = (long)(&int32_to_float64) - (long)(gen_code_ptr + 44) + -4;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 67) = (long)(&int32_to_float64) - (long)(gen_code_ptr + 67) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)param1 + 8;
    gen_code_ptr += 97;
}
break;

case INDEX_op_cvtpi2ps: {
    long param1, param2;
    extern void op_cvtpi2ps();
extern char int32_to_float32;
extern char int32_to_float32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtpi2ps+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvtpi2pd: {
    long param1, param2;
    extern void op_cvtpi2pd();
extern char int32_to_float64;
extern char int32_to_float64;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtpi2pd+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 37) = (long)(&int32_to_float64) - (long)(gen_code_ptr + 37) + -4;
    *(uint32_t *)(gen_code_ptr + 43) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 63) = (long)(&int32_to_float64) - (long)(gen_code_ptr + 63) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 8;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvtsi2ss: {
    long param1;
    extern void op_cvtsi2ss();
extern char int32_to_float32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtsi2ss+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (long)(&int32_to_float32) - (long)(gen_code_ptr + 16) + -4;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 0;
    gen_code_ptr += 29;
}
break;

case INDEX_op_cvtsi2sd: {
    long param1;
    extern void op_cvtsi2sd();
extern char int32_to_float64;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtsi2sd+0), 29);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (long)(&int32_to_float64) - (long)(gen_code_ptr + 16) + -4;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 0;
    gen_code_ptr += 29;
}
break;

case INDEX_op_cvtps2dq: {
    long param1, param2;
    extern void op_cvtps2dq();
extern char float32_to_int32;
extern char float32_to_int32;
extern char float32_to_int32;
extern char float32_to_int32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtps2dq+0), 145);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 112) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 117) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 117) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (int32_t)param1 + 12;
    gen_code_ptr += 145;
}
break;

case INDEX_op_cvtpd2dq: {
    long param1, param2;
    extern void op_cvtpd2dq();
extern char float64_to_int32;
extern char float64_to_int32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtpd2dq+0), 104);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_to_int32) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float64_to_int32) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 4;
    gen_code_ptr += 104;
}
break;

case INDEX_op_cvtps2pi: {
    long param1, param2;
    extern void op_cvtps2pi();
extern char float32_to_int32;
extern char float32_to_int32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtps2pi+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvtpd2pi: {
    long param1, param2;
    extern void op_cvtpd2pi();
extern char float64_to_int32;
extern char float64_to_int32;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtpd2pi+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_to_int32) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float64_to_int32) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvtss2si: {
    long param1;
    extern void op_cvtss2si();
extern char float32_to_int32;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtss2si+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float32_to_int32) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_cvtsd2si: {
    long param1;
    extern void op_cvtsd2si();
extern char float64_to_int32;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvtsd2si+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float64_to_int32) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_cvttps2dq: {
    long param1, param2;
    extern void op_cvttps2dq();
extern char float32_to_int32_round_to_zero;
extern char float32_to_int32_round_to_zero;
extern char float32_to_int32_round_to_zero;
extern char float32_to_int32_round_to_zero;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttps2dq+0), 145);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 80) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 91) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 91) + -4;
    *(uint32_t *)(gen_code_ptr + 106) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 112) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 117) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 117) + -4;
    *(uint32_t *)(gen_code_ptr + 128) = (int32_t)param1 + 12;
    gen_code_ptr += 145;
}
break;

case INDEX_op_cvttpd2dq: {
    long param1, param2;
    extern void op_cvttpd2dq();
extern char float64_to_int32_round_to_zero;
extern char float64_to_int32_round_to_zero;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttpd2dq+0), 104);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_to_int32_round_to_zero) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float64_to_int32_round_to_zero) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 72) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 4;
    gen_code_ptr += 104;
}
break;

case INDEX_op_cvttps2pi: {
    long param1, param2;
    extern void op_cvttps2pi();
extern char float32_to_int32_round_to_zero;
extern char float32_to_int32_round_to_zero;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttps2pi+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvttpd2pi: {
    long param1, param2;
    extern void op_cvttpd2pi();
extern char float64_to_int32_round_to_zero;
extern char float64_to_int32_round_to_zero;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttpd2pi+0), 93);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 39) = (long)(&float64_to_int32_round_to_zero) - (long)(gen_code_ptr + 39) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 65) = (long)(&float64_to_int32_round_to_zero) - (long)(gen_code_ptr + 65) + -4;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param1 + 4;
    gen_code_ptr += 93;
}
break;

case INDEX_op_cvttss2si: {
    long param1;
    extern void op_cvttss2si();
extern char float32_to_int32_round_to_zero;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttss2si+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float32_to_int32_round_to_zero) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_cvttsd2si: {
    long param1;
    extern void op_cvttsd2si();
extern char float64_to_int32_round_to_zero;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_cvttsd2si+0), 39);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (long)(&float64_to_int32_round_to_zero) - (long)(gen_code_ptr + 21) + -4;
    *(uint32_t *)(gen_code_ptr + 34) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 34) + -4;
    gen_code_ptr += 39;
}
break;

case INDEX_op_rsqrtps: {
    long param1, param2;
    extern void op_rsqrtps();
extern char approx_rsqrt;
extern char approx_rsqrt;
extern char approx_rsqrt;
extern char approx_rsqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_rsqrtps+0), 125);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&approx_rsqrt) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&approx_rsqrt) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&approx_rsqrt) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&approx_rsqrt) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (int32_t)param1 + 12;
    gen_code_ptr += 125;
}
break;

case INDEX_op_rsqrtss: {
    long param1, param2;
    extern void op_rsqrtss();
extern char approx_rsqrt;
    memcpy(gen_code_ptr, (void *)((char *)&op_rsqrtss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (long)(&approx_rsqrt) - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_rcpps: {
    long param1, param2;
    extern void op_rcpps();
extern char approx_rcp;
extern char approx_rcp;
extern char approx_rcp;
extern char approx_rcp;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcpps+0), 125);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&approx_rcp) - (long)(gen_code_ptr + 32) + -4;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 53) = (long)(&approx_rcp) - (long)(gen_code_ptr + 53) + -4;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 74) = (long)(&approx_rcp) - (long)(gen_code_ptr + 74) + -4;
    *(uint32_t *)(gen_code_ptr + 82) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 90) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (long)(&approx_rcp) - (long)(gen_code_ptr + 95) + -4;
    *(uint32_t *)(gen_code_ptr + 108) = (int32_t)param1 + 12;
    gen_code_ptr += 125;
}
break;

case INDEX_op_rcpss: {
    long param1, param2;
    extern void op_rcpss();
extern char approx_rcp;
    memcpy(gen_code_ptr, (void *)((char *)&op_rcpss+0), 27);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 6) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (long)(&approx_rcp) - (long)(gen_code_ptr + 14) + -4;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param1 + 0;
    gen_code_ptr += 27;
}
break;

case INDEX_op_haddps: {
    long param1, param2;
    extern void op_haddps();
    memcpy(gen_code_ptr, (void *)((char *)&op_haddps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_haddpd: {
    long param1, param2;
    extern void op_haddpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_haddpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_hsubps: {
    long param1, param2;
    extern void op_hsubps();
    memcpy(gen_code_ptr, (void *)((char *)&op_hsubps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_hsubpd: {
    long param1, param2;
    extern void op_hsubpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_hsubpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_addsubps: {
    long param1, param2;
    extern void op_addsubps();
    memcpy(gen_code_ptr, (void *)((char *)&op_addsubps+0), 108);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 86) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 95) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 104) = (int32_t)param1 + 12;
    gen_code_ptr += 108;
}
break;

case INDEX_op_addsubpd: {
    long param1, param2;
    extern void op_addsubpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_addsubpd+0), 54);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 41) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    gen_code_ptr += 54;
}
break;

case INDEX_op_cmpeqps: {
    long param1, param2;
    extern void op_cmpeqps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpeqps+0), 120);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param1 + 0;
    gen_code_ptr += 120;
}
break;

case INDEX_op_cmpeqss: {
    long param1, param2;
    extern void op_cmpeqss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpeqss+0), 37);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 33) = (int32_t)param1 + 0;
    gen_code_ptr += 37;
}
break;

case INDEX_op_cmpeqpd: {
    long param1, param2;
    extern void op_cmpeqpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpeqpd+0), 82);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 0;
    gen_code_ptr += 82;
}
break;

case INDEX_op_cmpeqsd: {
    long param1, param2;
    extern void op_cmpeqsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpeqsd+0), 41);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 37) = (int32_t)param1 + 0;
    gen_code_ptr += 41;
}
break;

case INDEX_op_cmpltps: {
    long param1, param2;
    extern void op_cmpltps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpltps+0), 112);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 0;
    gen_code_ptr += 112;
}
break;

case INDEX_op_cmpltss: {
    long param1, param2;
    extern void op_cmpltss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpltss+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    gen_code_ptr += 31;
}
break;

case INDEX_op_cmpltpd: {
    long param1, param2;
    extern void op_cmpltpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpltpd+0), 81);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 59) = (int32_t)param1 + 0;
    gen_code_ptr += 81;
}
break;

case INDEX_op_cmpltsd: {
    long param1, param2;
    extern void op_cmpltsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpltsd+0), 38);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 34) = (int32_t)param1 + 0;
    gen_code_ptr += 38;
}
break;

case INDEX_op_cmpleps: {
    long param1, param2;
    extern void op_cmpleps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpleps+0), 98);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 46) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 0;
    gen_code_ptr += 98;
}
break;

case INDEX_op_cmpless: {
    long param1, param2;
    extern void op_cmpless();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpless+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 0;
    gen_code_ptr += 28;
}
break;

case INDEX_op_cmplepd: {
    long param1, param2;
    extern void op_cmplepd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmplepd+0), 66);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 0;
    gen_code_ptr += 66;
}
break;

case INDEX_op_cmplesd: {
    long param1, param2;
    extern void op_cmplesd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmplesd+0), 31);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param1 + 0;
    gen_code_ptr += 31;
}
break;

case INDEX_op_cmpunordps: {
    long param1, param2;
    extern void op_cmpunordps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpunordps+0), 116);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    gen_code_ptr += 116;
}
break;

case INDEX_op_cmpunordss: {
    long param1, param2;
    extern void op_cmpunordss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpunordss+0), 32);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param1 + 0;
    gen_code_ptr += 32;
}
break;

case INDEX_op_cmpunordpd: {
    long param1, param2;
    extern void op_cmpunordpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpunordpd+0), 73);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 0;
    gen_code_ptr += 73;
}
break;

case INDEX_op_cmpunordsd: {
    long param1, param2;
    extern void op_cmpunordsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpunordsd+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_cmpneqps: {
    long param1, param2;
    extern void op_cmpneqps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpneqps+0), 132);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 0;
    gen_code_ptr += 132;
}
break;

case INDEX_op_cmpneqss: {
    long param1, param2;
    extern void op_cmpneqss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpneqss+0), 40);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    gen_code_ptr += 40;
}
break;

case INDEX_op_cmpneqpd: {
    long param1, param2;
    extern void op_cmpneqpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpneqpd+0), 88);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 54) = (int32_t)param1 + 0;
    gen_code_ptr += 88;
}
break;

case INDEX_op_cmpneqsd: {
    long param1, param2;
    extern void op_cmpneqsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpneqsd+0), 44);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 40) = (int32_t)param1 + 0;
    gen_code_ptr += 44;
}
break;

case INDEX_op_cmpnltps: {
    long param1, param2;
    extern void op_cmpnltps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnltps+0), 124);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 62) = (int32_t)param1 + 0;
    gen_code_ptr += 124;
}
break;

case INDEX_op_cmpnltss: {
    long param1, param2;
    extern void op_cmpnltss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnltss+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_cmpnltpd: {
    long param1, param2;
    extern void op_cmpnltpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnltpd+0), 77);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 57) = (int32_t)param1 + 0;
    gen_code_ptr += 77;
}
break;

case INDEX_op_cmpnltsd: {
    long param1, param2;
    extern void op_cmpnltsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnltsd+0), 36);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param1 + 0;
    gen_code_ptr += 36;
}
break;

case INDEX_op_cmpnleps: {
    long param1, param2;
    extern void op_cmpnleps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnleps+0), 90);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 20) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 46) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 0;
    gen_code_ptr += 90;
}
break;

case INDEX_op_cmpnless: {
    long param1, param2;
    extern void op_cmpnless();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnless+0), 26);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 22) = (int32_t)param1 + 0;
    gen_code_ptr += 26;
}
break;

case INDEX_op_cmpnlepd: {
    long param1, param2;
    extern void op_cmpnlepd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnlepd+0), 60);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 12) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)param1 + 0;
    gen_code_ptr += 60;
}
break;

case INDEX_op_cmpnlesd: {
    long param1, param2;
    extern void op_cmpnlesd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpnlesd+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 0;
    gen_code_ptr += 28;
}
break;

case INDEX_op_cmpordps: {
    long param1, param2;
    extern void op_cmpordps();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpordps+0), 116);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 60) = (int32_t)param1 + 0;
    gen_code_ptr += 116;
}
break;

case INDEX_op_cmpordss: {
    long param1, param2;
    extern void op_cmpordss();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpordss+0), 32);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 15) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 28) = (int32_t)param1 + 0;
    gen_code_ptr += 32;
}
break;

case INDEX_op_cmpordpd: {
    long param1, param2;
    extern void op_cmpordpd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpordpd+0), 73);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 48) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param1 + 0;
    gen_code_ptr += 73;
}
break;

case INDEX_op_cmpordsd: {
    long param1, param2;
    extern void op_cmpordsd();
    memcpy(gen_code_ptr, (void *)((char *)&op_cmpordsd+0), 34);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param1 + 0;
    gen_code_ptr += 34;
}
break;

case INDEX_op_ucomiss: {
    long param1, param2;
    extern void op_ucomiss();
extern char float32_compare_quiet;
extern char comis_eflags;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_ucomiss+0), 68);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&float32_compare_quiet) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)(long)(&comis_eflags) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 68;
}
break;

case INDEX_op_comiss: {
    long param1, param2;
    extern void op_comiss();
extern char float32_compare;
extern char comis_eflags;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_comiss+0), 68);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&float32_compare) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)(long)(&comis_eflags) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 68;
}
break;

case INDEX_op_ucomisd: {
    long param1, param2;
    extern void op_ucomisd();
extern char float64_compare_quiet;
extern char comis_eflags;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_ucomisd+0), 68);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&float64_compare_quiet) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)(long)(&comis_eflags) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 68;
}
break;

case INDEX_op_comisd: {
    long param1, param2;
    extern void op_comisd();
extern char float64_compare;
extern char comis_eflags;
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_comisd+0), 68);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 25) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (long)(&float64_compare) - (long)(gen_code_ptr + 30) + -4;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)(long)(&comis_eflags) + 0;
    *(uint32_t *)(gen_code_ptr + 56) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 56) + -4;
    gen_code_ptr += 68;
}
break;

case INDEX_op_movmskps: {
    long param1;
    extern void op_movmskps();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movmskps+0), 76);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 49) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 68) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 68) + -4;
    gen_code_ptr += 76;
}
break;

case INDEX_op_movmskpd: {
    long param1;
    extern void op_movmskpd();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_movmskpd+0), 46);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 7) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 14) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 38) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 38) + -4;
    gen_code_ptr += 46;
}
break;

case INDEX_op_pmovmskb_xmm: {
    long param1;
    extern void op_pmovmskb_xmm();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_pmovmskb_xmm+0), 298);
    param1 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 8) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 15;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 1;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 67) = (int32_t)param1 + 3;
    *(uint32_t *)(gen_code_ptr + 83) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 99) = (int32_t)param1 + 5;
    *(uint32_t *)(gen_code_ptr + 115) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 130) = (int32_t)param1 + 7;
    *(uint32_t *)(gen_code_ptr + 146) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 164) = (int32_t)param1 + 9;
    *(uint32_t *)(gen_code_ptr + 183) = (int32_t)param1 + 10;
    *(uint32_t *)(gen_code_ptr + 202) = (int32_t)param1 + 11;
    *(uint32_t *)(gen_code_ptr + 221) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 249) = (int32_t)param1 + 13;
    *(uint32_t *)(gen_code_ptr + 268) = (int32_t)param1 + 14;
    *(uint32_t *)(gen_code_ptr + 290) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 290) + -4;
    gen_code_ptr += 298;
}
break;

case INDEX_op_pinsrw_xmm: {
    long param1, param2;
    extern void op_pinsrw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_pinsrw_xmm+0), 22);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param1 + 0;
    gen_code_ptr += 22;
}
break;

case INDEX_op_pextrw_xmm: {
    long param1, param2;
    extern void op_pextrw_xmm();
extern char taintcheck_reg_clean;
    memcpy(gen_code_ptr, (void *)((char *)&op_pextrw_xmm+0), 40);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 2) = param2 - (long)(gen_code_ptr + 2) + -4;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 32) = (long)(&taintcheck_reg_clean) - (long)(gen_code_ptr + 32) + -4;
    gen_code_ptr += 40;
}
break;

case INDEX_op_packsswb_xmm: {
    long param1, param2;
    extern void op_packsswb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_packsswb_xmm+0), 452);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param2 + 14;
    *(uint32_t *)(gen_code_ptr + 165) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 183) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 201) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 219) = (int32_t)param2 + 10;
    *(uint32_t *)(gen_code_ptr + 237) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 279) = (int32_t)param1 + 0;
    gen_code_ptr += 452;
}
break;

case INDEX_op_packuswb_xmm: {
    long param1, param2;
    extern void op_packuswb_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_packuswb_xmm+0), 513);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 18) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 26) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 36) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param2 + 14;
    *(uint32_t *)(gen_code_ptr + 195) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 216) = (int32_t)param2 + 6;
    *(uint32_t *)(gen_code_ptr + 237) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 258) = (int32_t)param2 + 10;
    *(uint32_t *)(gen_code_ptr + 279) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 324) = (int32_t)param1 + 0;
    gen_code_ptr += 513;
}
break;

case INDEX_op_packssdw_xmm: {
    long param1, param2;
    extern void op_packssdw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_packssdw_xmm+0), 262);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 4) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 23) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 51) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 165) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 180) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 195) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 210) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 224) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 237) = (int32_t)param1 + 10;
    *(uint32_t *)(gen_code_ptr + 248) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 257) = (int32_t)param1 + 14;
    gen_code_ptr += 262;
}
break;

case INDEX_op_punpcklbw_xmm: {
    long param1, param2;
    extern void op_punpcklbw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpcklbw_xmm+0), 233);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 30) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 47) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 55) = (int32_t)param2 + 1;
    *(uint32_t *)(gen_code_ptr + 63) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 71) = (int32_t)param2 + 3;
    *(uint32_t *)(gen_code_ptr + 79) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 87) = (int32_t)param2 + 5;
    gen_code_ptr += 233;
}
break;

case INDEX_op_punpcklwd_xmm: {
    long param1, param2;
    extern void op_punpcklwd_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpcklwd_xmm+0), 97);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 11) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 19) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 27) = (int32_t)param2 + 2;
    *(uint32_t *)(gen_code_ptr + 35) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 42) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 50) = (int32_t)param2 + 4;
    *(uint32_t *)(gen_code_ptr + 58) = (int32_t)param1 + 6;
    gen_code_ptr += 97;
}
break;

case INDEX_op_punpckldq_xmm: {
    long param1, param2;
    extern void op_punpckldq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckldq_xmm+0), 37);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 4;
    gen_code_ptr += 37;
}
break;

case INDEX_op_punpcklqdq_xmm: {
    long param1, param2;
    extern void op_punpcklqdq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpcklqdq_xmm+0), 14);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param2 + 0;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 8;
    gen_code_ptr += 14;
}
break;

case INDEX_op_punpckhbw_xmm: {
    long param1, param2;
    extern void op_punpckhbw_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhbw_xmm+0), 255);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 9) = (int32_t)param2 + 10;
    *(uint32_t *)(gen_code_ptr + 16) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 44) = (int32_t)param2 + 13;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 68) = (int32_t)param2 + 9;
    *(uint32_t *)(gen_code_ptr + 76) = (int32_t)param2 + 11;
    *(uint32_t *)(gen_code_ptr + 111) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 119) = (int32_t)param2 + 15;
    *(uint32_t *)(gen_code_ptr + 141) = (int32_t)param2 + 14;
    *(uint32_t *)(gen_code_ptr + 156) = (int32_t)param1 + 0;
    gen_code_ptr += 255;
}
break;

case INDEX_op_punpckhwd_xmm: {
    long param1, param2;
    extern void op_punpckhwd_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhwd_xmm+0), 130);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 5) = (int32_t)param1 + 10;
    *(uint32_t *)(gen_code_ptr + 13) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 21) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 29) = (int32_t)param1 + 14;
    *(uint32_t *)(gen_code_ptr + 37) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 45) = (int32_t)param2 + 10;
    *(uint32_t *)(gen_code_ptr + 53) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 61) = (int32_t)param2 + 14;
    *(uint32_t *)(gen_code_ptr + 69) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 77) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 85) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 93) = (int32_t)param1 + 2;
    *(uint32_t *)(gen_code_ptr + 101) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 109) = (int32_t)param1 + 6;
    *(uint32_t *)(gen_code_ptr + 117) = (int32_t)param1 + 10;
    *(uint32_t *)(gen_code_ptr + 125) = (int32_t)param1 + 14;
    gen_code_ptr += 130;
}
break;

case INDEX_op_punpckhdq_xmm: {
    long param1, param2;
    extern void op_punpckhdq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhdq_xmm+0), 56);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 12;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param2 + 12;
    *(uint32_t *)(gen_code_ptr + 31) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 38) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 45) = (int32_t)param1 + 4;
    *(uint32_t *)(gen_code_ptr + 52) = (int32_t)param1 + 12;
    gen_code_ptr += 56;
}
break;

case INDEX_op_punpckhqdq_xmm: {
    long param1, param2;
    extern void op_punpckhqdq_xmm();
    memcpy(gen_code_ptr, (void *)((char *)&op_punpckhqdq_xmm+0), 28);
    param1 = *opparam_ptr++;
    param2 = *opparam_ptr++;
    *(uint32_t *)(gen_code_ptr + 3) = (int32_t)param1 + 8;
    *(uint32_t *)(gen_code_ptr + 10) = (int32_t)param2 + 8;
    *(uint32_t *)(gen_code_ptr + 17) = (int32_t)param1 + 0;
    *(uint32_t *)(gen_code_ptr + 24) = (int32_t)param1 + 8;
    gen_code_ptr += 28;
}
break;

case INDEX_op_vmrun: {
    extern void op_vmrun();
extern char helper_vmrun;
    memcpy(gen_code_ptr, (void *)((char *)&op_vmrun+0), 16);
    *(uint32_t *)(gen_code_ptr + 8) = (long)(&helper_vmrun) - (long)(gen_code_ptr + 8) + -4;
    gen_code_ptr += 16;
}
break;

case INDEX_op_vmmcall: {
    extern void op_vmmcall();
extern char helper_vmmcall;
    memcpy(gen_code_ptr, (void *)((char *)&op_vmmcall+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_vmmcall) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_vmload: {
    extern void op_vmload();
extern char helper_vmload;
    memcpy(gen_code_ptr, (void *)((char *)&op_vmload+0), 16);
    *(uint32_t *)(gen_code_ptr + 8) = (long)(&helper_vmload) - (long)(gen_code_ptr + 8) + -4;
    gen_code_ptr += 16;
}
break;

case INDEX_op_vmsave: {
    extern void op_vmsave();
extern char helper_vmsave;
    memcpy(gen_code_ptr, (void *)((char *)&op_vmsave+0), 16);
    *(uint32_t *)(gen_code_ptr + 8) = (long)(&helper_vmsave) - (long)(gen_code_ptr + 8) + -4;
    gen_code_ptr += 16;
}
break;

case INDEX_op_stgi: {
    extern void op_stgi();
extern char helper_stgi;
    memcpy(gen_code_ptr, (void *)((char *)&op_stgi+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_stgi) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_clgi: {
    extern void op_clgi();
extern char helper_clgi;
    memcpy(gen_code_ptr, (void *)((char *)&op_clgi+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_clgi) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_skinit: {
    extern void op_skinit();
extern char helper_skinit;
    memcpy(gen_code_ptr, (void *)((char *)&op_skinit+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_skinit) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

case INDEX_op_invlpga: {
    extern void op_invlpga();
extern char helper_invlpga;
    memcpy(gen_code_ptr, (void *)((char *)&op_invlpga+0), 13);
    *(uint32_t *)(gen_code_ptr + 5) = (long)(&helper_invlpga) - (long)(gen_code_ptr + 5) + -4;
    gen_code_ptr += 13;
}
break;

        case INDEX_op_nop:
            break;
        case INDEX_op_nop1:
            opparam_ptr++;
            break;
        case INDEX_op_nop2:
            opparam_ptr += 2;
            break;
        case INDEX_op_nop3:
            opparam_ptr += 3;
            break;
        default:
            goto the_end;
        }
    }
 the_end:
flush_icache_range((unsigned long)gen_code_buf, (unsigned long)gen_code_ptr);
return gen_code_ptr -  gen_code_buf;
}

