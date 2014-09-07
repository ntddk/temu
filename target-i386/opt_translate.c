static GenOpFunc *gen_op_opt_movl_A0_reg[CPU_NB_REGS] = {
    DEF_REGS(gen_op_opt_movl_A0_, )
};

static GenOpFunc *gen_op_opt_addl_A0_reg_sN[4][CPU_NB_REGS] = {
    [0] = {
        DEF_REGS(gen_op_opt_addl_A0_, )
    },
    [1] = {
        DEF_REGS(gen_op_opt_addl_A0_, _s1)
    },
    [2] = {
        DEF_REGS(gen_op_opt_addl_A0_, _s2)
    },
    [3] = {
        DEF_REGS(gen_op_opt_addl_A0_, _s3)
    },
};

#if 0 /* unused */
static GenOpFunc *gen_op_opt_ldu_T0_A0[3 * 4] = {
    gen_op_TD_ldub_raw_T0_A0,
    gen_op_TD_lduw_raw_T0_A0,
    NULL,
    NULL,

#ifndef CONFIG_USER_ONLY
    gen_op_TD_ldub_kernel_T0_A0,
    gen_op_TD_lduw_kernel_T0_A0,
    NULL,
    NULL,

    gen_op_TD_ldub_user_T0_A0,
    gen_op_TD_lduw_user_T0_A0,
    NULL,
    NULL,
#endif
};
#endif

static GenOpFunc *gen_op_opt_ld_T0_A0[3 * 4] = {
    gen_op_TD_ldub_raw_T0_A0,
    gen_op_TD_lduw_raw_T0_A0,
    gen_op_TD_ldl_raw_T0_A0,
    X86_64_ONLY(gen_op_ldq_raw_T0_A0),

#ifndef CONFIG_USER_ONLY
    gen_op_TD_ldub_kernel_T0_A0,
    gen_op_TD_lduw_kernel_T0_A0,
    gen_op_TD_ldl_kernel_T0_A0,
    X86_64_ONLY(gen_op_ldq_kernel_T0_A0),

    gen_op_TD_ldub_user_T0_A0,
    gen_op_TD_lduw_user_T0_A0,
    gen_op_TD_ldl_user_T0_A0,
    X86_64_ONLY(gen_op_ldq_user_T0_A0),
#endif
};

#if 0 /* unused */
static GenOpFunc *gen_op_opt_ld_T1_A0[3 * 4] = {
    gen_op_TD_ldub_raw_T1_A0,
    gen_op_TD_lduw_raw_T1_A0,
    gen_op_TD_ldl_raw_T1_A0,
    X86_64_ONLY(gen_op_ldq_raw_T1_A0),

#ifndef CONFIG_USER_ONLY
    gen_op_TD_ldub_kernel_T1_A0,
    gen_op_TD_lduw_kernel_T1_A0,
    gen_op_TD_ldl_kernel_T1_A0,
    X86_64_ONLY(gen_op_ldq_kernel_T1_A0),

    gen_op_TD_ldub_user_T1_A0,
    gen_op_TD_lduw_user_T1_A0,
    gen_op_TD_ldl_user_T1_A0,
    X86_64_ONLY(gen_op_ldq_user_T1_A0),
#endif
};
#endif


static GenOpFunc *gen_op_opt_st_T0_A0[3 * 4] = {
    gen_op_TD_stb_raw_T0_A0,
    gen_op_TD_stw_raw_T0_A0,
    gen_op_TD_stl_raw_T0_A0,
    X86_64_ONLY(gen_op_stq_raw_T0_A0),

#ifndef CONFIG_USER_ONLY
    gen_op_TD_stb_kernel_T0_A0,
    gen_op_TD_stw_kernel_T0_A0,
    gen_op_TD_stl_kernel_T0_A0,
    X86_64_ONLY(gen_op_stq_kernel_T0_A0),

    gen_op_TD_stb_user_T0_A0,
    gen_op_TD_stw_user_T0_A0,
    gen_op_TD_stl_user_T0_A0,
    X86_64_ONLY(gen_op_stq_user_T0_A0),
#endif
};


static GenOpFunc *gen_op_opt_mov_reg_T0[NB_OP_SIZES][CPU_NB_REGS] = {
    [OT_BYTE] = {
        gen_op_opt_movb_EAX_T0,
        gen_op_opt_movb_ECX_T0,
        gen_op_opt_movb_EDX_T0,
        gen_op_opt_movb_EBX_T0,
#ifdef TARGET_X86_64
        gen_op_movb_ESP_T0_wrapper,
        gen_op_movb_EBP_T0_wrapper,
        gen_op_movb_ESI_T0_wrapper,
        gen_op_movb_EDI_T0_wrapper,
        gen_op_movb_R8_T0,
        gen_op_movb_R9_T0,
        gen_op_movb_R10_T0,
        gen_op_movb_R11_T0,
        gen_op_movb_R12_T0,
        gen_op_movb_R13_T0,
        gen_op_movb_R14_T0,
        gen_op_movb_R15_T0,
#else
        gen_op_opt_movh_EAX_T0,
        gen_op_opt_movh_ECX_T0,
        gen_op_opt_movh_EDX_T0,
        gen_op_opt_movh_EBX_T0,
#endif
    },
    [OT_WORD] = {
        DEF_REGS(gen_op_opt_movw_, _T0)
    },
    [OT_LONG] = {
        DEF_REGS(gen_op_opt_movl_, _T0)
    },
#ifdef TARGET_X86_64
    [OT_QUAD] = {
        DEF_REGS(gen_op_movq_, _T0)
    },
#endif
};

static GenOpFunc *gen_op_opt_mov_reg_T1[NB_OP_SIZES][CPU_NB_REGS] = {
    [OT_BYTE] = {
        gen_op_opt_movb_EAX_T1,
        gen_op_opt_movb_ECX_T1,
        gen_op_opt_movb_EDX_T1,
        gen_op_opt_movb_EBX_T1,
#ifdef TARGET_X86_64
        gen_op_movb_ESP_T1_wrapper,
        gen_op_movb_EBP_T1_wrapper,
        gen_op_movb_ESI_T1_wrapper,
        gen_op_movb_EDI_T1_wrapper,
        gen_op_movb_R8_T1,
        gen_op_movb_R9_T1,
        gen_op_movb_R10_T1,
        gen_op_movb_R11_T1,
        gen_op_movb_R12_T1,
        gen_op_movb_R13_T1,
        gen_op_movb_R14_T1,
        gen_op_movb_R15_T1,
#else
        gen_op_opt_movh_EAX_T1,
        gen_op_opt_movh_ECX_T1,
        gen_op_opt_movh_EDX_T1,
        gen_op_opt_movh_EBX_T1,
#endif
    },
    [OT_WORD] = {
        DEF_REGS(gen_op_opt_movw_, _T1)
    },
    [OT_LONG] = {
        DEF_REGS(gen_op_opt_movl_, _T1)
    },
#ifdef TARGET_X86_64
    [OT_QUAD] = {
        DEF_REGS(gen_op_movq_, _T1)
    },
#endif
};


static GenOpFunc *gen_op_opt_mov_TN_reg[NB_OP_SIZES][2][CPU_NB_REGS] = 
{
    [OT_BYTE] = {
        {
            gen_op_opt_movl_T0_EAX,
            gen_op_opt_movl_T0_ECX,
            gen_op_opt_movl_T0_EDX,
            gen_op_opt_movl_T0_EBX,
#ifdef TARGET_X86_64
            gen_op_movl_T0_ESP_wrapper,
            gen_op_movl_T0_EBP_wrapper,
            gen_op_movl_T0_ESI_wrapper,
            gen_op_movl_T0_EDI_wrapper,
            gen_op_movl_T0_R8,
            gen_op_movl_T0_R9,
            gen_op_movl_T0_R10,
            gen_op_movl_T0_R11,
            gen_op_movl_T0_R12,
            gen_op_movl_T0_R13,
            gen_op_movl_T0_R14,
            gen_op_movl_T0_R15,
#else
            gen_op_opt_movh_T0_EAX,
            gen_op_opt_movh_T0_ECX,
            gen_op_opt_movh_T0_EDX,
            gen_op_opt_movh_T0_EBX,
#endif
        },
        {
            gen_op_opt_movl_T1_EAX,
            gen_op_opt_movl_T1_ECX,
            gen_op_opt_movl_T1_EDX,
            gen_op_opt_movl_T1_EBX,
#ifdef TARGET_X86_64
            gen_op_movl_T1_ESP_wrapper,
            gen_op_movl_T1_EBP_wrapper,
            gen_op_movl_T1_ESI_wrapper,
            gen_op_movl_T1_EDI_wrapper,
            gen_op_movl_T1_R8,
            gen_op_movl_T1_R9,
            gen_op_movl_T1_R10,
            gen_op_movl_T1_R11,
            gen_op_movl_T1_R12,
            gen_op_movl_T1_R13,
            gen_op_movl_T1_R14,
            gen_op_movl_T1_R15,
#else
            gen_op_opt_movh_T1_EAX,
            gen_op_opt_movh_T1_ECX,
            gen_op_opt_movh_T1_EDX,
            gen_op_opt_movh_T1_EBX,
#endif
        },
    },
    [OT_WORD] = {
        {
            DEF_REGS(gen_op_opt_movl_T0_, )
        },
        {
            DEF_REGS(gen_op_opt_movl_T1_, )
        },
    },
    [OT_LONG] = {
        {
            DEF_REGS(gen_op_opt_movl_T0_, )
        },
        {
            DEF_REGS(gen_op_opt_movl_T1_, )
        },
    },
#ifdef TARGET_X86_64
    [OT_QUAD] = {
        {
            DEF_REGS(gen_op_movl_T0_, )
        },
        {
            DEF_REGS(gen_op_movl_T1_, )
        },
    },
#endif
};


static void gen_opt_lea_modrm(DisasContext *s, int modrm, int *reg_ptr, int *offset_ptr)
{
    target_long disp;
    int havesib;
    int base;
    int index;
    int scale;
    int opreg;
    int mod, rm, code, override, must_add_seg;

	s->modrm_base = s->modrm_index = -1;
	
    override = s->override;
    must_add_seg = s->addseg;
    if (override >= 0)
        must_add_seg = 1;
    mod = (modrm >> 6) & 3;
    rm = modrm & 7;

    if (s->aflag) {

        havesib = 0;
        base = rm;
        index = 0;
        scale = 0;
        
        if (base == 4) {
            havesib = 1;
            code = ldub_code(s->pc++);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            base = (code & 7);
        }
        base |= REX_B(s);

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)ldl_code(s->pc);
                s->pc += 4;
                if (CODE64(s) && !havesib) {
                    disp += s->pc + s->rip_offset;
                }
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)ldub_code(s->pc++);
            break;
        default:
        case 2:
            disp = ldl_code(s->pc);
            s->pc += 4;
            break;
        }
        
        s->modrm_base = base;
        if (base >= 0) {
            /* for correct popl handling with esp */
            if (base == 4 && s->popl_esp_hack)
                disp += s->popl_esp_hack;
#ifdef TARGET_X86_64
            if (s->aflag == 2) {
                gen_op_movq_A0_reg[base]();
                if (disp != 0) {
                    if ((int32_t)disp == disp)
                        gen_op_addq_A0_im(disp);
                    else
                        gen_op_addq_A0_im64(disp >> 32, disp);
                }
            } else 
#endif
            {
                gen_op_opt_movl_A0_reg[base]();
                if (disp != 0)
                    gen_op_opt_addl_A0_im(disp);
            }
        } else {
#ifdef TARGET_X86_64
            if (s->aflag == 2) {
                if ((int32_t)disp == disp)
                    gen_op_movq_A0_im(disp);
                else
                    gen_op_movq_A0_im64(disp >> 32, disp);
            } else 
#endif
            {
                gen_op_opt_movl_A0_im(disp);
            }
        }
        
        /* XXX: index == 4 is always invalid */
        if (havesib && (index != 4 || scale != 0)) {
            s->modrm_index = index;
#ifdef TARGET_X86_64
            if (s->aflag == 2) {
                gen_op_addq_A0_reg_sN[scale][index]();
            } else 
#endif
            {
                gen_op_opt_addl_A0_reg_sN[scale][index]();
            }
        }
        if (must_add_seg) {
            if (override < 0) {
                if (base == R_EBP || base == R_ESP)
                    override = R_SS;
                else
                    override = R_DS;
            }
#ifdef TARGET_X86_64
            if (s->aflag == 2) {
                gen_op_addq_A0_seg(offsetof(CPUX86State,segs[override].base));
            } else 
#endif
            {
                gen_op_addl_A0_seg(offsetof(CPUX86State,segs[override].base));
            }
        }
    } else {
        switch (mod) {
        case 0:
            if (rm == 6) {
                disp = lduw_code(s->pc);
                s->pc += 2;
                gen_op_movl_A0_im(disp);
                rm = 0; /* avoid SS override */
                goto no_rm;
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)ldub_code(s->pc++);
            break;
        default:
        case 2:
            disp = lduw_code(s->pc);
            s->pc += 2;
            break;
        }
        switch(rm) {
        case 0:
        	s->modrm_base = R_EBX;
        	s->modrm_index = R_ESI;
            gen_op_opt_movl_A0_reg[R_EBX]();
            gen_op_opt_addl_A0_reg_sN[0][R_ESI]();
            break;
        case 1:
        	s->modrm_base = R_EBX;
        	s->modrm_index = R_EDI;
            gen_op_opt_movl_A0_reg[R_EBX]();
            gen_op_opt_addl_A0_reg_sN[0][R_EDI]();
            break;
        case 2:
        	s->modrm_base = R_EBP;
        	s->modrm_index = R_ESI;
            gen_op_opt_movl_A0_reg[R_EBP]();
            gen_op_opt_addl_A0_reg_sN[0][R_ESI]();
            break;
        case 3:
        	s->modrm_base = R_EBP;
        	s->modrm_index = R_EDI;
            gen_op_opt_movl_A0_reg[R_EBP]();
            gen_op_opt_addl_A0_reg_sN[0][R_EDI]();
            break;
        case 4:
        	s->modrm_base = R_ESI;
        	s->modrm_index = -1;
            gen_op_opt_movl_A0_reg[R_ESI]();
            break;
        case 5:
        	s->modrm_base = R_EDX;
        	s->modrm_index = -1;
            gen_op_opt_movl_A0_reg[R_EDI]();
            break;
        case 6:
        	s->modrm_base = R_EBP;
        	s->modrm_index = -1;
            gen_op_opt_movl_A0_reg[R_EBP]();
            break;
        default:
        case 7:
        	s->modrm_base = R_EBX;
        	s->modrm_index = -1;
            gen_op_opt_movl_A0_reg[R_EBX]();
            break;
        }
        if (disp != 0)
            gen_op_opt_addl_A0_im(disp);
        gen_op_opt_andl_A0_ffff();
    no_rm:
        if (must_add_seg) {
            if (override < 0) {
                if (rm == 2 || rm == 3 || rm == 6)
                    override = R_SS;
                else
                    override = R_DS;
            }
            gen_op_addl_A0_seg(offsetof(CPUX86State,segs[override].base));
        }
    }

    opreg = OR_A0;
    disp = 0;
    *reg_ptr = opreg;
    *offset_ptr = disp;
}

/* generate modrm memory load or store of 'reg'. TMP0 is used if reg !=
   OR_TMP0 */
static void gen_opt_ldst_modrm(DisasContext *s, int modrm, int ot, int reg, int is_store)
{
    int mod, rm, opreg, disp;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        s->ldst_reg = rm;
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_opt_mov_TN_reg[ot][0][reg]();
            gen_op_opt_mov_reg_T0[ot][rm]();
        } else {
            gen_op_opt_mov_TN_reg[ot][0][rm]();
            if (reg != OR_TMP0)
                gen_op_opt_mov_reg_T0[ot][reg]();
        }
    } else {
        s->ldst_reg = -1;
        gen_opt_lea_modrm(s, modrm, &opreg, &disp);
        if (is_store) {
            if (reg != OR_TMP0)
                gen_op_opt_mov_TN_reg[ot][0][reg]();
            gen_op_opt_st_T0_A0[ot + s->mem_index]();
        } else {
            gen_op_opt_ld_T0_A0[ot + s->mem_index]();
            if (reg != OR_TMP0)
                gen_op_opt_mov_reg_T0[ot][reg]();
        }
    }
}


static void gen_opt_push_T0(DisasContext *s)
{
#ifdef TARGET_X86_64
    if (CODE64(s)) {
        gen_op_movq_A0_reg[R_ESP]();
        if (s->dflag) {
            gen_op_subq_A0_8();
            gen_op_st_T0_A0[OT_QUAD + s->mem_index]();
        } else {
            gen_op_subq_A0_2();
            gen_op_st_T0_A0[OT_WORD + s->mem_index]();
        }
        gen_op_movq_ESP_A0();
    } else 
#endif
    {
        gen_op_opt_movl_A0_reg[R_ESP]();
        if (!s->dflag)
            gen_op_subl_A0_2();
        else
            gen_op_subl_A0_4();
        if (s->ss32) {
            if (s->addseg) {
                gen_op_opt_movl_T1_A0();
                gen_op_addl_A0_SS();
            }
        } else {
            gen_op_andl_A0_ffff();
            gen_op_opt_movl_T1_A0();
            gen_op_addl_A0_SS();
        }
        gen_op_opt_st_T0_A0[s->dflag + 1 + s->mem_index]();
        if (s->ss32 && !s->addseg)
            gen_op_opt_movl_ESP_A0();
        else
            gen_op_opt_mov_reg_T1[s->ss32 + 1][R_ESP]();
    }
}

static void gen_opt_pop_T0(DisasContext *s)
{
    {
        gen_op_opt_movl_A0_reg[R_ESP]();
        if (s->ss32) {
            if (s->addseg)
                gen_op_addl_A0_SS();
        } else {
            gen_op_andl_A0_ffff();
            gen_op_addl_A0_SS();
        }
        gen_op_opt_ld_T0_A0[s->dflag + 1 + s->mem_index]();
    }
}

