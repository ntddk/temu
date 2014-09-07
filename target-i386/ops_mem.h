void OPPROTO glue(glue(op_ldub, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    T0 = glue(TC_ldub, MEMSUFFIX)(A0, R_T0*4);
#else
    T0 = glue(ldub, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldsb, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    T0 = glue(TC_ldsb, MEMSUFFIX)(A0, R_T0*4);
#else
    T0 = glue(ldsb, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_lduw, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    T0 = glue(TC_lduw, MEMSUFFIX)(A0, R_T0*4);
#else
    T0 = glue(lduw, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldsw, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    T0 = glue(TC_ldsw, MEMSUFFIX)(A0, R_T0*4);
#else
    T0 = glue(ldsw, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldl, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    T0 = glue(TC_ldl, MEMSUFFIX)(A0, R_T0*4);
#else
   T0 = (uint32_t)glue(ldl, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldub, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    T1 = glue(TC_ldub, MEMSUFFIX)(A0, R_T1*4);
#else
    T1 = glue(ldub, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldsb, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    T1 = glue(TC_ldsb, MEMSUFFIX)(A0, R_T1*4);
#else
    T1 = glue(ldsb, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_lduw, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    T1 = glue(TC_lduw, MEMSUFFIX)(A0, R_T1*4);
#else
    T1 = glue(lduw, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldsw, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    T1 = glue(TC_ldsw, MEMSUFFIX)(A0, R_T1*4);
#else
    T1 = glue(ldsw, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_ldl, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    T1 = glue(TC_ldl, MEMSUFFIX)(A0, R_T1*4);
#else
    T1 = (uint32_t)glue(ldl, MEMSUFFIX)(A0);
#endif
}

void OPPROTO glue(glue(op_stb, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    glue(TC_stb, MEMSUFFIX)(A0, T0, R_T0*4);
#else
    glue(stb, MEMSUFFIX)(A0, T0);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_stw, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    glue(TC_stw, MEMSUFFIX)(A0, T0, R_T0*4);
#else
    glue(stw, MEMSUFFIX)(A0, T0);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_stl, MEMSUFFIX), _T0_A0)(void)
{
#if TAINT_ENABLED
    glue(TC_stl, MEMSUFFIX)(A0, T0, R_T0*4);
#else
    glue(stl, MEMSUFFIX)(A0, T0);
#endif
    FORCE_RET();
}

#if 0
void OPPROTO glue(glue(op_stb, MEMSUFFIX), _T1_A0)(void)
{
    glue(stb, MEMSUFFIX)(A0, T1);
    FORCE_RET();
}
#endif

void OPPROTO glue(glue(op_stw, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    glue(TC_stw, MEMSUFFIX)(A0, T1, R_T1*4);
#else
    glue(stw, MEMSUFFIX)(A0, T1);
#endif
    FORCE_RET();
}

void OPPROTO glue(glue(op_stl, MEMSUFFIX), _T1_A0)(void)
{
#if TAINT_ENABLED
    glue(TC_stl, MEMSUFFIX)(A0, T1, R_T1*4);
#else
    glue(stl, MEMSUFFIX)(A0, T1);
#endif
    FORCE_RET();
}

/* SSE/MMX support */
void OPPROTO glue(glue(op_ldq, MEMSUFFIX), _env_A0)(void)
{
    uint64_t *p;
    p = (uint64_t *)((char *)env + PARAM1);
    *p = glue(ldq, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_stq, MEMSUFFIX), _env_A0)(void)
{
    uint64_t *p;
    p = (uint64_t *)((char *)env + PARAM1);
    glue(stq, MEMSUFFIX)(A0, *p);
    FORCE_RET();
}

void OPPROTO glue(glue(op_ldo, MEMSUFFIX), _env_A0)(void)
{
    XMMReg *p;
    p = (XMMReg *)((char *)env + PARAM1);
    p->XMM_Q(0) = glue(ldq, MEMSUFFIX)(A0);
    p->XMM_Q(1) = glue(ldq, MEMSUFFIX)(A0 + 8);
}

void OPPROTO glue(glue(op_sto, MEMSUFFIX), _env_A0)(void)
{
    XMMReg *p;
    p = (XMMReg *)((char *)env + PARAM1);
    glue(stq, MEMSUFFIX)(A0, p->XMM_Q(0));
    glue(stq, MEMSUFFIX)(A0 + 8, p->XMM_Q(1));
    FORCE_RET();
}

#ifdef TARGET_X86_64
void OPPROTO glue(glue(op_ldsl, MEMSUFFIX), _T0_A0)(void)
{
    T0 = (int32_t)glue(ldl, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_ldsl, MEMSUFFIX), _T1_A0)(void)
{
    T1 = (int32_t)glue(ldl, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_ldq, MEMSUFFIX), _T0_A0)(void)
{
    T0 = glue(ldq, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_ldq, MEMSUFFIX), _T1_A0)(void)
{
    T1 = glue(ldq, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_stq, MEMSUFFIX), _T0_A0)(void)
{
    glue(stq, MEMSUFFIX)(A0, T0);
    FORCE_RET();
}

void OPPROTO glue(glue(op_stq, MEMSUFFIX), _T1_A0)(void)
{
    glue(stq, MEMSUFFIX)(A0, T1);
    FORCE_RET();
}
#endif

#if TAINT_ENABLED
#include "TD_ops_mem.h" 
#endif

#undef MEMSUFFIX
