void OPPROTO glue(glue(op_TD_ldub, MEMSUFFIX), _T0_A0)(void)
{
    T0 = glue(TD_ldub, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldsb, MEMSUFFIX), _T0_A0)(void)
{
    T0 = glue(TD_ldsb, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_lduw, MEMSUFFIX), _T0_A0)(void)
{
    T0 = glue(TD_lduw, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldsw, MEMSUFFIX), _T0_A0)(void)
{
    T0 = glue(TD_ldsw, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldl, MEMSUFFIX), _T0_A0)(void)
{
    T0 = (uint32_t)glue(TD_ldl, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldub, MEMSUFFIX), _T1_A0)(void)
{
    T1 = glue(TD_ldub, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldsb, MEMSUFFIX), _T1_A0)(void)
{
    T1 = glue(TD_ldsb, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_lduw, MEMSUFFIX), _T1_A0)(void)
{
    T1 = glue(TD_lduw, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldsw, MEMSUFFIX), _T1_A0)(void)
{
    T1 = glue(TD_ldsw, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_ldl, MEMSUFFIX), _T1_A0)(void)
{
    T1 = (uint32_t)glue(TD_ldl, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TD_stb, MEMSUFFIX), _T0_A0)(void)
{
    glue(TD_stb, MEMSUFFIX)(A0, T0);
    FORCE_RET();
}

void OPPROTO glue(glue(op_TD_stw, MEMSUFFIX), _T0_A0)(void)
{
    glue(TD_stw, MEMSUFFIX)(A0, T0);
    FORCE_RET();
}

void OPPROTO glue(glue(op_TD_stl, MEMSUFFIX), _T0_A0)(void)
{
    glue(TD_stl, MEMSUFFIX)(A0, T0);
    FORCE_RET();
}

#if 0
void OPPROTO glue(glue(op_stb, MEMSUFFIX), _T1_A0)(void)
{
    glue(stb, MEMSUFFIX)(A0, T1);
    FORCE_RET();
}
#endif

void OPPROTO glue(glue(op_TD_stw, MEMSUFFIX), _T1_A0)(void)
{
    glue(TD_stw, MEMSUFFIX)(A0, T1);
    FORCE_RET();
}

void OPPROTO glue(glue(op_TD_stl, MEMSUFFIX), _T1_A0)(void)
{
    glue(TD_stl, MEMSUFFIX)(A0, T1);
    FORCE_RET();
}

#if 0
/* SSE/MMX support */
void OPPROTO glue(glue(op_TC_ldq, MEMSUFFIX), _env_A0)(void)
{
    uint64_t *p;
    p = (uint64_t *)((char *)env + PARAM1);
    *p = glue(ldq, MEMSUFFIX)(A0);
}

void OPPROTO glue(glue(op_TC_stq, MEMSUFFIX), _env_A0)(void)
{
    uint64_t *p;
    p = (uint64_t *)((char *)env + PARAM1);
    glue(stq, MEMSUFFIX)(A0, *p);
    FORCE_RET();
}

void OPPROTO glue(glue(op_TC_ldo, MEMSUFFIX), _env_A0)(void)
{
    XMMReg *p;
    p = (XMMReg *)((char *)env + PARAM1);
    p->XMM_Q(0) = glue(ldq, MEMSUFFIX)(A0);
    p->XMM_Q(1) = glue(ldq, MEMSUFFIX)(A0 + 8);
}

void OPPROTO glue(glue(op_TC_sto, MEMSUFFIX), _env_A0)(void)
{
    XMMReg *p;
    p = (XMMReg *)((char *)env + PARAM1);
    glue(stq, MEMSUFFIX)(A0, p->XMM_Q(0));
    glue(stq, MEMSUFFIX)(A0 + 8, p->XMM_Q(1));
    FORCE_RET();
}

#endif

