void OPPROTO glue(op_opt_movl_A0,REGNAME)(void)
{
    A0 = (uint32_t)REG; 
}

void OPPROTO glue(op_opt_addl_A0,REGNAME)(void)
{
    A0 = (uint32_t)(A0 + REG);
}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s1)(void)
{
    A0 = (uint32_t)(A0 + (REG << 1));
}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s2)(void)
{
    A0 = (uint32_t)(A0 + (REG << 2));
}

void OPPROTO glue(glue(op_opt_addl_A0,REGNAME),_s3)(void)
{
    A0 = (uint32_t)(A0 + (REG << 3));
}

void OPPROTO glue(op_opt_movl_T0,REGNAME)(void)
{
    T0 = REG;
}

void OPPROTO glue(op_opt_movl_T1,REGNAME)(void)
{
    T1 = REG;
}

void OPPROTO glue(op_opt_movh_T0,REGNAME)(void)
{
    T0 = REG >> 8;
}

void OPPROTO glue(op_opt_movh_T1,REGNAME)(void)
{
    T1 = REG >> 8;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_T0)(void)
{
    REG = (uint32_t)T0;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_T1)(void)
{
    REG = (uint32_t)T1;
}

void OPPROTO glue(glue(op_opt_movl,REGNAME),_A0)(void)
{
    REG = (uint32_t)A0;
}


/* mov T1 to REG if T0 is true */
void OPPROTO glue(glue(op_opt_cmovw,REGNAME),_T1_T0)(void)
{
    if (T0)
        REG = (REG & ~0xffff) | (T1 & 0xffff);
    FORCE_RET();
}

void OPPROTO glue(glue(op_opt_cmovl,REGNAME),_T1_T0)(void)
{
    if (T0)
        REG = (uint32_t)T1;

    FORCE_RET();
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_T0)(void)
{
    REG = (REG & ~0xffff) | (T0 & 0xffff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_T1)(void)
{
    REG = (REG & ~0xffff) | (T1 & 0xffff);
}

/* NOTE: A0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movw,REGNAME),_A0)(void)
{
    REG = (REG & ~0xffff) | (A0 & 0xffff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movb,REGNAME),_T0)(void)
{
    REG = (REG & ~0xff) | (T0 & 0xff);
}

/* NOTE: T0 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movh,REGNAME),_T0)(void)
{
    REG = (REG & ~0xff00) | ((T0 & 0xff) << 8);
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movb,REGNAME),_T1)(void)
{
    REG = (REG & ~0xff) | (T1 & 0xff);
}

/* NOTE: T1 high order bits are ignored */
void OPPROTO glue(glue(op_opt_movh,REGNAME),_T1)(void)
{
    REG = (REG & ~0xff00) | ((T1 & 0xff) << 8);
}

