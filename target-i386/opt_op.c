void OPPROTO op_opt_movl_A0_im(void)
{
    A0 = (uint32_t)PARAM1;
}

void OPPROTO op_opt_addl_A0_im(void)
{
    A0 = (uint32_t)(A0 + PARAM1);
}

void OPPROTO op_opt_andl_A0_ffff(void)
{
    A0 = A0 & 0xffff;
}

void OPPROTO op_opt_movl_T0_imu(void)
{
    T0 = (uint32_t)PARAM1;
}

void OPPROTO op_opt_movl_T0_im(void)
{
    T0 = (int32_t)PARAM1;
}

void OPPROTO op_opt_movl_T1_A0(void)
{
    T1 = A0;
}

void OPPROTO op_opt_movl_T1_im(void)
{
    T1 = (int32_t)PARAM1;
}

void OPPROTO op_opt_movl_T1_imu(void)
{
    T1 = (uint32_t)PARAM1;
}

