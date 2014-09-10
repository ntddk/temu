/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

/********************************************************************
** Based in part on hook_helpers.h
**
** This file should be included where these functions are defined.
** XXX: currently this is hook_helpers.c
**
*/

#ifndef _HOOK_HELPERS_H_
#define _HOOK_HELPERS_H_

#include <inttypes.h>

/* apparently taintcheck.h assumes this has already been included */
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
extern int check_ti();
extern int inc_ti();
extern int dec_ti();
#if TAINT_ENABLED
extern uint64_t get_reg_taint(int reg_id);
extern int clean_taint_reg(int reg_id);
#endif 
extern uint32_t get_retaddr();

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _HOOK_HELPERS_H_
