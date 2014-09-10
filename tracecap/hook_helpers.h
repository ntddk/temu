/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

/********************************************************************
** hook_helpers.h
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
#include "../shared/hooks/hook_plugins/hook_plugin.h"
#include "my_stub_def.h"
//#include "../shared/hooks/hook_plugins/stub_def.h"


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
extern int read_mem(uint32_t vaddr, int length, unsigned char *buf);
extern int write_mem(uint32_t vaddr, int length, unsigned char *buf);
extern int read_reg(int reg_id, uint32_t *val);
extern void write_reg(int reg_id, uint32_t val);
extern int taint_mem(uint32_t vaddr, uint32_t size, void *param);
extern int taint_reg(int reg_id, void *param);
extern int write_log(const char *const name, const char *const fmt, ...);
extern int get_function_name (uint32_t eip, char *mod_name, char *fun_name);

extern void get_procname(char *buf, uint32_t *pid);
extern uint64_t get_mem_taint(uint32_t vaddr, uint32_t size, uint8_t *records);
extern void clean_mem_taint(uint32_t vaddr, int size);

//extern uint8_t get_reg_taint(int reg_id, uint32_t size, uint8_t *records);

//extern void * plugin_malloc(size_t size);
//extern void plugin_free(void *ptr);

extern hook_plugin_info_t g_plugin_info;

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _HOOK_HELPERS_H_
