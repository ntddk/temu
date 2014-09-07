/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _IHOOK_HELPER_H_
#define _IHOOK_HELPER_H_

#include <inttypes.h>
#include <stdlib.h>
#include "../../list.h"

typedef int (*fcn_hook_t)(void *);

typedef struct {
  const char *module;
  const char *name;
  fcn_hook_t fcn;
} hook_table_entry_t;

typedef struct {
  int type; //0: data, 1: pointer
  int dir;	//0: in, 1: out, 2: in & out
  int size; //0: string, -1: wide string, >0: actual size
} argument_info_t;

typedef struct {
  char function_name[128];
  int nr_args;
  argument_info_t arguments[12];
  int has_retval;
  uint32_t call_no;
  uint32_t hook_handle;
  uint32_t stack[13];
} function_hook_info_t;


class ihook_helper_t {
  public:
	virtual ~ihook_helper_t(){};
	virtual void function_call_entry(function_hook_info_t *hook_info) = 0;
	virtual void function_call_return(function_hook_info_t *hook_info) = 0;
	virtual int  immediate_return(function_hook_info_t *hook_info, int pop_args) = 0;
	virtual void hook_return_address(function_hook_info_t *hook_info, fcn_hook_t hook_proc) = 0;
	virtual void set_hooks(hook_table_entry_t *hook_table) = 0;
};

#endif //_IHOOK_HELPER_H_
