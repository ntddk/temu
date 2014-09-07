/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/********************************************************************
** plugin.h
** Author: Cody Hartwig <chartwig@cs.cmu.edu>
**
 *
 * This file contains the function pointer declarations used by
 * plugins.
 * It should be included by the actual plugin implementation file.
 */
#include "hook_plugin.h"

#undef INLINE

extern read_mem_t 		read_mem;
extern write_mem_t      write_mem;
extern read_reg_t 		read_reg;
extern write_reg_t		write_reg;
extern taint_mem_t 		taint_mem;
extern taint_reg_t 		taint_reg;
extern get_procname_t 		get_procname;
//extern register_hookapi_t 	register_hookapi;
//extern remove_hookapi_t 	remove_hookapi;
extern get_function_name_t	get_function_name;
//extern int 		       *taintcheck_running;
//extern char 		       *lib_hook_procname;
extern int				*proc_cr3;

extern write_log_t		write_log;
extern get_mem_taint_t		get_mem_taint;
extern set_mem_taint_t 		set_mem_taint;
extern clean_mem_taint_t clean_mem_taint;

extern should_hook_t should_hook;
//extern register_hookapi_byname_t register_hookapi_byname; 

#define LOG(fmt, args...) write_log("plugin", fmt, ##args)
#define LOGL(fmt, args...) \
  write_log("plugin", __FILE__":%02d: " fmt, __LINE__, ##args)
#define LOGFCN(fmt, args...) write_log("fcn", fmt, ##args)
