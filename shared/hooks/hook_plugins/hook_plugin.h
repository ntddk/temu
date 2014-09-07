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
** hook_plugin.h
** Author: Cody Hartwig <chartwig@cs.cmu.edu>
**         Heng Yin <hyin@ece.cmu.edu>
**
 *
 * This file should be included in QEMU where it can be called
 * for each loaded plugin. This gives each plugin the functions
 * it needs to function.
 */
#ifndef _HOOK_PLUGIN_H_
#define _HOOK_PLUGIN_H_

#include <inttypes.h>
#include "../reg_ids.h"

extern int good_proc();

/* function pointer typedefs */
typedef int (*read_mem_t)(uint32_t, int, unsigned char *);
typedef int (*write_mem_t)(uint32_t, int, unsigned char *);
typedef int (*read_reg_t)(int, uint32_t *);
typedef void (*write_reg_t)(int, uint32_t);
typedef int (*taint_mem_t)(uint32_t vaddr, uint32_t size, void *param);
typedef int (*taint_reg_t)(int regid, void *param);
typedef void(*get_procname_t)(char *, uint32_t *);
//typedef int(*register_hookapi_t)(uint32_t, int(*)(void *), void *, uint32_t);
#if 0
typedef uint32_t (*hookapi_hook_function_t)(int is_global,
               uint32_t eip, 
               int(*)(void *), 
               void *opaque, 
               uint32_t sizeof_opaque
               );

typedef uint32_t 
(*hookapi_hook_return_t)(
               uint32_t eip, 
               int (*)(void *), 
               void *opaque, 
               uint32_t sizeof_opaque
               );
 
typedef void (*hookapi_remove_hook_t)(uint32_t handle);

typedef int (*hookapi_hook_function_byname)(const char *mod, const char *func, 
	int is_global, int (*)(void *), void *opaque, uint32_t sizeof_opaque);
#endif
//typedef int(*remove_hookapi_t)(uint32_t eip);
typedef int(*get_function_name_t)(uint32_t, char *, char*);

typedef int(*write_log_t)(const char*const, const char*const, ...);

//typedef uint64_t(*get_mem_taint_t)(uint32_t, int, mini_taint_record_t *);
typedef uint64_t (*get_mem_taint_t)(uint32_t vaddr, uint32_t size, uint8_t *records);
typedef void (*set_mem_taint_t)(uint32_t vaddr, uint32_t size, uint64_t taint, uint8_t *records);
typedef void (*clean_mem_taint_t)(uint32_t, int);

typedef int (*should_hook_t)(const char*const, const char*const);
//typedef int (*register_hookapi_byname_t)(char *, char *, int(*)(void *), void *, uint32_t);

/* typedef for plugin info */
typedef struct {
  read_mem_t 		read_mem;	    /* function to read memory 	     */
  write_mem_t 		write_mem;	    /* function to write memory      */
  read_reg_t 		read_reg;	    /* function to read registers    */
  write_reg_t		write_reg;	    /* function to write registers   */
#if TAINT_ENABLED  
  taint_mem_t 		taint_mem;	    /* function to taint memory      */
  taint_reg_t 		taint_reg;	    /* function to taint registers   */
#endif  
  get_procname_t 	get_procname;	    /* function to get name of proc  */
  get_function_name_t	get_function_name;  /* function to get function name */
  unsigned int		*proc_cr3;
  write_log_t		write_log;          /* function to log data */
#if TAINT_ENABLED  
  get_mem_taint_t	get_mem_taint;      /* function to get memory taint  */
  set_mem_taint_t 	set_mem_taint;
  clean_mem_taint_t clean_mem_taint;
#endif  
  should_hook_t		should_hook; /* tell plugin which functions */
} hook_plugin_info_t;

typedef void (*init_plugin_t)(hook_plugin_info_t *);

/* 
** hook table types (used for generically hooking a list of functions 
*/
typedef int (*fcn_hook_t)(void *);

typedef struct {
  char *module;
  char *name;
  fcn_hook_t fcn;
  int do_hook;
} hook_t;

extern void set_hooks(hook_t *);

#endif /* _HOOK_PLUGIN_H_ */
