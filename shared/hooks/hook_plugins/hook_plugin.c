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
** hook_plugin.c
** Author: Cody Hartwig <chartwig@cs.cmu.edu>
**		   Heng Yin <hyin@ece.cmu.edu>
**
** This file should get built in with the hook plugin
**
*/
#include "config.h"
#include "hook_plugin.h"
#include "shared/hookapi.h"

extern void internal_init_plugin();

read_mem_t 			read_mem 		= 0;
write_mem_t 		write_mem 		= 0;
read_reg_t 			read_reg 		= 0;
write_reg_t			write_reg		= 0;
taint_mem_t 		taint_mem 		= 0;
taint_reg_t 		taint_reg 		= 0;
get_procname_t 		get_procname 		= 0;
//register_hookapi_t 	register_hookapi 	= 0;
//remove_hookapi_t 	remove_hookapi 		= 0;
get_function_name_t 	get_function_name	= 0;
//int 		       *taintcheck_running 	= 0;
//char 		       *lib_hook_procname 	= 0;
unsigned int	   *proc_cr3 = 0;

write_log_t			write_log		= 0;
get_mem_taint_t		get_mem_taint	= 0;
set_mem_taint_t		set_mem_taint	= 0;
clean_mem_taint_t	clean_mem_taint = 0;

should_hook_t 		should_hook = 0;
//register_hookapi_byname_t register_hookapi_byname = 0;
uint32_t 		*	next_origin = 0;

void
init_plugin(hook_plugin_info_t *p)
{
  /* set up function pointers.  these are global within the 
   * scope of the plugin */
  read_mem = p->read_mem;
  write_mem = p->write_mem;
  read_reg = p->read_reg;
  write_reg = p->write_reg;
  taint_mem = p->taint_mem;
  taint_reg = p->taint_reg;
  get_procname = p->get_procname;
//  register_hookapi = p->register_hookapi;
//  remove_hookapi = p->remove_hookapi;
  get_function_name = p->get_function_name;
//  taintcheck_running = p->taintcheck_running;
//lib_hook_procname = p->lib_hook_procname;
  proc_cr3 = p->proc_cr3;

  write_log = p->write_log;
  get_mem_taint = p->get_mem_taint;
  set_mem_taint = p->set_mem_taint;
  clean_mem_taint = p->clean_mem_taint;


  should_hook = p->should_hook;
//  register_hookapi_byname = p->register_hookapi_byname;
  
  /* allow plugin to do register_hookapi */
  internal_init_plugin();
}

/*
** check to see if hook was called for process we are tracing
*/
int
good_proc()
{
  unsigned int cr3;

//  if (!*taintcheck_running) return 0;

  read_reg(cr3_reg, &cr3);
  if(cr3 != *proc_cr3) return 0;

  return 1;
}

/*
** iterate over list of hooked functions and register appropriate hooks
*/
void
set_hooks(hook_t *hook_table)
{
  int i;

  /*
  ** print functions to hook (and hook them)
  */
  write_log("plugin","\tHooking:\n");
  printf("\tHooking:\n");
  for (i = 0; 0 != hook_table[i].module; ++i)  {
    if (0 == should_hook(hook_table[i].module, hook_table[i].name)) 
      continue;
  
    write_log("plugin",
	  "\t+%s::%s\n", hook_table[i].module, hook_table[i].name);
    printf("\t+%s::%s\n", hook_table[i].module, hook_table[i].name);

    hookapi_hook_function_byname(hook_table[i].module, hook_table[i].name, 
                       0, hook_table[i].fcn, 0, 0);
  }

}

