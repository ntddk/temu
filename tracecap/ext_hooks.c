/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

/**************************************************************************
 * Based in part on hook_helpers.c
 *
 * this file defines functions that are made available to hook plugins.
 *
 * NOTE: to create a new function for plugins to call:
 * <hook_plugin.h>
 * 	o Add member to hook_plugin_info_t struct for new function
 * 	o Add typedef for function pointer type
 * <hook_plugin.c>
 * 	o add global variable to hook_plugin.c for new function
 * 	o add assignment to global variable in init function
 * <hook_helpers.h>

 * 	o create extern declaration of function in hook_helpers.h
 * <hook_helpers.c>
 * 	o add initialization to g_plugin_info with new function
 */
#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include "tracecap.h"
#include "TEMU_main.h"
#include "../shared/hooks/reg_ids.h"
#include "hook_helpers.h"

int check_ti () {
	return skip_taint_info;
}

int inc_ti () {
	return ++skip_taint_info;
}

int dec_ti () {
	if (skip_taint_info > 0)
		return --skip_taint_info;
	else
		return 0;
}

#if TAINT_ENABLED 
/* Returns the taint mask of a register */
uint64_t get_reg_taint(int reg_id) {
  uint32_t regnum=0, reg_offset=0, size=0;

  reg_index_from_id(reg_id, &regnum, &reg_offset, &size);
  return taintcheck_register_check(regnum, reg_offset, size, NULL);
}

/* Cleans the taint information of a register */
int clean_taint_reg(int reg_id) {
  uint32_t regnum=0, reg_offset=0, size=0;

  /* we do not taint EIP currently --Heng Yin */
  if(reg_id == eip_reg) return -1;

  reg_index_from_id(reg_id, &regnum, &reg_offset, &size);
  taintcheck_taint_register(regnum, reg_offset, size, 0, NULL);

  return 0;
}

#endif //TAINT_ENABLED

/* Read the return address from the stack */
uint32_t get_retaddr() {
    uint32_t esp = 0, retaddr = 0;
    int read_err = 0;

    TEMU_read_register(esp_reg, &esp);

    read_err = TEMU_read_mem(esp, 4, (unsigned char*)&retaddr);
    if (read_err)
      return 0;
    else
      return retaddr;
}
