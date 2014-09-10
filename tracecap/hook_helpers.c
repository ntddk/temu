/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

/**************************************************************************
 * hook_helpers.c
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
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include "config.h"
#include "../TEMU_lib.h"
#include "hook_helpers.h"
#include "tracecap.h"

#include "../shared/procmod.h"


#include "../shared/hooks/hook_plugin_loader.h"
#include "../shared/hooks/function_map.h"
#include "../shared/hookapi.h"

int
read_mem(uint32_t vaddr, int length, unsigned char *buf)
{
  return (TEMU_read_mem(vaddr, length, buf) < 0);
}

int
write_mem(uint32_t vaddr, int length, unsigned char *buf)
{
  return (TEMU_write_mem(vaddr, length, buf) < 0);
}

static inline uint32_t SIZE_TO_MASK(uint32_t size) 
{
  return (size >=4)? -1 : (1<<(size*8))-1;
}


int
read_reg(int reg_id, uint32_t *val)
{
  *val = 0;
  TEMU_read_register(reg_id, val);
  return 0;
}

void
write_reg(int reg_id, uint32_t val)
{
  TEMU_write_register(reg_id, &val);
}

#if TAINT_ENABLED
/* Taint a memory region. Caller is in charge of freeing param */
int
taint_mem(uint32_t vaddr, uint32_t size, void *param)
{
  hook_taint_record_t *hook_rec = param;
  //fprintf(stderr,"tainting: 0x%x, size=%d, type=%d, origin=%d, offset=%d\n",
  //    vaddr, size, hook_rec->source, hook_rec->origin, hook_rec->offset);

  uint32_t paddr = 0, vaddr2=0;
  taint_record_t records[64];
  uint32_t i, j, len, offset;
  uint32_t trOffset = hook_rec->offset;

  for(i=0; i<size; i+=len) {
    vaddr2 = vaddr;
    paddr = TEMU_get_phys_addr((vaddr+i)&TARGET_PAGE_MASK);
    offset = (vaddr+i)&(TARGET_PAGE_SIZE-1);
    paddr += offset;
    len = (TARGET_PAGE_SIZE - offset > size-i)? size-i: TARGET_PAGE_SIZE-offset;
    
    /* while loop is because we can only taint 64 bytes at a time */
    int rem_size = len;
    while (rem_size > 0) {
      int this_size = rem_size <= 64 ? rem_size : 64;
      
      unsigned char vals[64];
      assert(!read_mem(vaddr2, this_size, vals));
    
      for (j = 0; j < this_size; j++) {
      	memset (&records[j],0,sizeof(taint_record_t));
				records[j].numRecords = 1;
				records[j].taintBytes[0].source = hook_rec->source;
				records[j].taintBytes[0].origin = hook_rec->origin;
				records[j].taintBytes[0].offset = trOffset;
				trOffset++;
      } /* end for */

      /* actually do taint */
      taintcheck_taint_memory(paddr, this_size, 
		  	(this_size<64)? (1ULL<<size)-1: (uint64_t)(-1), 
			(uint8_t*)records);
      //fprintf(stderr,"  paddr=%08x vaddr2=%08x this_size=%d \n", 
      //	paddr, vaddr2, this_size);

      /* prepare for next loop iteration */
      rem_size -= this_size;
      vaddr2 += this_size;
      paddr += this_size;
    } /* end while */
  }

//	free (param);
  return 0;
}


int
taint_reg(int reg_id, void *param)
{
  hook_taint_record_t *hook_rec = param;
  
  /* we do not taint EIP currently --Heng Yin */
  if(reg_id == eip_reg) return -1;

  taint_record_t records[MAX_OPERAND_LEN];
  //memset (&records,0,sizeof(records));
	
  uint32_t base_id=0, reg_offset=0, size=0;
  reg_index_from_id(reg_id, &base_id, &reg_offset, &size);
  int i;
  for (i = 0; i < size; ++i) {
		records[i].numRecords = 1;
		records[i].taintBytes[0].source = TAINT_SOURCE_HOOKAPI; //hook_rec->source
		records[i].taintBytes[0].origin = hook_rec->origin;
		records[i].taintBytes[0].offset = hook_rec->offset + i;
  }
  
  taintcheck_taint_register(base_id, reg_offset, size, (1<<size)-1, (uint8_t*)records);
  return 0;
}


uint64_t
get_mem_taint(uint32_t vaddr, uint32_t size, uint8_t *rec) //size<=64
{
  return taintcheck_check_virtmem(vaddr, size, rec);
}

/* recover the taint information 
 * size <= 64
 */
void set_mem_taint(uint32_t vaddr, uint32_t size, uint64_t taint, uint8_t *records)
{
  taintcheck_taint_virtmem(vaddr, size, taint, records);
}


void clean_mem_taint(uint32_t vaddr, int size)
{
  taintcheck_taint_virtmem(vaddr, size, 0, NULL); 
}

#endif //TAINT_ENABLED


void
get_procname(char *buf, uint32_t *pid)
{
  find_process(TEMU_cpu_cr[3], buf, pid);
}


int write_log(const char *const name, const char *const fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char hookname[128]= "";
  
  if ((strncmp(name,"tracenetlog",11) == 0) && (tracenetlog)) {
  	vfprintf(tracenetlog, fmt, ap);   
  }
  else if (strncmp(name,"tracehooklog",12) == 0) {
  	if (!tracehooklog) {
			snprintf(hookname, 128, "%s.hooklog", tracename_p); 
			tracehooklog = fopen(hookname, "w");
                        if (0 == tracehooklog) {
                          perror("write_log");
                          return -1;
                        }
			vfprintf(tracehooklog, fmt, ap);
  	}
  	else {
  		vfprintf(tracehooklog, fmt, ap);
  	}
  }
  else {
  	vfprintf(stderr, fmt, ap);
  }
  va_end(ap);

  return 0;
}

int get_function_name (uint32_t eip, char *mod_name_ptr, char *fun_name_ptr) {
	struct names_t *fun_struct_ptr = NULL;
	
	fun_struct_ptr = query_name((unsigned long) eip);
	if (fun_struct_ptr != NULL) {
		strncpy(mod_name_ptr,fun_struct_ptr->mod_name,512);
		strncpy(fun_name_ptr,fun_struct_ptr->fun_name,512);
		return 1;
	}
	else {
		strncpy(mod_name_ptr,"unknown",512);
		strncpy(fun_name_ptr,"unknown",512);
		return 0;
	}
	
}

hook_plugin_info_t g_plugin_info = 
  {
    read_mem,
    write_mem,
    read_reg,
    write_reg,
#if TAINT_ENABLED
    taint_mem,
    taint_reg,
#endif    
    get_procname,
    get_function_name,
    0,
    write_log, /* Write log */
#if TAINT_ENABLED    
    get_mem_taint,
    set_mem_taint,
    clean_mem_taint,
#endif    
    should_hook,
  };

