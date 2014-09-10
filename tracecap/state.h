/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _STATE_H_
#define _STATE_H_

#include "TEMU_lib.h"

/* Whether to save registers in addition to memory */
#define SAVE_REGISTERS 1

/* In the current state file format, the layout of the x86 registers
   we use is modeled after 32-bit Linux's user_regs_struct. It's not
   really ideal for our applications: for instance, it records the
   segment registers, but not the LDT/GDT or the segment descriptors.
   The question of what registers we want to save should be revisited
   the next time we revise the file format. -SMcC */

struct state_file_regs_struct
{
  long int ebx;
  long int ecx;
  long int edx;
  long int esi;
  long int edi;
  long int ebp;
  long int eax;
  long int xds;
  long int xes;
  long int xfs;
  long int xgs;
  long int orig_eax;
  long int eip;
  long int xcs;
  long int eflags;
  long int esp;
  long int xss;
};

/* Whether to save kernel memory in addition to user memory */
#define SAVE_KERNEL_MEM 0

/* Saves memory state for process identified by cr3 into filename
   The state is captured at function call
   Returns zero if successful, otherwise it failed
*/
int save_state_by_cr3(uint32_t cr3, const char *filename);

/* Saves memory state for process identified by pid into filename
   The state is captured at function call
   Returns zero if successful, otherwise it failed
*/
int save_state_by_pid(uint32_t pid, const char *filename);

/* Saves memory state for process identified by cr3 into filename
   The state is captured the first time the process execution reaches addr
   Returns zero if successful, otherwise it failed
*/
int save_state_at_addr(uint32_t pid, uint32_t addr, const char *filename);

#endif // _STATE_H_
