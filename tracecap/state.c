/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include "state.h"
#include "bswap.h"
#include "shared/hookapi.h"
#include "shared/procmod.h"
#include "shared/read_linux.h"

#define STATE_PAGE_SIZE 4096

/* Trace header values */
#define STATE_VERSION_NUMBER 20
#define STATE_MAGIC_NUMBER 0xFFFEFFFE

/* File to dump the state */
static FILE *statelog = 0;

/* CR3 of process for which memory will be dumped */
static uint32_t statecr3 = 0;

/* The memory dump will be taken when execution reaches this address */
static uint32_t stateaddr = 0;

/* Hook handle for taking the memory dump at a specific EIP value */
static uint32_t stateaddr_hook_handle = 0;

/* A region */
typedef struct {
  uint32_t begin;
  uint32_t end;
} map_t;

/* Save registers */
void save_registers(struct state_file_regs_struct *regs)
{
  regs->eax = TEMU_cpu_regs[R_EAX];
  regs->ebx = TEMU_cpu_regs[R_EBX];
  regs->ecx = TEMU_cpu_regs[R_ECX];
  regs->edx = TEMU_cpu_regs[R_EDX];
  regs->esi = TEMU_cpu_regs[R_ESI];
  regs->edi = TEMU_cpu_regs[R_EDI];
  regs->ebp = TEMU_cpu_regs[R_EBP];
  regs->esp = TEMU_cpu_regs[R_ESP];
  regs->eip = *TEMU_cpu_eip;
  regs->eflags = *TEMU_cpu_eflags;
  regs->xcs = TEMU_cpu_segs[R_CS].selector;
  regs->xds = TEMU_cpu_segs[R_DS].selector;
  regs->xes = TEMU_cpu_segs[R_ES].selector;
  regs->xfs = TEMU_cpu_segs[R_FS].selector;
  regs->xgs = TEMU_cpu_segs[R_GS].selector;
  regs->xss = TEMU_cpu_segs[R_SS].selector;
  regs->orig_eax = 0;           //? Do we need to remember the call number
}

/* Save state (registers + memory pages) for process identified by statecr3 */
int save_state(void *opaque)
{
  /* remove address hook */
  if ((stateaddr_hook_handle) && (*TEMU_cpu_eip == stateaddr)) {
    term_printf("Saving state at address: 0x%08x\n", stateaddr);
    hookapi_remove_hook(stateaddr_hook_handle);
  }

  /* fail if the there is no file handle */
  if (!statelog)
    return 1;

  term_printf("Saving state for CR3: 0x%08x\n", statecr3);

  /* Write header fields */
  uint32_t magic = STATE_MAGIC_NUMBER;
  uint32_t version = STATE_VERSION_NUMBER;
  fwrite(&magic, 4, 1, statelog);
  fwrite(&version, 4, 1, statelog);

#if SAVE_REGISTERS != 0
  /* save registers */
  struct state_file_regs_struct regs;
  save_registers(&regs);
  fwrite(&regs, sizeof(regs), 1, statelog);
  fflush(statelog);
#endif

  /* save memories */
  //traverse_pages();
  uint32_t page_start_addr = 0;
  char buf[STATE_PAGE_SIZE];
  int err = 0;
  uint32_t stop_addr = 0xFFFFE000;

#if SAVE_KERNEL_MEM == 0
  uint32_t kernel_start_addr;
  // Avoid saving kernel memory if not requested
  if (taskaddr) { 
    // linux
    kernel_start_addr = 0xC0000000;
  } else { 
    // windows
    kernel_start_addr = 0x80000000;
  }
  stop_addr = kernel_start_addr - STATE_PAGE_SIZE; 
#endif

  for (page_start_addr = 0; page_start_addr <= stop_addr; 
       page_start_addr+= STATE_PAGE_SIZE)
  {
    //term_printf("Page_start: 0x%08x\n", page_start_addr);
    err = TEMU_read_mem_with_cr3(statecr3, page_start_addr, STATE_PAGE_SIZE,
            buf);

    if (!err) {
      map_t range;
      range.begin = page_start_addr;
      range.end = page_start_addr + STATE_PAGE_SIZE - 1;
      //term_printf("Writing page: 0x%08x -> 0x%08x\n", range.begin, range.end);

      /* write range to file */
      fwrite(&range, sizeof(range), 1, statelog);

      /* write page to file */
      fwrite(buf, 1, STATE_PAGE_SIZE, statelog);
      //fflush(statelog);
    }
  }

  /* close state file */
  fclose(statelog);
  statelog = 0;

  return 0;
}

/* Save state for given process (identified by CR3) */
int save_state_by_cr3(uint32_t cr3, const char *filename) {
  int status = 0;

  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_cr3");
    return 1;
  }

  statecr3 = cr3;
  status = save_state(NULL);

  return status;
}

/* Save state for given process (identified by PID) */
int save_state_by_pid(uint32_t pid, const char *filename) {
  int status = 0;

  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_by_pid");
    return 1;
  }

  statecr3 = find_cr3(pid);
  if (0 == statecr3)
    return 1;

  status = save_state(NULL);

  return status;
}

/* Save state for given process (identified by PID) 
 * when process execution reaches given address */
int save_state_at_addr(uint32_t pid, uint32_t addr, const char *filename)
{
  statecr3 = find_cr3(pid);
  if (0 == statecr3)
    return 1;

  stateaddr = addr;

  statelog = fopen(filename, "w");
  if (0 == statelog) {
    perror("save_state_at_addr");
    return 1;
  }

  term_printf("Hooking save state address: 0x%08x CR3: 0x%08x\n", 
    stateaddr, statecr3);
  stateaddr_hook_handle =
    hookapi_hook_function(0, stateaddr, save_state, NULL, 0);

  return 0;
}

