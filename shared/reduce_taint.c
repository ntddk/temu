/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "procmod.h"
#include "hooks/function_map.h"
#include "TEMU_main.h"
#include "hookapi.h"
#include "read_linux.h"

#if TAINT_ENABLED

static int ExAllocatePoolWithTag_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;
}

static int RtlAllocateHeap_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;
}

static int RtlReAllocateHeap_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 16, 0, NULL);
  return 0;
}

static int ExInterlockedPushEntryList_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  uint32_t vaddr;
  TEMU_read_mem(TEMU_cpu_regs[R_ESP] + 4, 4, &vaddr); // first argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  TEMU_read_mem(TEMU_cpu_regs[R_ESP] + 8, 4, &vaddr); // second argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  return 0;
}

static int InterlockedPushEntrySList_call(void *opaque)
{
  //fastcall
  taintcheck_reg_clean(R_ECX);
  taintcheck_reg_clean(R_EDX);
  uint32_t vaddr;
  TEMU_read_mem(TEMU_cpu_regs[R_ECX], 4, &vaddr); // first argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  TEMU_read_mem(TEMU_cpu_regs[R_EDX], 4, &vaddr); // second argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  return 0;
}

static int alloca_probe_ret(void *opaque)
{
  uint32_t *handle = (uint32_t *)opaque;
  hookapi_remove_hook(*handle);
  free(handle);
  taintcheck_reg_clean(R_ESP);
  return 0;
}

static int alloca_probe_call(void *opaque)
{
  uint32_t ret_eip;
  TEMU_read_mem(TEMU_cpu_regs[R_ESP], 4, &ret_eip);
  uint32_t *hook_handle = malloc(sizeof(uint32_t));
  if(hook_handle) {
    *hook_handle = hookapi_hook_return(ret_eip, alloca_probe_ret, 
			hook_handle, sizeof(uint32_t));
  }
  return 0;
}

static int _aligned_offset_malloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;  
}

static int _aligned_offset_realloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 16, 0, NULL);
  return 0;  
}

static int calloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 8, 0, NULL);
  return 0;  
}

static int malloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 4, 0, NULL);
  return 0;  
}

static int realloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 8, 0, NULL);
  return 0;  
}

static int NtAllocateVirtualMemory_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 24, 0, NULL);
  return 0;  
}

void reduce_taint_init()
{
  hookapi_hook_function_byname("ntoskrnl.exe", "ExAllocatePoolWithTag", 
  		1, ExAllocatePoolWithTag_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "RtlAllocateHeap", 
  		1, RtlAllocateHeap_call, 0, 0);
  hookapi_hook_function_byname("ntdll.dll", "RtlAllocateHeap", 
  		1, RtlAllocateHeap_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "NtAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntdll.dll", "NtAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntoskrnl.exe", "ZwAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntdll.dll", "RtlReAllocateHeap", 
  		1, RtlReAllocateHeap_call, 0, 0);

  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedPushEntryList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedInsertHeadList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedInsertTailList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "InterlockedPushEntrySList", 
  		1, InterlockedPushEntrySList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedPushEntrySList", 
  		1, InterlockedPushEntrySList_call, 0, 0);
  hookapi_hook_function_byname("ntdll.dll", "_alloca_probe", 1, 
			alloca_probe_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "_alloca_probe", 1,
			alloca_probe_call, 0, 0);

  hookapi_hook_function_byname("msvcrt.dll", "_aligned_offset_malloc",
		 1, _aligned_offset_malloc_call, 0, 0);
  hookapi_hook_function_byname("msvcrt.dll", "_aligned_offset_realloc",
		 1, _aligned_offset_realloc_call, 0, 0);
  hookapi_hook_function_byname("msvcrt.dll", "calloc", 1,
		 calloc_call, 0, 0);  
  hookapi_hook_function_byname("msvcrt.dll", "malloc", 1,
		 malloc_call, 0, 0);  
  hookapi_hook_function_byname("msvcrt.dll", "realloc", 1,
		 realloc_call, 0, 0);  
} 

#endif //TAINT_ENABLED
