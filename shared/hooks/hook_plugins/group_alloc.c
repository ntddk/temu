/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.
*/

/*************************************************************************
** group_alloc.c
** Author: Juan Caballero
**
** This file contains hooks for Windows memory allocation functions
**
** TODO: Add kernel32.dll::VirtualAlloc, kernel32.dll::VirtualFree
*/

#include "config.h"
#include "plugin.h"
#include "group_hook_helper.h"
#ifdef PLUGIN_PROTOS
  #include "../../../protos/my_stub_def.h"
  #include "../../../protos/protos.h"
#endif
#ifdef PLUGIN_TRACECAP
  #include "../../../tracecap/my_stub_def.h"
  #include "../../../tracecap/tracecap.h"
#endif

#include <stdio.h>
#include <string.h>

#define LOCAL_DEBUG 1
#define WRITE if (LOCAL_DEBUG) write_log


static int alloca_probe_call(void *opaque);
static int alloca_probe_ret(void *opaque);

static int malloc_call(void *opaque);
static int malloc_ret(void *opaque);
static int calloc_call(void *opaque);
static int calloc_ret(void *opaque);
static int free_call(void *opaque);
static int realloc_call(void *opaque);
static int realloc_ret(void *opaque);
static int rtl_allocate_heap_call(void *opaque);
static int rtl_allocate_heap_ret(void *opaque);
static int rtl_free_heap_call(void *opaque);
static int rtl_reallocate_heap_call(void *opaque);
static int rtl_reallocate_heap_ret(void *opaque);


hook_t hooks[] =
{
  /* Stack allocation */
  {"ntdll.dll", "_alloca_probe", alloca_probe_call, 0},
  {"ntoskrnl.exe", "_alloca_probe", alloca_probe_call, 0},

  /* Heap allocation */
  {"cygwin1.dll", "_malloc", malloc_call, 0},
  {"cygwin1.dll", "_calloc", calloc_call, 0},
  {"cygwin1.dll", "_free", free_call, 0},
  {"cygwin1.dll", "_realloc", realloc_call, 0},
  {"msvcrt.dll", "malloc", malloc_call, 0},
  {"msvcrt.dll", "calloc", calloc_call, 0},
  {"msvcrt.dll", "free", free_call, 0},
  {"msvcrt.dll", "realloc", realloc_call, 0},
  {"MSVCR71.DLL", "malloc", malloc_call, 0},
  {"MSVCR71.DLL", "calloc", calloc_call, 0},
  {"MSVCR71.DLL", "free", free_call, 0},
  {"MSVCR71.DLL", "realloc", realloc_call, 0},
  {"ntdll.dll", "RtlAllocateHeap", rtl_allocate_heap_call, 0},
  {"ntdll.dll", "RtlFreeHeap", rtl_free_heap_call, 0},
  {"ntdll.dll", "RtlReAllocateHeap", rtl_reallocate_heap_call, 0},
  {"ole32.dll", "CoTaskMemAlloc", malloc_call, 0},
  {"ole32.dll", "CoTaskMemFree", free_call, 0},
  {"ole32.dll", "CoTaskMemRealloc", realloc_call, 0},

};

int local_num_funs = (sizeof(hooks)/sizeof(hook_t));


void internal_init_plugin()
{
  initialize_plugin(hooks,local_num_funs);

  /* Create file to store allocation information */
  if (alloclog == NULL) {
    alloclog = fopen("/tmp/tmp.alloc", "w");
  }
}

/************************* STACK ALLOCATION **********************/

int alloca_probe_call(void *opaque)
{
  uint64_t taint = 0;
  uint32_t esp, buf;
  int read_err;

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  // If EAX not tainted, return
  taint = get_reg_taint(eax_reg);
  if (taint == 0)
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)&buf);
  if (read_err) return 0;

  /* Hook return */
  retaddr_t *s = malloc(sizeof(retaddr_t));
  if (s == NULL) return 0;
  s->hook_handle = hookapi_hook_return(buf, alloca_probe_ret, (void*)s,
    sizeof(retaddr_t));

  inc_ti();

  return 0;
}

int alloca_probe_ret(void *opaque)
{
  /* Remove return hook */
  retaddr_t *s = (retaddr_t *)opaque;
  hookapi_remove_hook(s->hook_handle);
  if (s) free(s);

  // Clear ESP
  clean_taint_reg(esp_reg);

  if (check_ti())
    dec_ti();

  return 0;
}


/************************* HEAP ALLOCATION **********************/

typedef struct {
  uint32_t inst_ctr;
  uint32_t hook_handle;
  uint32_t size;
  uint64_t sizeTaint;
} malloc_t;

int malloc_call(void *opaque)
{
  uint32_t esp;
  int read_err = 0;
  uint32_t buf[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Store the parameters */
  malloc_t *s = malloc(sizeof(malloc_t));
  if (s == NULL) return 0;
  s->inst_ctr = tstats.insn_counter_traced;
  s->size = buf[1];

  /* Check if the parameters are tainted. If so, clear them */
  s->sizeTaint = get_mem_taint(esp+4, 4, NULL);

  /* If parameters tainted, clear them */
  if (s->sizeTaint) {
    clean_mem_taint(esp+4, 4);
  }

  /* Hook the return address */
  //if (tstats.insn_counter_traced > 0) {
    s->hook_handle = hookapi_hook_return(buf[0], malloc_ret, (void*)s,
      sizeof(malloc_t));
    inc_ti();
  //}
  //else free(s);

  return 0;
}

int malloc_ret(void *opaque)
{
  uint32_t eax;
  malloc_t *s = (malloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Get allocation start address from EAX */
  read_reg(eax_reg, &eax);

  /* Check if parameters tainted */
  int sizeT = 0;
  if (s->sizeTaint) sizeT = 1;

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld ALLOC 0x%08x %d %d 0x0 0 0x0 0\n",
      tstats.insn_counter_traced, eax, s->size, sizeT);
  }

  if (s) free(s);

  if (check_ti())
      dec_ti();

  return 0;
}

int calloc_call(void *opaque)
{
  uint32_t esp;
  int read_err = 0;
  uint32_t buf[3];

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Store the parameters */
  malloc_t *s = malloc(sizeof(malloc_t));
  if (s == NULL) return 0;
  s->inst_ctr = tstats.insn_counter_traced;
  s->size = buf[1] * buf[2];

  /* Check if the parameters are tainted. If so, clear them */
  s->sizeTaint = get_mem_taint(esp+4, 8, NULL);

  /* If parameters tainted, clear them */
  if (s->sizeTaint) {
    clean_mem_taint(esp+4, 8);
  }

  /* Hook the return address */
  //if (tstats.insn_counter_traced > 0) {
    s->hook_handle = hookapi_hook_return(buf[0], calloc_ret, (void*)s,
      sizeof(malloc_t));
    inc_ti();
  //}
  //else free(s);

  return 0;
}

int calloc_ret(void *opaque)
{
  uint32_t eax;
  malloc_t *s = (malloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Get allocation start address from EAX */
  read_reg(eax_reg, &eax);

  /* Check if parameters tainted */
  int sizeT = 0;
  if (s->sizeTaint) sizeT = 1;

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld CALLOC 0x%08x %d %d 0x0 0 0x0 0\n",
      tstats.insn_counter_traced, eax, s->size, sizeT);
  }

  if (s) free(s);

  if (check_ti())
      dec_ti();

  return 0;
}


int free_call(void *opaque)
{
  uint32_t esp;
  int read_err = 0;
  uint32_t buf[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Check if the parameters are tainted. If so, clear them */
  uint64_t bufPtrTaint = get_mem_taint(esp+4, 4, NULL);

  /* If parameters tainted, clear them */
  if (bufPtrTaint) {
    clean_mem_taint(esp+4, 4);
  }

  /* No need to hook return, no return values */

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld FREE 0x%08x\n", tstats.insn_counter_traced, buf[1]);
  }

  return 0;
}

typedef struct {
  uint32_t inst_ctr;
  uint32_t hook_handle;
  uint32_t bufPtr;
  uint32_t bufSize;
  uint64_t bufSizeTaint;
} realloc_t;

int realloc_call(void *opaque)
{
  uint32_t esp;
  int read_err = 0;
  uint32_t buf[2];

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Store the parameters */
  realloc_t *s = malloc(sizeof(realloc_t));
  if (s == NULL) return 0;
  s->inst_ctr = tstats.insn_counter_traced;
  s->bufPtr = buf[1];
  s->bufSize = buf[2];

  /* Check if the size is tainted. If so, clear it */
  s->bufSizeTaint = get_mem_taint(esp+8, 4, NULL);

  /* If parameters tainted, clear them */
  if (s->bufSizeTaint) {
    clean_mem_taint(esp+8, 4);
  }

  /* Hook the return address */
  //if (tstats.insn_counter_traced > 0) {
    s->hook_handle = hookapi_hook_return(buf[0], realloc_ret, (void*)s,
      sizeof(realloc_t));
    inc_ti();
  //}
  //else free(s);

  return 0;
}


int realloc_ret(void *opaque)
{
  uint32_t eax;
  realloc_t *s = (realloc_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Get allocation start address from EAX */
  read_reg(eax_reg, &eax);

  /* Check if parameters tainted */
  int sizeT = (s->bufSizeTaint) ? 1 : 0;

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld FREE-R 0x%08x\n", tstats.insn_counter_traced, s->bufPtr);
    fprintf(alloclog, "%08ld ALLOC-R 0x%08x 0 %d %d\n",
      tstats.insn_counter_traced, eax, s->bufSize, sizeT);
  }

  if (s) free(s);

  if (check_ti())
      dec_ti();

  return 0;
}


typedef struct {
  uint32_t inst_ctr;
  uint32_t hook_handle;
  uint32_t size;
  uint64_t sizeTaint;
  uint32_t heapHandle;
  uint64_t heapHandleTaint;
  uint32_t flags;
  uint64_t flagsTaint;
} rtl_allocate_heap_t;


int rtl_allocate_heap_call(void *opaque)
{
  uint32_t esp = 0;
  uint32_t buf[4]; // Assume parameters are 4-byte long
  int read_err = 0;

  /*
    PVOID  RtlAllocateHeap(IN PVOID HeapHandle,IN ULONG Flags,
      IN SIZE_T Size);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Store the parameters */
  rtl_allocate_heap_t *s = malloc(sizeof(rtl_allocate_heap_t));
  if (s == NULL) return 0;
  s->inst_ctr = tstats.insn_counter_traced;
  s->size = buf[3];
  s->heapHandle = buf[1];
  s->flags = buf[2];

  /* Check if the parameters are tainted. If so, clear them */
  s->heapHandleTaint = get_mem_taint(esp+4, 4, NULL);
  s->flagsTaint = get_mem_taint(esp+8, 4, NULL);
  s->sizeTaint = get_mem_taint(esp+12, 4, NULL);

  /* If parameters tainted, clear them */
  if (s->heapHandleTaint) {
    clean_mem_taint(esp+4, 4);
  }
  if (s->flagsTaint) {
    clean_mem_taint(esp+8, 4);
  }
  if (s->sizeTaint) {
    clean_mem_taint(esp+12, 4);
  }

  /* Hook the return address */
  //if (tstats.insn_counter_traced > 0) {
    s->hook_handle = hookapi_hook_return(buf[0], rtl_allocate_heap_ret,
    (void*)s, sizeof(rtl_allocate_heap_t));
    inc_ti();
  //}
  //else free(s);

  return 0;
}

int rtl_allocate_heap_ret(void *opaque)
{
  uint32_t eax;
  rtl_allocate_heap_t *s = (rtl_allocate_heap_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Get allocation start address from EAX */
  read_reg(eax_reg, &eax);

  /* Check if parameters tainted */
  int sizeT = 0, handleT = 0, flagsT = 0;
  if (s->heapHandleTaint) handleT = 1;
  if (s->flagsTaint) flagsT = 1;
  if (s->sizeTaint) sizeT = 1;

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld ALLOC 0x%08x %d %d 0x%08x %d 0x%08x %d\n",
      tstats.insn_counter_traced, eax, s->size, sizeT, s->heapHandle, handleT,
      s->flags, flagsT);
  }

  if (s) free(s);

  if (check_ti())
      dec_ti();

  return 0;
}

typedef struct {
  uint32_t inst_ctr;
  uint32_t hook_handle;
  uint32_t buf_start;
  uint64_t bufTaint;
  uint32_t heapHandle;
  uint64_t heapHandleTaint;
  uint32_t flags;
  uint64_t flagsTaint;
} rtl_free_heap_t;

int rtl_free_heap_call(void *opaque)
{
  uint32_t esp = 0;
  uint32_t buf[4]; // Assume parameters are 4-byte long
  int read_err = 0;

  /*
    BOOLEAN  RtlFreeHeap(IN PVOID HeapHandle,IN ULONG Flags,
      IN PVOID HeapBase);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Check if the parameters are tainted. If so, clear them */
  uint64_t heapHandleTaint = get_mem_taint(esp+4, 4, NULL);
  uint64_t flagsTaint = get_mem_taint(esp+8, 4, NULL);
  uint64_t bufTaint = get_mem_taint(esp+12, 4, NULL);

  /* If parameters tainted, clear them */
  if (heapHandleTaint) {
    clean_mem_taint(esp+4, 4);
  }
  if (flagsTaint) {
    clean_mem_taint(esp+8, 4);
  }
  if (bufTaint) {
    clean_mem_taint(esp+12, 4);
  }

  /* No need to hook return, ignoring boolean return value */

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld FREE 0x%08x\n", tstats.insn_counter_traced, buf[3]);
  }

  return 0;
}


typedef struct {
  uint32_t inst_ctr;
  uint32_t hook_handle;
  uint32_t size;
  uint64_t sizeTaint;
  uint32_t heapHandle;
  uint64_t heapHandleTaint;
  uint32_t flags;
  uint64_t flagsTaint;
  uint32_t old_buf_start;
  uint64_t bufTaint;
} rtl_reallocate_heap_t;


int rtl_reallocate_heap_call(void *opaque)
{
  uint32_t esp = 0;
  uint32_t buf[5]; // Assume parameters are 4-byte long
  int read_err = 0;

  /*
    PVOID RtlReAllocateHeap(HANDLE heap,ULONG flags,
      PVOID ptr,SIZE_T size);
   */

  /* If not tracing yet, return */
  if (tracepid == 0) return 0;

  if (check_ti())
    return 0;

  /* Read stack starting at ESP */
  read_reg(esp_reg, &esp);
  read_err = read_mem(esp, sizeof(buf), (unsigned char*)buf);
  if (read_err) return 0;

  /* Store the parameters */
  rtl_reallocate_heap_t *s = malloc(sizeof(rtl_reallocate_heap_t));
  if (s == NULL) return 0;
  s->inst_ctr = tstats.insn_counter_traced;
  s->size = buf[4];
  s->heapHandle = buf[1];
  s->flags = buf[2];
  s->old_buf_start = buf[3];

  /* Check if the parameters are tainted. If so, clear them */
  s->heapHandleTaint = get_mem_taint(esp+4, 4, NULL);
  s->flagsTaint = get_mem_taint(esp+8, 4, NULL);
  s->bufTaint = get_mem_taint(esp+12, 4, NULL);
  s->sizeTaint = get_mem_taint(esp+16, 4, NULL);

  /* If parameters tainted, clear them */
  if (s->heapHandleTaint) {
    clean_mem_taint(esp+4, 4);
  }
  if (s->flagsTaint) {
    clean_mem_taint(esp+8, 4);
  }
  if (s->bufTaint) {
    clean_mem_taint(esp+12, 4);
  }
  if (s->sizeTaint) {
    clean_mem_taint(esp+16, 4);
  }


  // Hook the return address
  //if (tstats.insn_counter_traced > 0) {
    s->hook_handle = hookapi_hook_return(buf[0], rtl_reallocate_heap_ret,
    (void*)s, sizeof(rtl_reallocate_heap_t));
    inc_ti();
  //}
  //else free(s);

  return 0;
}

int rtl_reallocate_heap_ret(void *opaque)
{
  uint32_t eax;
  rtl_reallocate_heap_t *s = (rtl_reallocate_heap_t *)opaque;

  /* Remove hook */
  hookapi_remove_hook(s->hook_handle);

  /* Get allocation start address from EAX */
  read_reg(eax_reg, &eax);

  /* Check if parameters tainted */
  int sizeT = 0, handleT = 0, flagsT = 0, bufT;
  if (s->heapHandleTaint) handleT = 1;
  if (s->flagsTaint) flagsT = 1;
  if (s->bufTaint) bufT = 1;
  if (s->sizeTaint) sizeT = 1;

  /* Print to file the parameter information */
  if (alloclog) {
    fprintf(alloclog, "%08ld FREE-R 0x%08x\n",
      tstats.insn_counter_traced, s->old_buf_start);
    fprintf(alloclog, "%08ld ALLOC-R 0x%08x 0 %d %d 0x%08x %d 0x%08x %d\n",
      tstats.insn_counter_traced, eax, s->size, sizeT, s->heapHandle, handleT,
      s->flags, flagsT);
  }

  if (s) free(s);

  if (check_ti())
      dec_ti();

  return 0;
}

