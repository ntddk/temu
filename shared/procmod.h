/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef _PROCMOD_H_INCLUDED
#define _PROCMOD_H_INCLUDED

/////////////////////////////////
/// @defgroup semantics OS-Aware: OS-level Semantics Extractor
///

/// @ingroup semantics
/// a structure of module information
typedef struct _tmodinfo
{
	char	    name[512]; ///< module name
	uint32_t	base;  ///< module base address
	uint32_t	size;  ///< module size
}tmodinfo_t;

typedef struct _old_tmodinfo
{
  char name[32];
  uint32_t base;
  uint32_t size;
}old_modinfo_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*createproc_notify_t)(uint32_t pid, uint32_t cr3);
typedef void (*removeproc_notify_t)(uint32_t pid);
typedef void (*loadmodule_notify_t)(uint32_t pid, uint32_t cr3, char *name, 
		uint32_t base, uint32_t size);
extern createproc_notify_t createproc_notify;
extern removeproc_notify_t removeproc_notify;
extern loadmodule_notify_t loadmodule_notify;

// MIN: process tracking...
typedef void (*loadmainmodule_notify_t)(uint32_t pid, char* name);
extern loadmainmodule_notify_t loadmainmodule_notify;


/// @ingroup semantics
/// locate the module that a given instruction belongs to
/// @param eip virtual address of a given instruction
/// @param cr3 memory space id: physical address of page table
/// @param proc process name (output argument)
/// @return tmodinfo_t structure 
tmodinfo_t * locate_module(uint32_t eip, uint32_t cr3, char proc[]);

/// @ingroup semantics
/// find process given a memory space id
/// @param cr3 memory space id: physical address of page table
/// @param proc process name (output argument)
/// @param pid  process pid (output argument)
/// @return number of modules in this process 
int find_process(uint32_t cr3, char proc[], uint32_t *pid);

//int delete_thread_by_tid(uint32_t tid);
//int remove_threads_by_cr3(uint32_t cr3);

/// @ingroup semantics
/// @return the current thread id. If for some reason, this operation 
/// is not successful, the return value is set to -1. 
/// This function only works in Windows XP for Now. 
uint32_t get_current_tid();

void get_proc_modules(uint32_t pid, old_modinfo_t *buf, int size);

int procmod_init();

void procmod_cleanup();

uint32_t find_cr3(uint32_t pid);

uint32_t find_pid(uint32_t cr3);

uint32_t find_pid_by_name(const char* proc_name);

void list_procs();
void do_linux_ps();
void list_guest_modules(uint32_t pid);

void parse_process(char *log);
void parse_module(char *log);

/// @ingroup semantics
/// This function is only used to update process and module information for Linux
int update_proc(void *opaque);

int checkcr3(uint32_t cr3, uint32_t eip, uint32_t tracepid, char *name,
             int len, uint32_t * offset);

/// @ingroup semantics
/// This function inserts the module information 
int procmod_insert_modinfo(uint32_t pid, uint32_t cr3, const char *name,
                           uint32_t base, uint32_t size);


tmodinfo_t *locate_module_byname(const char *name, uint32_t pid);

int is_guest_windows();

#ifdef __cplusplus 
};
#endif

#endif

