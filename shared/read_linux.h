/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef __READ_LINUX_H__
#define __READ_LINUX_H__
#include "hookapi.h"

struct koffset {
    char version[128]; 
    target_ulong hookingpoint;
    target_ulong hookingpoint2; 
    target_ulong taskaddr; 
    int tasksize; 
    int listoffset; 
    int pidoffset; 
    int mmoffset; 
    int pgdoffset; 
    int commoffset; 
    int commsize; 
    int vmstartoffset; 
    int vmendoffset;
    int vmnextoffset; 
    int vmfileoffset; 
    int dentryoffset; 
    int dnameoffset; 
    int dinameoffset; 
}; 

extern target_ulong kernel_mem_start; 
extern target_ulong hookingpoint;
extern target_ulong hookingpoint2;
extern target_ulong taskaddr; 
extern int tasksize; 
extern int listoffset; 
extern int pidoffset; 
extern int mmoffset; 
extern int pgdoffset; 
extern int commoffset; 
extern int commsize; 
extern int vmstartoffset; 
extern int vmendoffset; 
extern int vmnextoffset; 
extern int vmfileoffset; 
extern int dentryoffset; 
extern int dnameoffset; 
extern int dinameoffset; 


/* offset for fc5 image 
static const long hookingpoint = 0xC01A26FC; // selinux_...
static const long taskaddr = 0xC033C300; 
static const int tasksize = 1360; 
static const int listoffset = 96; 
static const int pidoffset = 156; 
static const int mmoffset = 120; 
static const int pgdoffset = 40; 
static const int commoffset = 432; 
static const int commsize = 16; 

static const int vmfileoffset = 76; 
static const int dentryoffset = 8; 
static const int dnameoffset = 40; 
static const int dinameoffset = 112; */

/* offset for redhat 7.3 */
/* static const long hookingpoint = 0xC0117140; 
static const long taskaddr = 0xC031E000; 
static const int tasksize = 1424; 
static const int listoffset = 72; 
static const int pidoffset = 108; 
static const int mmoffset = 44; 
static const int pgdoffset = 12; 
static const int commoffset = 558; 
static const int commsize = 16; 

static const int vmfileoffset = 56; 
static const int dentryoffset = 8; 
static const int dnameoffset = 60; 
static const int dinameoffset = 96;  */


int get_data(target_ulong addr, void *target, int size); 
target_ulong next_task_struct(target_ulong addr); 
target_ulong get_pid(target_ulong addr); 
target_ulong get_pgd(target_ulong addr);
void get_name(target_ulong addr, char *buf, int size);
target_ulong get_first_mmap(target_ulong addr);
target_ulong get_next_mmap(target_ulong addr);
target_ulong get_vmstart(target_ulong addr);
target_ulong get_vmend(target_ulong addr);
void get_mod_name(target_ulong addr, char *name, int size);
int init_kernel_offsets();

void for_all_hookpoints(hook_proc_t func, int action);
#endif
