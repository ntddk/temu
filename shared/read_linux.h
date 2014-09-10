/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.
*/

#ifndef __READ_LINUX_H__
#define __READ_LINUX_H__
#include "hookapi.h"

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

#endif
