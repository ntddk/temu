/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "config.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#if TAINT_ENABLED
#include "taintcheck.h"
#endif
#include "TEMU_main.h"
#include "hookapi.h"
#include "read_linux.h"

target_ulong kernel_mem_start = 0x80000000;

target_ulong hookingpoint = 0;
target_ulong hookingpoint2 = 0;
target_ulong taskaddr = 0;
int tasksize = 0;
int listoffset = 0;
int pidoffset = 0;
int mmoffset = 0;
int pgdoffset = 0;
int commoffset = 0;
int commsize = 0;
int vmstartoffset = 0;
int vmendoffset = 0;
int vmnextoffset = 0;
int vmfileoffset = 0;
int dentryoffset = 0;
int dnameoffset = 0;
int dinameoffset = 0;

/* need to check next_task_struct with the corresponding 
   kernel source code for compatibality 
   in 2.4.20 the next pointer points directly to the next
   tast_struct, while in 2.6.15, it is done through list_head */
static struct koffset kernel_table[] = {
  {"2.4.20-24.7",               /* entry name */
   0xC0120180, 0x00000000,      /* hooking address: flush_signal_handlers */
   0xC031E000,                  /* task struct root */
   1424,                        /* size of task_struct */
   72,                          /* offset of task_struct list */
   108,                         /* offset of pid */
   44,                          /* offset of mm */
   12,                          /* offset of pgd in mm */
   558,                         /* offset of comm */
   16,                          /* size of comm */
   4,                           /* offset of vm_start in vma */
   8,                           /* offset of vm_end in vma */
   12,                          /* offset of vm_next in vma */
   56,                          /* offset of vm_file in vma */
   8,                           /* offset of dentry in file */
   60,                          /* offset of d_name in dentry */
   96                           /* offset of d_iname in dentry */
   },
/*     {"redhat7.3", 0xC0117140, 0, 0xC031E000, 1424, 72, 108, 44, 12,  */
/*      558, 16, 56, 8, 60, 96},  */
  {"2.6.15-1.2054_FC5",         /* entry name (Fedora Core 5) */
   0xC012475C, 0x00000000,      /* hooking address: flush_signal_handlers */
   0xC033C300,                  /* task struct root */
   1360,                        /* size of task_struct */
   96,                          /* offset of task_struct list */
   156,                         /* offset of pid */
   120,                         /* offset of mm */
   40,                          /* offset of pgd in mm */
   432,                         /* offset of comm */
   16,                          /* size of comm */
   4,                           /* offset of vm_start in vma */
   8,                           /* offset of vm_end in vma */
   12,                          /* offset of vm_next in vma */
   76,                          /* offset of vm_file in vma */
   8,                           /* offset of dentry in file */
   40,                          /* offset of d_name in dentry */
   112                          /* offset of d_iname in dentry */
   },
  {"2.6.26-1-686",         /* entry name (Debian 2.6.26-1-686 2.6.26-4) */
   0xC012BD1A, 0x00000000, /* hooking address: flush_signal_handlers */
   0xC034D300,             /* task struct root */
   1048,                   /* size of task_struct */
   212,                    /* offset of task_struct list */
   272,                    /* offset of pid */
   236,                    /* offset of mm */
   36,                     /* offset of pgd in mm */
   553,                    /* offset of comm */
   16,                     /* size of comm */
   4,                      /* offset of vm_start in vma */
   8,                      /* offset of vm_end in vma */
   12,                     /* offset of vm_next in vma */
   72,                     /* offset of vm_file in vma */
   12,                     /* offset of dentry in file */
   28,                     /* offset of d_name in dentry */
   96                      /* offset of d_iname in dentry */ 
  },
  {"2.6.24-19-generic",    /* entry name (Ubuntu 2.6.24-19.41) */
   0xC0139590, 0x00000000, /* hooking address: flush_signal_handlers */
   0xC03EA3A0,             /* task struct root */
   1472,                   /* size of task_struct */
   140,                    /* offset of task_struct list */
   200,                    /* offset of pid */
   164,                    /* offset of mm */
   36,                     /* offset of pgd in mm */
   461,                    /* offset of comm */
   16,                     /* size of comm */
   4,                      /* offset of vm_start in vma */
   8,                      /* offset of vm_end in vma */
   12,                     /* offset of vm_next in vma */
   72,                     /* offset of vm_file in vma */
   12,                     /* offset of dentry in file */
   28,                     /* offset of d_name in dentry */
   96                      /* offset of d_iname in dentry */ 
  },
  {  "2.6.28-11-generic", /* entry name (Ubuntu 2.6.28-11.42) */
     0xc01449b0, 0x00000000, /* hooking address (flush_signal_handlers) */
     0xC0687340, /* task struct root (init_task) */
     3212, /* size of task_struct */
     452, /* offset of task_struct list */
     496, /* offset of pid */
     460, /* offset of mm */
     36, /* offset of pgd in mm */
     792, /* offset of comm */
     16, /* size of comm */
     4, /* offset of vm_start in vma */
     8, /* offset of vm_end in vma */
     12, /* offset of vm_next in vma */
     72, /* offset of vm_file in vma */
     12, /* offset of dentry in file */
     28, /* offset of d_name in dentry */
     96 /* offset of d_iname in dentry */ 
  },
  {  "2.6.28-14-generic", /* entry name (Ubuntu 2.6.28-14.47) */
     0xc01449d0, 0x00000000, /* hooking address (flush_signal_handlers) */
     0xC0682340, /* task struct root (init_task) */
     3212, /* size of task_struct */
     452, /* offset of task_struct list */
     496, /* offset of pid */
     460, /* offset of mm */
     36, /* offset of pgd in mm */
     792, /* offset of comm */
     16, /* size of comm */
     4, /* offset of vm_start in vma */
     8, /* offset of vm_end in vma */
     12, /* offset of vm_next in vma */
     72, /* offset of vm_file in vma */
     12, /* offset of dentry in file */
     28, /* offset of d_name in dentry */
     96 /* offset of d_iname in dentry */ 
  },
  {  "2.6.28-15-generic", /* entry name (Ubuntu 2.6.28-15.49) */
                /* should also work with Ubuntu 2.6.28-16.55 */
      0xc0144ad0, 0x00000000, /* hooking address (flush_signal_handlers) */
      0xC0683340, /* task struct root (init_task) */
      3212, /* size of task_struct */
      452, /* offset of task_struct list */
      496, /* offset of pid */
      460, /* offset of mm */
      36, /* offset of pgd in mm */
      792, /* offset of comm */
      16, /* size of comm */
      4, /* offset of vm_start in vma */
      8, /* offset of vm_end in vma */
      12, /* offset of vm_next in vma */
      72, /* offset of vm_file in vma */
      12, /* offset of dentry in file */
      28, /* offset of d_name in dentry */
      96 /* offset of d_iname in dentry */ 
  },  
  {"CentOS_5_2.6.18_92.1.10.el5", /* entry name */
   0xC04BD8BB, 0xC04BD8BE, 	/* hooking address */
   0xC06723C0, 			/* task struct root */
   1360, 			/* size of task_struct */
   124, 			/* offset of task_struct list */
   168, 			/* offset of pid */
   132, 			/* offset of mm */
   40, 				/* offset of pgd in mm */
   404, 			/* offset of comm */
   16, 				/* size of comm */
   4, 				/* offset of vm_start in vma */
   8, 				/* offset of vm_end in vma */
   12, 				/* offset of vm_next in vma */
   72, 				/* offset of vm_file in vma */
   8, 				/* offset of dentry in file */
   28, 				/* offset of d_name in dentry */
   100 				/* offset of d_iname in dentry */ 
  },
/*    {"fedora5", 0xC01A26FC, 0xC01A0F1D, 0xC033C300, 1360, 96, 156, 120, 40, 
      432, 16, 76, 8, 40, 112}, */
  {"", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

target_ulong next_task_struct(target_ulong addr)
{
  target_ulong retval;

  if (0xC031E000 == taskaddr)
    // this is for kernel 2.4.20
    TEMU_read_mem(addr + listoffset, sizeof(retval), &retval);
  else {
    // default is kernel 2.6
    target_ulong next;

    TEMU_read_mem(addr + listoffset + sizeof(target_ulong), 
			sizeof(target_ulong), &next);
    retval = next - listoffset;
  }

  return retval;
}

target_ulong get_pid(target_ulong addr)
{
  target_ulong pid;

  TEMU_read_mem(addr + pidoffset, sizeof(pid), &pid);
  return pid;

}

target_ulong get_pgd(target_ulong addr)
{
  target_ulong mmaddr, pgd;
  TEMU_read_mem(addr + mmoffset, sizeof(mmaddr), &mmaddr);
  if (0 == mmaddr)
    TEMU_read_mem(addr + mmoffset + sizeof(mmaddr), 
		sizeof(mmaddr), &mmaddr);

  if (0 != mmaddr)
    TEMU_read_mem(mmaddr + pgdoffset, sizeof(pgd), &pgd);
  else
    memset(&pgd, 0, sizeof(pgd));

  return pgd;
}

void get_name(target_ulong addr, char *buf, int size)
{
  TEMU_read_mem(addr + commoffset, 
		size < commsize ? size : commsize, buf);
}

target_ulong get_first_mmap(target_ulong addr)
{
  target_ulong mmaddr, mmap;
  TEMU_read_mem(addr + mmoffset, sizeof(mmaddr), &mmaddr);
  if (0 == mmaddr)
    TEMU_read_mem(addr + mmoffset + sizeof(mmaddr), 
                   sizeof(mmaddr), &mmaddr);

  if (0 != mmaddr)
    TEMU_read_mem(mmaddr, sizeof(mmap), &mmap);
  else
    memset(&mmap, 0, sizeof(mmap));

  return mmap;
}

target_ulong get_next_mmap(target_ulong addr)
{
  target_ulong mmap;
  TEMU_read_mem(addr + vmnextoffset, sizeof(mmap), &mmap);
  return mmap;
}

target_ulong get_vmstart(target_ulong addr)
{
  target_ulong vmstart;
  TEMU_read_mem(addr + vmstartoffset, sizeof(vmstart), &vmstart);
  return vmstart;
}

target_ulong get_vmend(target_ulong addr)
{
  target_ulong vmend;
  TEMU_read_mem(addr + vmendoffset, sizeof(vmend), &vmend);
  return vmend;
}

void get_mod_name(target_ulong addr, char *name, int size)
{
  target_ulong vmfile, dentry;
  if (TEMU_memory_rw(addr + vmfileoffset, &vmfile, sizeof(vmfile), 0) == -1
      || TEMU_memory_rw(vmfile + dentryoffset, &dentry, sizeof(dentry),
                        0) == -1
      || TEMU_memory_rw(dentry + dinameoffset, name, size < 36 ? size : 36,
                        0) == -1)
    name[0] = 0;
}

int init_kernel_offsets()
{
  int i = 0;
  int retval = -1;
  char buf[128];

  while (strlen(kernel_table[i].version) != 0) {

    hookingpoint = kernel_table[i].hookingpoint;
    hookingpoint2 = kernel_table[i].hookingpoint2;
    taskaddr = kernel_table[i].taskaddr;
    tasksize = kernel_table[i].tasksize;
    listoffset = kernel_table[i].listoffset;
    pidoffset = kernel_table[i].pidoffset;
    mmoffset = kernel_table[i].mmoffset;
    pgdoffset = kernel_table[i].pgdoffset;
    commoffset = kernel_table[i].commoffset;
    commsize = kernel_table[i].commsize;
    vmstartoffset = kernel_table[i].vmstartoffset;
    vmendoffset = kernel_table[i].vmendoffset;
    vmnextoffset = kernel_table[i].vmnextoffset;
    vmfileoffset = kernel_table[i].vmfileoffset;
    dentryoffset = kernel_table[i].dentryoffset;
    dnameoffset = kernel_table[i].dnameoffset;
    dinameoffset = kernel_table[i].dinameoffset;

    //term_printf("trying %d: %s\n", i, kernel_table[i].version); 
    TEMU_memory_rw(taskaddr + commoffset, buf, 128, 0);
    if (strcmp(buf, "swapper") == 0) {
      retval = i;
      kernel_mem_start = 0xC0000000;
      break;
    }

    i++;
  }

  return retval;
}

static uint32_t hook_handles[sizeof(kernel_table)/sizeof(struct koffset)];

void for_all_hookpoints(hook_proc_t func, int action)
{
  int i = 0;

  while (strlen(kernel_table[i].version) != 0) {
    if (action) 
      hook_handles[i] = hookapi_hook_function(1, kernel_table[i].hookingpoint,
                            func, NULL, 0);
    else
      hookapi_remove_hook(hook_handles[i]);

    i++;
  }

  return;
}
