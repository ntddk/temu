/*
TEMU is Copyright (C) 2006-2010, BitBlaze Team.

For compatibility, this Linux kernel module is distributed under a
different license. It may be redistributed and modified under the
terms of the GNU GPL, version 2 or later, but it is made available
WITHOUT ANY WARRANTY.
*/

#ifndef _LINUXDRV_H
#define _LINUXDRV_H

#define JPROBE_SUM    7
#define MESSAGE_MAX   512	/* max len of one message */
#define VIRTUAL_PORT "0x68"	/* virtual port in temu */

enum task_state {
    TASK_FORK,	/* task created */
    TASK_EXIT,	/* task exiting */
    TASK_EXEC,	/* task new binary loaded */
};

enum vma_state {
    VMA_CREATE,	/* create vma */
    VMA_REMOVE,	/* remove vma */
    VMA_MODIFY,	/* modify vma */
};

#endif
