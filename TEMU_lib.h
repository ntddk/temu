/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/// @file TEMU_lib.h
/// @author: Heng Yin <hyin@ece.cmu.edu>

#ifndef TEMU_LIB_H_INCLUDED
#define TEMU_LIB_H_INCLUDED

#include "TEMU_main.h"

/**** QEMU Timer ****/
typedef struct QEMUClock QEMUClock;
typedef struct QEMUTimer QEMUTimer;
typedef void QEMUTimerCB(void *opaque);
int64_t qemu_get_clock(QEMUClock *clock);
extern QEMUClock *vm_clock;
extern int64_t ticks_per_sec;

/**** Page Definitions ****/
#define TARGET_PAGE_BITS 12
#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK ~(TARGET_PAGE_SIZE - 1)

/**** QEMU VM Load/Save ******/
typedef struct QEMUFile QEMUFile;
QEMUFile *qemu_fopen(const char *filename, const char *mode);
void qemu_fflush(QEMUFile *f);
void qemu_fclose(QEMUFile *f);
void qemu_put_buffer(QEMUFile *f, const uint8_t *buf, int size);
void qemu_put_byte(QEMUFile *f, int v);
void qemu_put_be16(QEMUFile *f, unsigned int v);
void qemu_put_be32(QEMUFile *f, unsigned int v);
void qemu_put_be64(QEMUFile *f, uint64_t v);
int qemu_get_buffer(QEMUFile *f, uint8_t *buf, int size);
int qemu_get_byte(QEMUFile *f);
unsigned int qemu_get_be16(QEMUFile *f);
unsigned int qemu_get_be32(QEMUFile *f);
uint64_t qemu_get_be64(QEMUFile *f);
typedef void SaveStateHandler(QEMUFile *f, void *opaque);
typedef int LoadStateHandler(QEMUFile *f, void *opaque, int version_id);


#define EXCP_INTERRUPT 	0x10000 /* async interruption */
#define EXCP_HLT        0x10001 /* hlt instruction reached */
#define EXCP_DEBUG      0x10002 /* cpu stopped after a breakpoint or singlestep */
#define EXCP_HALTED     0x10003 /* cpu is halted (waiting for external event) */

/*! 
  \addtogroup DEC  XED-DEC: XED Decoding instructions
  \addtogroup INIT XED-INIT: XED Initialization

  \addtogroup main
 * Additional documentation for group 'main'
 * @{ 
 */ //start of group

/// Create a timer
QEMUTimer *qemu_new_timer(QEMUClock *clock, QEMUTimerCB *cb, void *opaque);
/// Free a timer
void qemu_free_timer(QEMUTimer *ts);
void qemu_del_timer(QEMUTimer *ts);
/// Set up a timeout
void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time);
/// Check if the timer is pending
int qemu_timer_pending(QEMUTimer *ts);

/// Register a VM entity for saving and restoring VM states
int register_savevm(const char *idstr, 
                    int instance_id, 
                    int version_id,
                    SaveStateHandler *save_state,
                    LoadStateHandler *load_state,
                    void *opaque);

/// Deregister a VM entity
int deregister_savevm(const char *idstr, int instance_id);

/// Pause VM
void vm_stop(int reason);
/// Load a previously saved VM snapshot
void do_loadvm(const char *name);
/// Save the current VM states into a snapshot
void do_savevm(const char *name);


/// Send a keystroke
void do_send_key(const char *string);
/*! @} */ //end of group



#endif //TEMU_LIB_H_INCLUDED
