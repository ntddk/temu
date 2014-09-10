/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#ifndef _TRACECAP_H_
#define _TRACECAP_H_

#include <stdio.h>
#include <inttypes.h>
#include <sys/user.h>
#include "trace.h"
#include "../shared/hookapi.h"
#include "TEMU_lib.h"
#include "conf.h"


#undef INLINE
#define TAINT_LOOP_IVS

/* Some configuration options that we don't foresee people to change 
 * Thus, they are not part of the ini configuration file */
#define PRINT_FUNCTION_MAP 1


/* Exit codes */
#define EXIT_NORMAL 1
#define EXIT_KILL_SIGNAL 13
#define EXIT_KILL_MSG 13
#define EXIT_DETECT_TAINTEIP 21
#define EXIT_DETECT_EXCEPTION 22
#define EXIT_DETECT_NULLPTR 23
#define EXIT_DETECT_PROCESSEXIT 24

/* External Variables */
extern FILE *tracelog;
extern FILE *tracenetlog;
extern FILE *tracehooklog;
extern FILE *calllog;
extern FILE *alloclog;
extern uint32_t tracepid;
extern uint32_t tracecr3;
extern EntryHeader eh;

extern int skip_taint_info;   // If !=0, operands will have empty taint records
extern int skip_decode_address; // If != 0, decode_address will be called
extern void (*hook_insn_begin) (uint32_t eip);
extern char *tracename_p;

/* Functions */
void do_taint_sendkey(const char *string, int id);
void do_taint_file(char *filename, int dev_index, uint32_t taint_id);
void do_linux_ps();
void do_tracing(uint32_t pid, const char *filename);
void do_tracing_by_name(const char *progname, const char *filename);
void do_save_state(uint32_t pid, uint32_t address, const char *filename);
void do_guest_modules(uint32_t pid);
void do_add_iv_eip(uint32_t eip);
void do_clean_iv_eips();

int tracing_start(uint32_t pid, const char *filename);
void tracing_stop();
void taint_loop_ivs();

#endif // _TRACECAP_H_
