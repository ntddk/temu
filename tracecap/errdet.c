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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "TEMU_lib.h"
#include "tracecap.h"
#include "procmod.h"
#include "errdet.h"


enum ActionType { ACTION_NONE = 0, 
		  ACTION_TERM, 
		  ACTION_STOP, 
		  ACTION_TRACING_STOP };

static enum ActionType action = ACTION_TERM;
static unsigned detectioncond = DETECT_COND_NONE;


void launch_action(int exitcode)
{
  switch (action) {
    case ACTION_NONE:
      break;
    case ACTION_TERM:
      if (tracepid)
        tracing_stop();
      exit(exitcode);
      break;
    case ACTION_STOP:
      vm_stop(0);
      break;
    case ACTION_TRACING_STOP:
      if (tracepid)
	tracing_stop();
      break;
    }
}

static int exception_detection(void *opaque) {
    if (!(detectioncond & DETECT_COND_EXCEPTION))
  return 0;

    write_insn(tracelog,&eh); // force this instruction to be written
    term_printf("ntdll.dll::KiUserExceptionDispatcher raised by insn 0x%lx. "
      "User exception detected.\n", eh.address);

    launch_action(EXIT_DETECT_EXCEPTION);

    return 0;
}

void enable_detection(unsigned detectionmask)
{
    if (detectionmask & DETECT_COND_EXCEPTION)
  hookapi_hook_function_byname("ntdll.dll", "KiUserExceptionDispatcher",
        0, exception_detection, 0, 0);
    detectioncond |= detectionmask;
    term_printf("Detection condition flag is now: 0x%x.\n", detectioncond);
}

void disable_detection(unsigned detectionmask)
{
    detectioncond &= ~detectionmask;
    term_printf("Detection condition flag is now: 0x%x.\n", detectioncond);
}

void do_detect(const char *condition, const char* on_off)
{
    int turn_on = 0;
    unsigned mask = 0;

    if (strcmp(on_off, "on")==0) {
      turn_on = 1;
    } else if (strcmp(on_off, "off")==0) {
        turn_on = 0;
    } else {
        term_printf("The switch option must be 'on' or 'off'.\n");
        return;
    }

    if (strcmp(condition, "tainteip")==0) {
      mask = DETECT_COND_TAINTEIP;
      term_printf("Set detecting tainted EIP to %s.\n", on_off);
    }
    else if (strcmp(condition, "nullptr")==0) {
      mask = DETECT_COND_NULLPTR;
      term_printf("Set detecting null pointer dereference to %s.\n", on_off);
    }
    else if (strcmp(condition, "exception")==0) {
      mask = DETECT_COND_EXCEPTION;
      term_printf("Set detecting user exception to %s.\n", on_off);
    }
    else if (strcmp(condition, "processexit")==0) {
      mask = DETECT_COND_PROCESSEXIT;
      term_printf("Set detecting process exit event to %s.\n", on_off);
    }
    else if (strcmp(condition, "all")==0) {
      mask = DETECT_COND_ALL;
      term_printf("Set detecting all condition type to %s.\n", on_off);
    }
    else {
      term_printf("Unknown detection option.\n");
      return;
    }

    if (turn_on)
      enable_detection(mask);
    else
      disable_detection(mask);
}

void do_action(const char *act)
{
    if (strcmp(act, "terminate")==0) {
      action = ACTION_TERM;
      term_printf("Terminaing after detection.\n");
    } else if (strcmp(act, "stopvm")==0) {
        action = ACTION_STOP;
        term_printf("Stopping VM after detection.\n");
    } else if (strcmp(act, "stoptracing")==0) {
        action = ACTION_TRACING_STOP;
	term_printf("Stop tracing after detection.\n");
    } else {
        action = ACTION_NONE;
        term_printf("Do nothing after detection.\n");
    } 
}


void procexit_detection(uint32_t pid) {
    if (!(detectioncond & DETECT_COND_PROCESSEXIT))
      return;

    if (tracepid != pid)
      return;

    term_printf("Process %d exitted.\n", pid);

    launch_action(EXIT_DETECT_PROCESSEXIT);
}

void nullptr_detection(u_int32_t address)
{
    if (!(detectioncond & DETECT_COND_NULLPTR))
  return ;

    term_printf("Null pointer dereference at 0x%08x\n", address);
    write_insn(tracelog,&eh); // force this instruction to be written

   launch_action(EXIT_DETECT_NULLPTR);
}

void tainteip_detection(uint8_t *record)
{
    if (!(detectioncond & DETECT_COND_TAINTEIP))
  return;

    uint32_t pid;
    char name[32];
    /* we ignore kernel-mode tainted eips to reduce false positives*/
    if (TEMU_is_in_kernel())
  return ;

    find_process(TEMU_cpu_cr[3], name, &pid);
    term_printf("Tainted EIP 0x%08x in process %d (%s)\n",
    *TEMU_cpu_eip, pid, name);

    // We will miss the instruction triggering vulnerability condition
    // if we log at the end of instruction
    write_insn(tracelog,&eh);

    static int eip_tainted_flag = 0;

    struct timeval eiptime;

    if (0 == eip_tainted_flag) {
  eip_tainted_flag = 1;
  if (gettimeofday(&eiptime, 0) == 0) {
      term_printf("Time of tainted EIP detection: %ld.%ld\n", eiptime.tv_sec, eiptime.tv_usec);
  }
    }

    launch_action(EXIT_DETECT_TAINTEIP);
}

