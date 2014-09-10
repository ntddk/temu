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
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "tracecap.h"
#include "bswap.h"
#include "state.h"
#include "shared/hooks/function_map.h"
#include "shared/procmod.h"

#if TRACE_ENABLED


FILE *tracelog = 0;
FILE *tracenetlog = 0;
FILE *tracehooklog = 0;
FILE *calllog = 0;
FILE *alloclog = 0;
uint32_t tracepid = 0;
uint32_t tracecr3 = 0;
uint32_t dump_pc_start = 0;
int skip_taint_info = 0;
int skip_decode_address = 0;

/* local hook API for instrumentation at certain EIP */
void (*hook_insn_begin) (uint32_t eip);

/* Filename for functions file */
char functionsname[128]= "";

/* Filename for trace file */
char tracename[128]= "";
char *tracename_p = tracename;


/* Start usage */
struct rusage startUsage;

/* Entry header */
EntryHeader eh;


int tracing_start(uint32_t pid, const char *filename)
{
#ifdef INSN_INFO
  char infoname[128];
  if (infolog)
    fclose(infolog);
  snprintf(infoname, 128, "%s.log", filename);
  infolog = fopen(infoname, "w");
  if (0 == infolog) {
    perror("tracing_start");
    tracepid = 0;
    tracecr3 = 0;
    return -1;
  }
#endif

  if (conf_log_external_calls) {
    trace_do_not_write = 1;
  }

  /* Initialize disassembler */
  xed2_init();

  strncpy(tracename, filename, 128);

  if (tracelog)
    fclose(tracelog);
  if (tracenetlog)
    fclose(tracenetlog);

  tracelog = fopen(filename, "w");
  if (0 == tracelog) {
    perror("tracing_start");
    tracepid = 0;
    tracecr3 = 0;
    return -1;
  }
  setvbuf(tracelog, filebuf, _IOFBF, FILEBUFSIZE);

  char netname[128];
  snprintf(netname, 128, "%s.netlog", filename);
  tracenetlog = fopen(netname, "w");
  if (0 == tracenetlog) {
    perror("tracing_start");
    tracepid = 0;
    tracecr3 = 0;
    return -1;
  }
  else {
    fprintf(tracenetlog, "Flow       Off  Data\n");
    fflush(tracenetlog);
  }

  // Set name for functions file
  snprintf(functionsname, 128, "%s.functions", filename);

  if (conf_log_external_calls) {
    char callname[128];
    if (calllog)
      fclose(calllog);
    snprintf(callname, 128, "%s.calls", filename);
    calllog = fopen(callname, "w");
    if (0 == calllog) {
      perror("tracing_start");
      tracepid = 0;
      tracecr3 = 0;
      return -1;
    }
    setvbuf(calllog, filebuf, _IOFBF, FILEBUFSIZE);
  }

  tracepid = pid;
  tracecr3 = find_cr3(pid);
  if (0 == tracecr3) {
    term_printf("CR3 for PID %d not found. Tracing all processes!\n",pid);
  }
  term_printf("PID: %d CR3: 0x%08x\n",tracepid, tracecr3);


  /* Initialize hooks only for this process */
  temu_plugin->monitored_cr3 = tracecr3;

  /* Get system start usage */
  if (getrusage(RUSAGE_SELF, &startUsage) != 0)
    term_printf ("Could not get start usage\n");

  return 0;
}

void term_printf(const char *fmt, ...);

void tracing_stop()
{
  /* If not tracing return */
  if (tracepid == 0)
    return;

  term_printf("Stop tracing process %d\n", tracepid);
  print_trace_stats();

  /* Get system stop usage */
  struct rusage stopUsage;
  if (getrusage(RUSAGE_SELF, &stopUsage) == 0) {
    double startUT = (double)startUsage.ru_utime.tv_sec +
                    (double)startUsage.ru_utime.tv_usec / 1e6;
    double startST = (double)startUsage.ru_stime.tv_sec +
                    (double)startUsage.ru_stime.tv_usec / 1e6;
    double stopUT = (double)stopUsage.ru_utime.tv_sec +
                    (double)stopUsage.ru_utime.tv_usec / 1e6;
    double stopST = (double)stopUsage.ru_stime.tv_sec +
                    (double)stopUsage.ru_stime.tv_usec / 1e6;

    double userProcessTime = (stopUT - startUT);
    double systemProcessTime = (stopST - startST);
    double processTime =  userProcessTime + systemProcessTime;

    term_printf ("Processing time: %g U: %g S: %g\n",
      processTime, userProcessTime, systemProcessTime);
  }
  else {
    term_printf ("Could not get usage\n");
  }


  tracepid = 0;
  header_already_written = 0;
  if (tracelog) {
    fclose(tracelog);
    tracelog = 0;
  }

  if (tracenetlog) {
    fclose(tracenetlog);
    tracenetlog = 0;
  }

  if (tracehooklog) {
    fclose(tracehooklog);
    tracehooklog = 0;
  }

  if (alloclog) {
    fclose(alloclog);
    alloclog = 0;
  }

  // Clear statistics
  clear_trace_stats();

  // Clear received_data flag
  received_tainted_data = 0;

// Print file with all functions offsets
#if PRINT_FUNCTION_MAP
  map_to_file(functionsname);
#endif

  if (conf_log_external_calls) {
    if (calllog) {
      fclose(calllog);
      calllog = 0;
    }
  }

#ifdef INSN_INFO
  if (infolog) {
    fclose(infolog);
    infolog = 0;
  }
#endif

  if (conf_save_state_at_trace_stop) {
    char statename[128];
    snprintf(statename, 128, "%s.state", tracename);

    int err = save_state_by_cr3(tracecr3, statename);
    if (err) {
      term_printf("Could not save state");
    }
  }

  /* Do not unload hooks, it'd crash emulation */

}

#endif                          //TRACE_ENABLED
