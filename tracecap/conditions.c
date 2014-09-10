/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#include "config.h"
#include <string.h>
#include <sys/time.h>
#include "conditions.h"
#include "TEMU_main.h"
#include "hookapi.h"
#include "conf.h"

int (*comparestring)(const char *, const char*);

/* ==== start and stop conditions ==== */

int tracing_start_condition = 1;

/* trace by name */
static char tracename[64];

void procname_clear() 
{
    tracename[0] = 0; 
}

char *procname_get() 
{
    return tracename; 
}

void procname_set(const char *name)
{
    strncpy(tracename, name, sizeof(tracename));
}

int procname_match(const char *name)
{
    int retval = 0; 
    
    if (strcmp(tracename, name) == 0)
	retval = 1;

    return retval; 
}

int procname_is_set()
{
    return (tracename[0] != 0);
}


/* start tracing on entering module */
static char cond_modulename[64];

void modname_clear() 
{
    cond_modulename[0] = 0; 
}

void modname_set(const char *name) 
{
    strncpy(cond_modulename, name, sizeof(cond_modulename)); 
}

int modname_match(const char *name)
{
    int retval = 0; 

    if (comparestring(cond_modulename, name) == 0)
	retval = 1; 

    return retval;
}

int modname_is_set()
{
    return (cond_modulename[0] != 0);
}

/* ==== filtering conditions ==== */

static struct timeval trace_stop_time;
static struct timeval trace_start_time;

/* Start tracing on different conditions */
static uint32_t tc_start_counter = 0;
static uint32_t tc_start_at = 0;
static uint32_t tc_stop_counter = 0;
static uint32_t tc_stop_at = 0;
static uint32_t tc_stop_address = 0;
static uint32_t tc_stop_hook_handle = 0;
static uint32_t cond_func_address;
static uint32_t cond_func_hook_handle = 0;


void tc_modname(const char *modname)
{
    strncpy(cond_modulename, modname, 64);
    tracing_start_condition = 0;
}

int tc_address_hook(void *opaque)
{
  if (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3]) {
    tracing_start_condition = 1;
    /* remove the hook */
    hookapi_remove_hook(cond_func_hook_handle);
   }

   return 0;
}

void tc_address(uint32_t address)
{
  /* Check if there is a conflict with conf_trace_only_after_first_taint */
  if (conf_trace_only_after_first_taint) {
    term_printf("tc_address_start conflicts with "
      "conf_trace_only_after_first_taint\n"
      "Disabling conf_trace_only_after_first_taint\n");
    conf_trace_only_after_first_taint = 0;
  }
  /* add a hook at address */
  tracing_start_condition = 0;
  cond_func_hook_handle = hookapi_hook_function(0, address, tc_address_hook, 
		NULL, 0);
  cond_func_address = address;
}

int tc_address_start_hook(void *opaque)
{
  term_printf("tc_address_start_hook(*) called\n");
  if ((tracing_kernel_all() ||
    (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3])) &&
    (tc_start_counter++ == tc_start_at))
  {
    tracing_start_condition = 1;
    tc_stop_counter = 0; // reset the tc_stop_counter at the execution saving
    /* remove the hook */
    hookapi_remove_hook(cond_func_hook_handle);
  }

  return 0;
}

void tc_address_start(uint32_t address, uint32_t at_counter)
{
  /* Check if there is a conflict with conf_trace_only_after_first_taint */
  if (conf_trace_only_after_first_taint) {
    term_printf("tc_address_start conflicts with "
      "conf_trace_only_after_first_taint\n"
      "Disabling conf_trace_only_after_first_taint\n");
    conf_trace_only_after_first_taint = 0;
  }
  /* add a hook at address */
  tracing_start_condition = 0;
  tc_start_counter = 0;
  tc_start_at = at_counter;
  cond_func_hook_handle = hookapi_hook_function(0, address, 
	tc_address_start_hook, NULL, 0);
  cond_func_address = address;
}

int tc_address_stop_hook(void *opaque)
{
  term_printf("tc_address_stop_hook(*) called\n");
  if ((tracing_kernel_all() ||
    (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3])) &&
    (tc_stop_counter++ == tc_stop_at))
  {
    tracing_start_condition = 0;
    if (gettimeofday(&trace_stop_time, 0) == 0) {
      term_printf("Trace ending time: %ld.%ld\n", trace_start_time.tv_sec, trace_start_time.tv_usec);
      term_printf("Total elapsed time: %ld usec\n",
      trace_stop_time.tv_sec*1000000 + trace_stop_time.tv_usec - trace_start_time.tv_sec*1000000 - trace_start_time.tv_usec);
    }
    /* remove the hook */
    hookapi_remove_hook(tc_stop_hook_handle);
  }

  return 0;
}

void tc_address_stop(uint32_t address, uint32_t at_counter)
{
  /* add a hook at address */
  tc_stop_counter = 0;
  tc_stop_at = at_counter;
  tc_stop_hook_handle = hookapi_hook_function(0, address, 
		tc_address_stop_hook, NULL, 0);
  tc_stop_address = address;
}


