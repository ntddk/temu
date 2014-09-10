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
#include <assert.h>
#include "TEMU_lib.h"
#include "tracecap.h"
#include "conditions.h"
#include "network.h"

/* Default configuration flags */
int conf_trace_only_after_first_taint = 1;
int conf_log_external_calls = 0;
int conf_write_ops_at_insn_end = 0;
int conf_save_state_at_trace_stop = 0;

/* Environment variables */
int tracing_table_lookup = 1;
static int conf_ignore_dns = 0;
static int conf_tainted_only = 0;
static int conf_single_thread_only = 0;
static int conf_tracing_kernel_all = 0;
static int conf_tracing_kernel_tainted = 0;
static int conf_tracing_kernel_partial = 0;

/* Default hook files */
char hook_dirname[256] = TEMU_HOME "/shared/hooks/hook_plugins";
char hook_plugins_filename[256] = PROJECT_HOME "/ini/hook_plugin.ini";

/* Default configuration file */
char ini_main_default_filename[256] = PROJECT_HOME "/ini/main.ini";


void set_ignore_dns(int state)
{
  if (state) {
    conf_ignore_dns = 1;
    term_printf("Ignore DNS flag on.\n");
  }
  else {
    conf_ignore_dns = 0;
    term_printf("Ignore DNS flag off.\n");
  }
}

inline int tracing_ignore_dns()
{
    return conf_ignore_dns;
}

void set_tainted_only(int state)
{
  if (state) {
    conf_tainted_only = 1;
    term_printf("Taint-only flag on.\n");
  }
  else {
    conf_tainted_only = 0;
    term_printf("Taint-only flag off.\n");
  }
}

inline int tracing_tainted_only()
{
    return conf_tainted_only;
}

void set_single_thread_only(int state)
{
  if (state) {
    conf_single_thread_only = 1;
    term_printf("Single-thread-only flag on.\n");
  }
  else {
    conf_single_thread_only = 0;
    term_printf("Single-thread-only flag off.\n");
  }
}

inline int tracing_single_thread_only()
{
    return conf_single_thread_only;
}

void set_kernel_all(int state)
{
  if (state) {
    conf_tracing_kernel_all = 1;
    term_printf("Kernel-all flag on.\n");
  }
  else {
    conf_tracing_kernel_all = 0;
    term_printf("Kernel-all flag off.\n");
  }
}

inline int tracing_kernel_all()
{
    return conf_tracing_kernel_all;
}

void set_kernel_tainted(int state)
{
  if (state) {
    conf_tracing_kernel_tainted = 1;
    term_printf("Kernel-tainted flag on.\n");
  }
  else {
    conf_tracing_kernel_tainted = 0;
    term_printf("Kernel-tainted flag off.\n");
  }
}

inline int tracing_kernel_tainted()
{
    return conf_tracing_kernel_tainted;
}

void set_kernel_partial(int state)
{
  if (state) {
    conf_tracing_kernel_partial = 1;
    term_printf("Kernel-partial flag on.\n");
  }
  else {
    conf_tracing_kernel_partial = 0;
    term_printf("Kernel-partial flag off.\n");
  }
}

inline int tracing_kernel_partial()
{
    return conf_tracing_kernel_partial;
}

inline int tracing_kernel()
{
    return conf_tracing_kernel_all || conf_tracing_kernel_partial ||
        conf_tracing_kernel_tainted;
}

/* Print configuration variables */
void print_conf_vars()
{
  term_printf(
      "TABLE_LOOKUP: %d\n"
      "TRACE_AFTER_FIRST_TAINT: %d\n"
      "LOG_EXTERNAL_CALLS: %d\n"
      "WRITE_OPS_AT_INSN_END: %d\n"
      "SAVE_STATE_AT_TRACE_STOP: %d\n"
      "PROTOS_IGNOREDNS: %d\n"
      "TAINTED_ONLY: %d\n" 
      "SINGLE_THREAD_ONLY: %d\n"
      "TRACING_KERNEL_ALL: %d\n"
      "TRACING_KERNEL_TAINTED: %d\n" 
      "TRACING_KERNEL_PARTIAL: %d\n",
      tracing_table_lookup,
      conf_trace_only_after_first_taint,
      conf_log_external_calls,
      conf_write_ops_at_insn_end,
      conf_save_state_at_trace_stop,
      conf_ignore_dns, 
      conf_tainted_only,
      conf_single_thread_only,
      conf_tracing_kernel_all,
      conf_tracing_kernel_tainted,
      conf_tracing_kernel_partial
  );
}

/* Parse network filter configuration */
void check_filter_conf(struct cnfnode *cn_root) {
  struct cnfresult *cnf_res;

#if TAINT_ENABLED
  /* Transport */
  cnf_res = cnf_find_entry(cn_root, "network/filter_transport");
  if (cnf_res) {
    update_nic_filter("proto",cnf_res->cnfnode->value);
  }
  /* Source port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_sport");
  if (cnf_res) {
    update_nic_filter("sport",cnf_res->cnfnode->value);
  }
  /* Destination port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_dport");
  if (cnf_res) {
    update_nic_filter("dport",cnf_res->cnfnode->value);
  }
  /* Source addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_saddr");
  if (cnf_res) {
    update_nic_filter("src",cnf_res->cnfnode->value);
  }
  /* Destination addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_daddr");
  if (cnf_res) {
    update_nic_filter("dst",cnf_res->cnfnode->value);
  }
#endif  
  
}


/* Parse boolean from configuration file */
static void set_bool_from_ini(struct cnfnode *cn_root, char *entry, int* flag) {
  struct cnfresult *cnf_res;

  cnf_res = cnf_find_entry(cn_root, entry);
  if (cnf_res) {
    if (strcasecmp(cnf_res->cnfnode->value, "yes") == 0) {
      *flag = 1;
      term_printf("%s is enabled.\n",entry);
    }
    else if (strcasecmp(cnf_res->cnfnode->value, "no") == 0) {
      *flag = 0;
      term_printf("%s is disabled.\n",entry);
    }
    else {
      term_printf("%s has incorrect value. Try <yes|no>.\n",entry);
    }
  }

}

/* Parse configuration file 
 * Returns zero if succeeds, -1 if it could not find the file */
int check_ini(const char *path_ini)
{
  struct cnfnode *cn_root;
  struct cnfmodule *mod_ini;
  struct cnfresult *cnf_res;

  register_ini(NULL);
  mod_ini = find_cnfmodule("ini");
  cn_root = cnfmodule_parse_file(mod_ini, path_ini);

  if (cn_root == NULL) {
    return -1;
  }

  /* Parse configuration flags */
  set_bool_from_ini(cn_root, "general/trace_only_after_first_taint",
    &conf_trace_only_after_first_taint);
  set_bool_from_ini(cn_root, "general/log_external_calls",
    &conf_log_external_calls);
  set_bool_from_ini(cn_root, "general/write_ops_at_insn_end",
    &conf_write_ops_at_insn_end);
  set_bool_from_ini(cn_root, "general/save_state_at_trace_stop",
    &conf_save_state_at_trace_stop);
  set_bool_from_ini(cn_root, "tracing/tracing_table_lookup",
    &tracing_table_lookup);
  set_bool_from_ini(cn_root, "tracing/tracing_tainted_only",
    &conf_tainted_only);
  set_bool_from_ini(cn_root, "tracing/tracing_single_thread_only",
    &conf_single_thread_only);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel",
    &conf_tracing_kernel_all);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_tainted",
    &conf_tracing_kernel_tainted);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_partial",
    &conf_tracing_kernel_partial);

  /* Parse network configuration */
  set_bool_from_ini(cn_root, "network/ignore_dns",
    &conf_ignore_dns);
  check_filter_conf(cn_root);
#if TAINT_ENABLED  
  print_nic_filter();
#endif  

  /* Find hook configuration file */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_ini");
  if (cnf_res)
  strncpy(hook_plugins_filename, cnf_res->cnfnode->value, 255);
  hook_plugins_filename[255] = '\0';
  term_printf("Loading plugin options from: %s\n", hook_plugins_filename);

  /* Find hooks directory */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_directory");
  if (cnf_res) {
    strncpy(hook_dirname, cnf_res->cnfnode->value, 255);
    hook_dirname[255] = '\0';
  }
  term_printf("Loading plugins from: %s\n", hook_dirname);

  destroy_cnftree(cn_root);

  return 0;
}

