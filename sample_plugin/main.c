/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/********************************************************************
 * @file sample_plugin.c
 * @author: Heng Yin <hyin@cs.berkeley.edu>
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "../shared/procmod.h"
#include "../shared/hooks/function_map.h"
#include "../slirp/slirp.h"
#include "../TEMU_lib.h"
#include "../shared/hookapi.h"
#include "../shared/read_linux.h"
#include "../shared/reduce_taint.h"
#include <xed-interface.h>
#include "main.h"
#include "network.h"

static plugin_interface_t my_interface;

char current_mod[128] = "";
char current_proc[128] = "";
char monitored_proc[128] = "";
int should_monitor = 0;

static int taint_sendkey_id = 0;
static int table_lookup_enabled = 1;
FILE *my_log = NULL;

xed_state_t xedState;

static void do_monitor_proc(char *proc)
{
  strncpy(monitored_proc, proc, 128);
}

//Send a tainted keystroke with a specified origin.
void do_taint_sendkey(const char *string, int id)
{
  taint_sendkey_id = id;
  do_send_key(string);
}


static term_cmd_t my_term_cmds[] = {
  {"taint_sendkey", "si", do_taint_sendkey,
   "key id", "send a tainted key to the guest system"},
  {"taint_nic", "i", do_taint_nic,
   "state", "set the network input to be tainted or not"},
  {"linux_ps", "", do_linux_ps,
   "", "list the processes on linux guest system"},
  {"guest_ps", "", list_procs,
   "", "list the processes on guest system"},
  {"monitor_proc", "s", do_monitor_proc,
	"proc_name", "monitor a process"},
  {NULL, NULL},
};

static term_cmd_t my_info_cmds[] = {
  {NULL, NULL},
};




static void 
my_taint_propagate(
	int nr_src,
	taint_operand_t * src_oprnds,
    taint_operand_t * dst_oprnd,
    int mode)
{
  //if table lookup is disabled and this propagation is actually a table lookup
  //do not propagate. 
  if(!table_lookup_enabled && mode == PROP_MODE_MOVE && nr_src == 2 && 
     src_oprnds[1].taint != 0 &&
     src_oprnds[0].taint == 0) {
    return;
  }
  
  if(should_monitor) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LEGACY_32,
				XED_ADDRESS_WIDTH_32b);
    uint8_t buf[15];
    char str[128];
    TEMU_read_mem(*TEMU_cpu_eip, 15, buf);
    xed_error_enum_t xed_error = xed_decode(&xedd, 
                                          STATIC_CAST(const xed_uint8_t*,buf),
                                           15);
    if(xed_error == XED_ERROR_NONE) {
      xed_decoded_inst_dump_intel_format(&xedd, str, sizeof(str), 0);
      term_printf("%s!%s: eip=%08x %s\n", current_proc, current_mod, 
			*TEMU_cpu_eip, str);
    }
  }
  default_taint_propagate(nr_src, src_oprnds, dst_oprnd, mode);
}


//parse the message from guest system to extract OS-level semantics
static void my_guest_message(char *message)
{
  switch (message[0]) {
  case 'P':
    parse_process(message);
    break;
  case 'M':
    parse_module(message);
    break;
  }
}

//This callback is invoked at the beginning of each basic block
static int my_block_begin()
{
  uint32_t eip, cr3;
  tmodinfo_t *mi;
  
  TEMU_read_register(eip_reg, &eip);
  TEMU_read_register(cr3_reg, &cr3);
  mi = locate_module(eip, cr3, current_proc); 

  should_monitor = (strcasecmp(current_proc, monitored_proc) == 0);
  if (!should_monitor)
    goto finished;

  fprintf(my_log, "block_begin: eip=%08x\n", eip);

finished:
  //we should always check if there is a hook at this point, 
  //no matter we are in the monitored context or not, because 
  //some hooks are global.
  hookapi_check_call(should_monitor);
  return 0;
}

//This callback is invoked for every instruction
static void my_insn_begin()
{
  //if this is not the process we want to monitor, return immediately
  if (!should_monitor) return;

  //now we can analyze this instruction
  uint32_t eip;
  TEMU_read_register(eip_reg, &eip);
  fprintf(my_log, "insn_begin: eip=%08x\n", eip);  
}

//This callback is invoked for every keystroke
static void my_send_keystroke(int reg)
{
  taint_record_t record;
  if (taint_sendkey_id) {
    //if this keystroke is supposed to be tainted, 
    //we will taint the destination register
	bzero(&record, sizeof(record));
    record.origin = taint_sendkey_id;
    record.offset = 0;
    taintcheck_taint_register(reg, 0, 1, 1, (uint8_t *) &record);
    taint_sendkey_id = 0;
  }
}


static void my_cleanup()
{
  procmod_cleanup();
  hookapi_cleanup();
  function_map_cleanup();

  fclose(my_log);
  my_log = NULL;
}


plugin_interface_t * init_plugin()
{
  if (!(my_log = fopen("plugin.log", "w"))) {
    fprintf(stderr, "cannot create plugin.log\n");
    return NULL;
  }

  function_map_init();
  init_hookapi();
  procmod_init();
  reduce_taint_init();

  xed_tables_init();
  xed_state_zero(&xedState);
  xed_state_init(&xedState, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);
  		
  my_interface.plugin_cleanup = my_cleanup;
  my_interface.taint_record_size = sizeof(taint_record_t);
  my_interface.taint_propagate = my_taint_propagate;
  my_interface.guest_message = my_guest_message;
  my_interface.block_begin = my_block_begin;
  my_interface.insn_begin = my_insn_begin;
  my_interface.term_cmds = my_term_cmds;
  my_interface.info_cmds = my_info_cmds;
  my_interface.send_keystroke = my_send_keystroke;
  my_interface.nic_recv = my_nic_recv;
  my_interface.nic_send = my_nic_send;
  my_interface.monitored_cr3 = 0;
  return &my_interface;
}


